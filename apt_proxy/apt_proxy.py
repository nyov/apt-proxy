#
# Copyright (C) 2002 Manuel Estrada Sainz <ranty@debian.org>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from twisted.internet import reactor, defer, abstract, protocol
from twisted.protocols import http, ftp
from twisted.web import static
import os, stat, signal, fcntl, exceptions
from os.path import dirname, basename
import re
import urlparse
import time
import string
import shelve
from twisted.python.failure import Failure
import memleak
#from posixfile import SEEK_SET, SEEK_CUR, SEEK_END
#since posixfile is considered obsolete I'll define the SEEK_* constants
#myself.
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

from types import *

#sibling imports
import packages, misc
from misc import log

from twisted_compat import compat

status_dir = '.apt-proxy'

class FileType:
    """
    This is just a way to distinguish between different filetypes.

    self.regex: regular expresion that should match. It could probably be
    self.replaced with something simpler, but... o well, it works.
    
    self.contype: string to the content-type http header.
    
    mutable: is it a Packages/Sources/...
    
    """
    def __init__ (self, regex, contype, mutable):
        self.regex = regex
        self.contype = contype
        self.mutable = mutable

    def check (self, name):
        "Returns true if name is of this filetype"
        if self.regex.search(name):
            return 1
        else:
            return 0

filetypes = (
    FileType(re.compile(r"\.deb$"), "application/dpkg", 0),
    FileType(re.compile(r"\.tar\.gz$"), "application/x-gzip", 0),
    FileType(re.compile(r"\.dsc$"),"text/plain", 0),
    FileType(re.compile(r"\.diff\.gz$"), "application/x-gzip", 0),
    FileType(re.compile(r"\.bin$"), "application/octet-stream", 0),
    FileType(re.compile(r"\.tgz$"), "application/x-gzip", 0),

    FileType(
    re.compile(r"/(Packages|Release|Sources|Contents-.*)(\.(gz|bz2))?$"),
    "text/plain", 1),
    )

class FileVerifier(protocol.ProcessProtocol):
    """
    It tryes to verify the integrity of a file by running some external
    command.

    self.deferred: a deferred that will be trigered when the command
    finishes or times out.

    Sample:
    
            verifier = FileVerifier(self)
            verifier.deferred.addCallbacks(callback_if_ok, callback_if_fail)
            verifier.deferred.arm()

        then eigher callback_if_ok or callback_if_fail will be called
        when the subprocess finishes execution.

    Checkout twisted.internet.defer.Deferred on how to use self.deferred
    
    """
    def __init__(self, request):
        self.factory = request.factory
        self.deferred = defer.Deferred()
        self.path = request.local_file

        if re.search(r"\.deb$", self.path):
            exe = '/usr/bin/dpkg'
            args = (exe, '--fsys-tarfile', self.path)
        elif re.search(r"\.gz$", self.path):
            exe = '/bin/gunzip'
            args = (exe, '-t', '-v', self.path)
        elif re.search(r"\.bz2$", self.path):
            exe = '/usr/bin/bunzip2'
            args = (exe, '--test', self.path)
        else:
            exe = '/bin/sh'
            args = (exe, '-c', "echo unknown file: not verified 1>&2")

        self.process = reactor.spawnProcess(self, exe, args)
        self.laterID = reactor.callLater(self.factory.timeout, self.timedout)

    def connectionMade(self):
        self.data = ''

    def outReceived(self, data):
        #we only care about errors
        pass
    def errReceived(self, data):
        self.data = self.data + data

    def failed(self):
        log.debug("verification failed: %s"%(self.path), 'verify', 1)
        os.unlink(self.path)
        self.deferred.errback(None)

    def timedout(self):
        """
        this should not happen, but if we timeout, we pretend that the
        operation failed.
        """
        self.laterID=None
        log.debug("Process Timedout:",'verify')
        self.failed()
        
    def processEnded(self, reason=None):
        """
        This get's automatically called when the process finishes, we check
        the status and report through the Deferred.
        """
        #log.debug("Process Status: %d" %(self.process.status),'verify')
        #log.debug(self.data, 'verify')
        if self.laterID:
            self.laterID.cancel()
            if self.process.status == 0:
                self.deferred.callback(None)
            else:
                self.failed()

def findFileType(name):
    "Look for the FileType of 'name'"
    for type in filetypes:
        if type.check(name):
            return type
    return None

class TempFile (file):
    def __init__(self, mode='w+b', bufsize=-1):
        import tempfile
        name = tempfile.mktemp('.apt-proxy')
        file.__init__(self, name, mode, bufsize)
        os.unlink(name)
    def append(self, data):
        self.seek(0, SEEK_END)
        self.write(data)
    def read(self, size=-1, start=None):
        if start != None:
            self.seek(start, SEEK_SET)
        return file.read(self, size)
    def size(self):
        self.seek(0, SEEK_END)
        return self.tell()

class Fetcher:
    """
    This is the base class for all Fetcher*, it tryies to hold as much
    common code as posible.

    Subclasses of this class are the ones responsable of contacting the backend
    servers and fetching.
    """
    gzip_convert = re.compile(r"/Packages$")
    post_convert = re.compile(r"/Packages.gz$")
    status_code = http.OK
    status_message = None
    requests = None
    request = None
    length = None
        
    def insert_request(self, request):
        """
        Request should be served through this Fetcher because it asked for
        the same uri that we are waiting for.
        
        We also have to get it up to date, give it all received data, send it
        the appropriate headers and set the response code.
        """
        if request in self.requests:
            raise 'this request is already assigned to this Fetcher'
        self.requests.append(request)
        request.apFetcher = self
        if (self.request):
            self.update_request(request)

    def update_request(self, request):
        """
        get a new request up to date
        """
        request.local_mtime = self.request.local_mtime
        request.local_size = self.request.local_size
        if(self.status_code != None):
            request.setResponseCode(self.status_code, self.status_message)
        for name, value in self.request.headers.items():
            request.setHeader(name, value)
        if self.transfered.size() != 0:
            request.write(self.transfered.read(start=0))

    def remove_request(self, request):
        """
        Request should NOT be served through this Fetcher, the client
        probably closed the connection.
        
        If this is our last request, we may also close the connection with the
        server depending on the configuration.

        We keep the last request for reference even if the client closed the
        connection.
        """
        self.requests.remove(request)
        if len(self.requests) == 0:
            log.debug("Last request removed",'client')
            if not self.factory.finish_horphans:
                if hasattr(self, 'transport') and self.transport:
                    log.debug(
                        "telling the transport to loseConnection",'client')
                    self.transport.loseConnection()
                if hasattr(self, 'loseConnection'):
                    self.loseConnection()
        else:
            self.request = self.requests[0]
        request.apFetcher = None

    def transfer_requests(self, fetcher):
        "Transfer all requests from self to fetcher"
        for req in self.requests:
            self.remove_request(req)
            fetcher.insert_request(req)

    def setResponseCode(self, code, message=None):
        "Set response code for all requests"
        self.status_code = code
        self.status_message = message
        for req in self.requests:
            req.setResponseCode(code, message)

    def setResponseHeader(self, name, value):
        "set 'value' for header 'name' on all requests"
        for req in self.requests:
            req.setHeader(name, value)

    def __init__(self, request=None):
        self.requests = []
        self.transfered = TempFile()
        if(request):
            self.activate(request)
            
    def activate(self, request):
        log.debug(str(self.__class__) + ' URI:' + request.uri, 'fetcher_activate')
        self.local_file = request.local_file
        self.local_mtime = request.local_mtime
        self.factory = request.factory
        self.request = request
        data = request.content.read()

        for req in self.requests:
            self.update_request(req)
        self.requests.append(request)

        request.apFetcher = self
        if self.factory.runningFetchers.has_key(request.uri):
            raise 'There already is a running fetcher'
        self.factory.runningFetchers[request.uri]=self

    def apDataReceived(self, data):
        """
        Should be called from the subclasses when data is available for
        streaming.

        Keeps all transfered data in 'self.transfered' for requests which arrive
        later and to write it in the cache at the end.

        Note: self.length if != None is the amount of data pending to be
        received.
        """
        if self.length != None:
            self.transfered.append(data[:self.length])
            for req in self.requests:
                req.write(data[:self.length])
        else:
            self.transfered.append(data)
            for req in self.requests:
                req.write(data)

    def apDataEnd(self, data):
        """
        Called by subclasses when the data transfer is over.

           -caches the received data if everyting went well
           -takes care or mtime and atime
           -finishes connection with server and the requests
        """
        import shutil
        if (self.status_code == http.OK):
            dir = dirname(self.local_file)
            if(not os.path.exists(dir)):
                os.makedirs(dir)
            f = open(self.local_file, "w")
            fcntl.lockf(f.fileno(), fcntl.LOCK_EX)
            f.truncate(0)
            if type(data) is StringType:
                f.write(data)
            else:
                data.seek(0, SEEK_SET)
                shutil.copyfileobj(data, f)
            f.close()
            if self.local_mtime != None:
                os.utime(self.local_file, (time.time(), self.local_mtime))
            else:
                log.debug("no local time: "+self.local_file,'client')
                os.utime(self.local_file, (time.time(), 0))

            self.factory.file_served(self.request.uri)
            self.request.backend.packages.packages_file(self.request.uri)
        
        if self.transport:
            self.transport.loseConnection()
        for req in self.requests:
            req.finish()
        self.apEnd()

    def apEnd(self):
        """
        Called by subclasses when apDataEnd does too much things.

        Let's everyone know that we are not the active Fetcher for our uri.
        """
        try:
            del self.factory.runningFetchers[self.request.uri]
        except exceptions.KeyError:
            log.debug("We are not on runningFetchers!!!",'client')
            log.debug(str(self.factory.runningFetchers),'client')
            raise exceptions.KeyError
        for req in self.requests[:]:
            self.remove_request(req)

    def apEndCached(self):
        """
        Serve my requests from the cache.
        """
        self.apEndTransfer(FetcherFile)
        
    def apEndTransfer(self, fetcher_class):
        """
        Remove this Fetcher and transfer all it's requests to a new instance of
        'fetcher_class'.
        """
        #Consider something like this:
        #req = dummyFetcher.fix_ref_request()
        #fetcher = fetcher_class()
        #dummyFetcher.transfer_requests(fetcher)
        #dummyFetcher.apEnd()
        #fetcher.activate(req)

        self.setResponseCode(http.OK)
        requests = self.requests[:]
        self.apEnd()
        fetcher = None
        for req in requests:
            if (fetcher_class != FetcherFile or req.serve_if_cached):
                running = req.factory.runningFetchers
                if (running.has_key(req.uri)):
                    #If we have an active Fetcher just use that
                    log.debug("have active Fetcher",'file_client')
                    running[req.uri].insert_request(req)
                    fetcher = running[req.uri]
                else:
                    fetcher = fetcher_class(req)
            else:
                req.finish()
        return fetcher
            
    def connectionFailed(self, reason=None):
        """
        Tell our requests that the connection with the server failed.

        When multi-server backends are implemented we could change server and
        try again.
        """
        log.msg('['+self.request.backend.base+']' + " Connection Failed: "
                + self.request.backend.path + "/" + self.request.backend_uri)
        if reason != None:
            log.debug("Connection Failed: "+str(reason))

        self.setResponseCode(http.SERVICE_UNAVAILABLE)
        self.apDataReceived("")
        self.apDataEnd(self.transfered)
        #Because of a bug in tcp.Client we may be called twice,
        #Make sure that next time nothing will happen
        #FIXME: This hack is probably not anymore pertinent.
        self.connectionFailed = lambda : log.debug('connectionFailed(2)',
                                                   'client','9')

class FetcherDummy(Fetcher):
    """
    """
    gzip_convert = re.compile(r"^Nothing should match this$")
    post_convert = re.compile(r"^Nothing should match this$")
    status_code = http.INTERNAL_SERVER_ERROR
    status_message = None
        
    def insert_request(self, request):
        """
        """
        if request in self.requests:
            raise 'this request is already assigned to this Fetcher'
        self.requests.append(request)
        request.apFetcher = self

    def remove_request(self, request):
        """
        """
        #make sure that it has updated values, since the requests
        #may be cached and we need them to serve it.
        request.local_mtime = self.request.local_mtime
        request.local_size = self.request.local_size

        self.requests.remove(request)
        request.apFetcher = None

    def fix_ref_request(self):
        if self.requests != []:
            if self.request not in self.requests:
                request = self.requests[0]
                request.local_mtime = self.request.local_mtime
                request.local_size = self.request.local_size
                self.request = request
            self.remove_request(self.request)
        else:
            self.request = None
            
        return self.request

class FetcherHttp(Fetcher, http.HTTPClient):

    forward_headers = [
        'last-modified',
        'content-length'
        ]
    def activate(self, request):
        Fetcher.activate(self, request)
        if not request.apFetcher:
            return

        class ClientFactory(protocol.ClientFactory):
            "Dummy ClientFactory to comply with current twisted API"
            def __init__(self, instance):
                self.instance = instance
            def buildProtocol(self, addr):
                return self.instance
            def clientConnectionFailed(self, connector, reason):
                self.instance.connectionFailed(reason)

        reactor.connectTCP(request.backend.host, request.backend.port,
                           ClientFactory(self), request.backend.timeout)

    def connectionMade(self):
        self.sendCommand(self.request.method, self.request.backend.path
                         + "/" + self.request.backend_uri)

        self.sendHeader('host', self.request.backend.host)

        if self.local_mtime != None:
            datetime = http.datetimeToString(self.local_mtime)
            self.sendHeader('if-modified-since', datetime)

        self.endHeaders()

    def handleStatus(self, version, code, message):
        self.status_code = int(code)

        self.setResponseCode(self.status_code)
        
    def handleHeader(self, key, value):

        key = string.lower(key)

        if key == 'last-modified':
            self.local_mtime = http.stringToDatetime(value)

        if key in self.forward_headers:
            self.setResponseHeader(key, value)

    def handleEndHeaders(self):
        if self.status_code == http.NOT_MODIFIED:
            log.debug("NOT_MODIFIED",'http_client')
            self.apEndCached()

    def rawDataReceived(self, data):
        self.apDataReceived(data)
        http.HTTPClient.rawDataReceived(self, data)

    def handleResponse(self, buffer):
        if self.length != 0:
            self.setResponseCode(http.NOT_FOUND)
        self.apDataEnd(buffer)

    def lineReceived(self, line):
        """
        log the line and handle it to the appropriate the base classe.
        
        The location header gave me trouble at some point, so I filter it just
        in case.

        Note: when running a class method directly and not from an object you
        have to give the 'self' parameter manualy.
        """
        log.debug(line,'http_client')
        if not re.search('^Location:', line):
            http.HTTPClient.lineReceived(self, line)

    def sendCommand(self, command, path):
        "log the line and handle it to the base class."
        log.debug(command + ":" + path,'http_client')
        http.HTTPClient.sendCommand(self, command, path)

    def endHeaders(self):
        "log and handle to the base class."
        log.debug("",'http_client')
        http.HTTPClient.endHeaders(self)

    def sendHeader(self, name, value):
        "log and handle to the base class."
        log.debug(name + ":" + value,'http_client')
        http.HTTPClient.sendHeader(self, name, value)

class FetcherFtp(Fetcher, protocol.Protocol):
    """
    This is the secuence here:

        -Start and connect the FTPClient
        -Ask for mtime
        -Ask for size
        -if couldn't get the size
            -try to get it by listing
        -get all that juicy data
        
    NOTE: Twisted's FTPClient code uses it's own timeouts here and there,
    so the timeout specified for the backend may not always be used
    """
    def activate (self, request):
        Fetcher.activate(self, request)
        if not request.apFetcher:
            return

        self.remote_file = (self.request.backend.path + "/" 
                            + self.request.backend_uri)

        from twisted.internet.protocol import ClientCreator

        creator = ClientCreator(reactor, ftp.FTPClient, passive=0)
        d = creator.connectTCP(request.backend.host, request.backend.port,
                               request.backend.timeout)
        d.addCallback(self.controlConnectionMade)
        d.addErrback(self.connectionFailed)

    def controlConnectionMade(self, ftpclient):
        self.ftpclient = ftpclient
        if log.isEnabled('ftp_client'):
            self.ftpclient.debug = 1

        self.ftpFetchMtime()

    def ftpFinish(self, code, message=None):
        "Finish the transfer with code 'code'"
        self.ftpclient.quit()
        self.setResponseCode(code, message)
        self.apDataReceived("")
        self.apDataEnd(self.transfered)

    def ftpFinishCached(self):
        "Finish the transfer giving the requests the cached file."
        self.ftpclient.quit()
        self.apEndCached()

    def ftpFetchMtime(self):
        "Get the modification time from the server."
        def apFtpMtimeFinish(msgs, fetcher, fail):
            """
            Got an answer to the mtime request.
            
            Someone should check that this is timezone independent.
            """
            code = None
            if not fail:
                code, msg = msgs[0].split()
            mtime = None
            if code == '213':
                time_tuple=time.strptime(msg[:14], "%Y%m%d%H%M%S")
                #replace day light savings with -1 (current)
                time_tuple = time_tuple[:8] + (-1,)
                #correct the result to GMT
                mtime = time.mktime(time_tuple) - time.altzone
            if (fetcher.local_mtime and mtime
                and fetcher.local_mtime >= mtime):
                fetcher.ftpFinishCached()
            else:
                fetcher.local_mtime = mtime
                fetcher.ftpFetchSize()

        d = self.ftpclient.queueStringCommand('MDTM ' + self.remote_file)
        d.addCallbacks(apFtpMtimeFinish, apFtpMtimeFinish,
                       (self, 0), None, (self, 1), None)
        d.arm()

    def ftpFetchSize(self):
        "Get the size of the file from the server"
        def apFtpSizeFinish(msgs, fetcher, fail):
            code = None
            if not fail:
                code, msg = msgs[0].split()
            if code != '213':
                log.debug("SIZE FAILED",'ftp_client')
                fetcher.ftpFetchList()
            else:
                fetcher.setResponseHeader('content-length', msg)
                fetcher.ftpFetchFile()

        d = self.ftpclient.queueStringCommand('SIZE ' + self.remote_file)
        d.addCallbacks(apFtpSizeFinish, apFtpSizeFinish,
                       (self, 0), None, (self, 1), None)
        d.arm()

    def ftpFetchList(self):
        "If ftpFetchSize didn't work try to get the size with a list command."
        def apFtpListFinish(msg, filelist, fetcher, fail):
            if fail:
                fetcher.ftpFinish(http.INTERNAL_SERVER_ERROR)
                return
            if len(filelist.files)== 0:
                fetcher.ftpFinish(http.NOT_FOUND)
                return
            file = filelist.files[0]
            fetcher.setResponseHeader('content-length', file['size'])
            fetcher.ftpFetchFile()
        filelist = ftp.FTPFileListProtocol()
        d = self.ftpclient.list(self.remote_file, filelist)
        d.addCallbacks(apFtpListFinish, apFtpListFinish,
                       (filelist, self, 0), None,
                       (filelist, self, 1), None)
        d.arm()

    def ftpFetchFile(self):
        "And finally, we ask for the file."
        def apFtpFetchFinish(msg, code, status, fetcher):
            fetcher.ftpFinish(code)
        d = self.ftpclient.retrieveFile(self.remote_file, self)
        d.addCallbacks(apFtpFetchFinish, apFtpFetchFinish,
                       (http.OK, "good", self), None,
                       (http.NOT_FOUND, "fail", self), None)
        d.arm()

    def dataReceived(self, data):
        self.setResponseCode(http.OK)
        self.apDataReceived(data)

    def connectionLost(self, reason=None):
        """
        Maybe we should do some recovery here, I don't know, but the Deferred
        should be enough.
        """
        log.debug("lost connection",'ftp_client')

class FetcherGzip(Fetcher, protocol.ProcessProtocol):
    """
    This is a fake Fetcher, it uses the real Fetcher from the request's
    backend via LoopbackRequest to get the data and gzip's or gunzip's as
    needed.

    NOTE: We use the serve_cached=0 parameter to Request.fetch so if
    it is cached it doesn't get uselessly read, we just get it from the cache.
    """
    post_convert = re.compile(r"^Should not match anithing$")
    gzip_convert = post_convert

    exe = '/bin/gzip'
    def activate(self, request, postconverting=0):
        Fetcher.activate(self, request)
        if not request.apFetcher:
            return

        self.args = (self.exe, '-c', '-9', '-n')
        if(self.factory.do_debug):
            self.args += ('-v',)

        if request.uri[-3:] == '.gz':
            host_uri = request.uri[:-3]
        else:
            host_uri = request.uri+'.gz'
            self.args += ('-d',)
        self.host_file = self.factory.cache_dir + host_uri
        self.args += (self.host_file,)

        running = self.factory.runningFetchers
        if not postconverting or running.has_key(self.host_file):
            #Make sure that the file is there
            loop = LoopbackRequest(request, self.host_transfer_done)
            loop.uri = host_uri
            loop.local_file = self.host_file
            loop.process()
            self.loop_req = loop
            loop.serve_if_cached=0
            if running.has_key(self.host_file):
                #the file is on it's way, wait for it.
                running[self.host_file].insert_request(loop)
            else:
                #we are not postconverting, so we need to fetch the host file.
                loop.fetch(serve_cached=0)
        else:
            #The file should be there already.
            self.loop_req = None
            self.host_transfer_done()

    def host_transfer_done(self):
        """
        Called by our LoopbackRequest when the real Fetcher calls
        finish() on it.

        If everything went well, check mtimes and only do the work if needed.

        If posible arrange things so the target file gets the same mtime as
        the host file.
        """
        if self.loop_req and self.loop_req.code != http.OK:
            self.setResponseCode(self.loop_req.code,
                                 self.loop_req.code_message)
            self.apDataReceived("")
            self.apDataEnd("")
            return

        self.local_mtime = os.stat(self.host_file)[stat.ST_MTIME]
        old_mtime = None
        if os.path.exists(self.local_file):
            old_mtime = os.stat(self.local_file)[stat.ST_MTIME]
        if self.local_mtime == old_mtime:
            self.apEndCached()
        else:
            self.process = reactor.spawnProcess(self, self.exe, self.args)

    def outReceived(self, data):
        self.setResponseCode(http.OK)
        self.apDataReceived(data)

    def errReceived(self, data):
        log.debug(data,'gzip')

    def loseConnection(self):
        """
        This is a bad workaround Process.loseConnection not doing it's
        job right.
        The problem only happends when we try to finish the process
        while decompresing.
        """
        if hasattr(self, 'process'):
            try:
                os.kill(self.process.pid, signal.SIGTERM)
                self.process.connectionLost()
            except exceptions.OSError, Error:
                import errno
                (Errno, Errstr) = Error
                if Errno != errno.ESRCH:
                    log.debug('Passing OSError exception '+Errstr)
                    raise 
                else:
                    log.debug('Threw away exception OSError no such process')

    def processEnded(self, reason=None):
        log.debug("Status: %d" %(self.process.status),'gzip')
        if self.process.status != 0:
            self.setResponseCode(http.NOT_FOUND)

        self.apDataReceived("")
        self.apDataEnd(self.transfered)

class FetcherRsync(Fetcher, protocol.ProcessProtocol):
    """
    I frequently am not called directly, Request.fetch makes the
    arrangement for FetcherGzip to use us and gzip the result if needed.
    
    NOTE: Here we LD_PRELOAD a rsync_hack.so to make rsync more friendly for
    streaming.
    """
    post_convert = re.compile(r"^Should not match anything$")
    gzip_convert = re.compile(r"/Packages.gz$")

    LD_PRELOAD=os.environ.get('APT_PROXY_RSYNC_HACK')
    if not LD_PRELOAD:
        LD_PRELOAD=os.getcwd() + "/rsync_hack/rsync_hack.so"
        if not os.path.exists(LD_PRELOAD):
            LD_PRELOAD='/usr/lib/apt-proxy/rsync_hack.so'

    def activate (self, request):
        Fetcher.activate(self, request)
        if not request.apFetcher:
            return

        uri = 'rsync://'+request.backend.host\
              +request.backend.path+'/'+request.backend_uri
        self.local_dir=re.sub(r"/[^/]*$", "", self.local_file)+'/'

        exe = '/usr/bin/rsync'
        if self.factory.do_debug:
            args = (exe, '--progress', '--verbose', '--times',
                    '--timeout', "%d"%(request.backend.timeout),
                    uri, '.',)
        else:
            args = (exe, '--quiet', '--times', uri, '.',
                    '--timeout',  "%d"%(request.backend.timeout),
                    )
        env = {'LD_PRELOAD': self.LD_PRELOAD}

        if(not os.path.exists(self.local_dir)):
            os.makedirs(self.local_dir)
        self.process = reactor.spawnProcess(self, exe, args, env,
                                            self.local_dir)

    def connectionMade(self):
        pass

    def outReceived(self, data):
        self.setResponseCode(http.OK)
        self.apDataReceived(data)

    def errReceived(self, data):
        log.debug(data,'rsync_client')

    def processEnded(self, reason=None):
        log.debug("Status: %d" %(self.process.status),'rsync_client')
        if self.process.status != 0:
            self.setResponseCode(http.NOT_FOUND)
            if not os.path.exists(self.local_file):
                try:
                    os.removedirs(self.local_dir)
                except:
                    pass

        elif self.transfered == '':
            log.debug("NOT_MODIFIED",'rsync_client')
            self.apEndCached()
            return
        if os.path.exists(self.local_file):
            self.local_mtime = os.stat(self.local_file)[stat.ST_MTIME]
        self.apDataReceived("")
        self.apDataEnd(self.transfered)


class FetcherFile(Fetcher):
    """
    Sends the cached file or tells the client that the file was not
    'modified-since' if appropriate.
    """
    post_convert = re.compile(r"/Packages.gz$")
    gzip_convert = re.compile(r"^Should not match anything$")

    request = None
    laterID = None
    file = None
    def if_modified(self, request):
        """
        Check if the file was 'modified-since' and tell the client if it
        wasn't.
        """
        if_modified_since = request.getHeader('if-modified-since')
        if if_modified_since != None:
            if_modified_since = http.stringToDatetime(
                    if_modified_since)

        if request.local_mtime <= if_modified_since:
            request.setResponseCode(http.NOT_MODIFIED)
            request.setHeader("Content-Length", 0)
            request.write("")
            request.finish()
            self.remove_request(request)
        
    def insert_request(self, request):
        if not request.serve_if_cached:
            request.finish()
            return
        Fetcher.insert_request(self, request)
        self.if_modified(request)
        
    def activate(self, request):
        Fetcher.activate(self, request)
        if not request.apFetcher:
            return
        self.factory.file_served(request.uri)

        self.if_modified(request)
        if len(self.requests) == 0:
            #we had a single request and didn't have to send it
            self.apEnd()
            return

        self.size = request.local_size
        self.file = open(self.local_file,'rb')
        fcntl.lockf(self.file.fileno(), fcntl.LOCK_SH)
        
        request.setHeader("Content-Length", request.local_size)
        request.setHeader("Last-modified",
                          http.datetimeToString(request.local_mtime))
        self.readBuffer()

    def readBuffer(self):
        self.laterID = None
        data = self.file.read(abstract.FileDescriptor.bufferSize)
        self.apDataReceived(data)

        if self.file.tell() == self.size:
            self.apDataReceived("")
            for req in self.requests:
                req.finish()
            self.apEnd()
        else:
            self.laterID = reactor.callLater(0, self.readBuffer)

    def apEnd(self):
        if self.laterID:
            self.laterID.cancel()
        if self.file:
            self.file.close()
        Fetcher.apEnd(self)
                                         
class Backend:
    """
    Holds the backend caracteristics, including the Fetcher class to be
    used to fetch files.
    """
    fetchers = {
        'http' : FetcherHttp,
        'ftp'  : FetcherFtp,
        'rsync': FetcherRsync,
        }
    ports = {
        'http' : 80,
        'ftp'  : 21,
        'rsync': 873,
        }

    def __init__(self, base, uri):
        self.base = base

        # hack because urlparse doesn't support rsync
        if uri[0:5] == 'rsync':
            uri = 'http'+uri[5:]
            is_rsync=1
        else:
            is_rsync=0

        self.scheme, netloc, self.path, parameters, \
                     query, fragment = urlparse.urlparse(uri)

        if ':' in netloc:
            self.host, self.port = netloc.split(':')
        else:
            self.host = netloc
            self.port = self.ports[self.scheme]
        if is_rsync:
            self.scheme = 'rsync'
        self.fetcher = self.fetchers[self.scheme]

    def check_path(self, path):
        """
        'path' is the original uri of the request.
        
        We return the path to be appended to the backend path to
        request the file from the backend server or None if the path
        doesn't match this backend.
        """
        if re.search("^/"+self.base+"/", path):
            return  path[len(self.base)+2:]
        else:
            return None

class Request(http.Request):
    """
    Each new request from connected clients generates a new instance of this
    class, and process() is called.
    """
    local_mtime = None
    local_size = None
    serve_if_cached = 1
    
    def simplify_path(self, old_path):
        """
        change //+ with /
        change /directory/../ with /
        More than three ocurrences of /../ together will not be
        properly handled
        
        NOTE: os.path.normpath could probably be used here.
        """
        path = re.sub(r"//+", "/", old_path)
        path = re.sub(r"/\./+", "/", path)
        new_path = re.sub(r"/[^/]+/\.\./", "/", path)
        while (new_path != path):
            path = new_path
            new_path = re.sub(r"/[^/]+/\.\./", "/", path)
        if (new_path != old_path):
            log.debug("simplified path from " + old_path + 
                      " to " + new_path,'simplify_path')
        return path

    def finishCode(self, responseCode, message=None):
        "Finish the request with an status code"
        self.setResponseCode(responseCode, message)
        self.write("")
        self.finish()

    def finish(self):
        http.Request.finish(self)
        if self.factory.disable_pipelining:
            if hasattr(self.transport, 'loseConnection'):
                self.transport.loseConnection()

    def check_cached(self):
        """
        check the existence and ask for the integrity of the requested file and
        return a Deferred to be trigered when we find out.
        """
        def file_ok(result, deferred, self):
            """
            called if FileVerifier has determined that the file is cached and
            in good shape.

            Now we check NOTE: The file may still be too old or not fresh
            enough.
            """
            stat_tuple = os.stat(self.local_file)

            self.local_mtime = stat_tuple[stat.ST_MTIME]
            self.local_size = stat_tuple[stat.ST_SIZE]
            log.debug("Modification time:" + 
                      time.asctime(time.localtime(self.local_mtime)), 
                      "file_ok")
            update_times = self.factory.update_times

            if update_times.has_key(self.uri): 
                last_access = update_times[self.uri]
                log.debug("last_access from db: " + 
                          time.asctime(time.localtime(last_access)), 
                          "file_ok")
            else:
                last_access = self.local_mtime


            cur_time = time.time()
            min_time = cur_time - self.factory.max_freq

            if not self.filetype.mutable:
                log.debug("file is immutable: "+self.local_file, 'file_ok')
                deferred.callback(None)
            elif last_access < min_time:
                log.debug("file is too old: "+self.local_file, 'file_ok')
                update_times[self.uri] = cur_time
                deferred.errback()
            else:
                log.debug("file is ok: "+self.local_file, 'file_ok')
                deferred.callback(None)

        log.debug("check_cached: "+self.local_file, 'file_ok')
        deferred = defer.Deferred()
        if os.path.exists(self.local_file):
            verifier = FileVerifier(self)
            verifier.deferred.addCallbacks(file_ok, deferred.errback,
                                           (deferred, self), None,
                                           None, None)
            verifier.deferred.arm()
        else:
            deferred.errback()
        return deferred

    def __init__(self, channel, queued):
        self.factory=channel.factory
        http.Request.__init__(self, channel, queued)

    def connectionLost(self, reason=None):
        """
        The connection with the client was lost, remove this request from its
        Fetcher.
        """
        #If it is waiting for a file verification it may not have an
        #apFetcher assigned
        if self.apFetcher:
            self.apFetcher.remove_request(self)
        self.finish()

    def fetch(self, serve_cached=1):
        """
        Serve 'self' from cache or through the appropriate Fetcher
        depending on the asociated backend.
    
        Use post_convert and gzip_convert regular expresions of the Fetcher
        to gzip/gunzip file before and after download.
    
        'serve_cached': this is somewhat of a hack only usefull for
        LoopbackRequests (See LoopbackRequest class for more information).
        """
        def fetch_real(result, dummyFetcher, cached, running):
            """
            This is called after verifying if the file is properly cached.
            
            If 'cached' the requested file is properly cached.
            If not 'cached' the requested file was not there, didn't pass the
            integrity check or may be outdated.
            """
            if len(dummyFetcher.requests)==0:
                #The request's are gone, the clients probably closed the
                #conection
                log.debug("THE REQUESTS ARE GONE (Clients closed conection)", 
                          'fetch')
                dummyFetcher.apEnd()
                return

            req = dummyFetcher.request
            
            if cached:
                msg = ("Using cached copy of %s"
                       %(dummyFetcher.request.local_file))
                fetcher_class = FetcherFile
            else:
                msg = ("Consulting server about %s"
                       %(dummyFetcher.request.local_file))
                fetcher_class = req.backend.fetcher

            if fetcher_class.gzip_convert.search(req.uri):
                msg = ("Using gzip/gunzip to get %s"
                       %(dummyFetcher.request.local_file))
                fetcher_class = FetcherGzip

            log.debug(msg, 'fetch_real')
            fetcher = dummyFetcher.apEndTransfer(fetcher_class)
            if (fetcher and fetcher.post_convert.search(req.uri)
                and not running.has_key(req.uri[:-3])):
                log.debug("post converting: "+req.uri,'convert')
                loop = LoopbackRequest(req)
                loop.uri = req.uri[:-3]
                loop.local_file = req.local_file[:-3]
                loop.process()
                loop.serve_if_cached=0
                #FetcherGzip will attach as a request of the
                #original Fetcher, efectively waiting for the
                #original file if needed
                gzip = FetcherGzip()
                gzip.activate(loop, postconverting=1)

        self.serve_if_cached = serve_cached
        running = self.factory.runningFetchers
        if (running.has_key(self.uri)):
            #If we have an active fetcher just use that
            log.debug("have active fetcher: "+self.uri,'client')
            running[self.uri].insert_request(self)
            return running[self.uri]
        else:
            #we make a FetcherDummy instance to hold other requests for the
            #same file while the check is in process. We will transfer all
            #the requests to a real fetcher when the check is done.
            dummyFetcher = FetcherDummy(self)
            #Standard Deferred practice
            d = self.check_cached()
            d.addCallbacks(fetch_real, fetch_real,
                           (dummyFetcher, 1, running,), None,
                           (dummyFetcher, 0, running,), None)
            d.arm()

    def process(self):
        """
        Each new request begins processing here
        """
        log.debug("Request: " + self.method + " " + self.uri);
        # Clean up URL
        self.uri = self.simplify_path(self.uri)

        self.local_file = self.factory.cache_dir + self.uri

        if self.factory.disable_pipelining:
            self.setHeader('Connection','close')
            self.channel.persistent = 0

        if self.method != 'GET':
            #we currently only support GET
            log.debug("abort - not implemented")
            self.finishCode(http.NOT_IMPLEMENTED)
            return

        if re.search('/\.\./', self.uri):
            log.debug("/../ in simplified uri ("+self.uri+")")
            self.finishCode(http.FORBIDDEN)
            return

        self.backend = None
        for backend in self.factory.backends:
            uri = backend.check_path(self.uri)
            if uri:
                self.backend = backend
                self.backend_uri = uri

        if not self.backend:
            log.debug("abort - non existent Backend")
            self.finishCode(http.NOT_FOUND, "NON-EXISTENT BACKEND")
            return

        self.filetype = findFileType(self.uri)

        if not self.filetype:
            log.debug("abort - unknown extension")
            self.finishCode(http.NOT_FOUND)
            return

        self.setHeader('content-type', self.filetype.contype)

        if os.path.isdir(self.local_file):
            log.debug("abort - Directory listing not allowed")
            self.finishCode(http.FORBIDDEN)
            return

        self.fetch()

class LoopbackRequest(Request):
    """
    This is just a fake Request so a Fetcher can attach to another
    Fetcher and be notified when then transaction is completed.

    Look at FetcherGzip for a sample.
    """
    import cStringIO
    local_mtime = None
    headers = {}
    content = cStringIO.StringIO()
    def __init__(self, other_req, finish=None):
        self.finish_cb = finish
        http.Request.__init__(self, None, 1)
        self.backend = other_req.backend
        self.factory = other_req.factory
        self.filetype = other_req.filetype
        self.method = other_req.method
        self.clientproto = other_req.clientproto
    def process(self):
        self.backend_uri = self.backend.check_path(self.uri)
    def write(self, data):
        "We don't care for the data, just want to know then it is served."
        pass
    def finish(self):
        "If he wanted to know, tell dady that we are served."
        if self.finish_cb:
            self.finish_cb()
        self.transport = None
        pass

class Channel(http.HTTPChannel):
    """
    This class encapsulates a channel (an HTTP socket connection with a single
    client).

    Each incomming request is passed to a new Request instance.
    """
    requestFactory = Request

    def headerReceived(self, line):
        "log and pass over to the base class"
        log.debug("Header: " + line)
        http.HTTPChannel.headerReceived(self, line)

    def allContentReceived(self):
        log.debug("End of request.")
        http.HTTPChannel.allContentReceived(self)

    def connectionLost(self, reason=None):
        "If the connection is lost, notify all my requets"
        for req in self.requests:
            req.connectionLost()
        log.debug("Client connection closed")
        if log.isEnabled('memleak'):
            memleak.print_top_10()

class Factory(protocol.ServerFactory):
    """
    This is the center of apt-proxy, it holds all configuration and global data
    and gets attached everywhere.

    Factory receives incommng client connections and creates a Channel for
    each client request.

    interesting attributes:

    self.runningFetchers: a dictionary, uri/Fetcher pairs, that holds the
    active Fetcher for that uri if any. If there is an active Fetcher for
    a certain uri at a certain time the request is inserted into the Fetcher
    found here instead of instanciating a new one.

    Persisten dictionaries:
    self.update_times: last time we checked the freashness of a certain file.
    self.access_times: last time that a certain file was requested.
    self.packages: all versions of a certain package name.
    
    """
    def periodic(self):
        "Called periodically as configured mainly to do mirror maintanace."
        log.debug("Doing periodic cleaning up")
        self.clean_old_files()
        self.recycler.start()
        log.debug("Periodic cleaning done")
        if (self.cleanup_freq != None):
            reactor.callLater(self.cleanup_freq, self.periodic)

    def __init__ (self):
        self.runningFetchers = {}
        pass

    def startFactory(self):
        if self.do_debug:
            log.addDomains(self.debug)
        db_dir = self.cache_dir+'/'+status_dir+'/db'
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.update_times = shelve.open(db_dir+'/update.db')
        self.access_times = shelve.open(db_dir+'/access.db')
        self.packages = shelve.open(db_dir+'/packages.db')
        #start periodic updates
        self.recycler = misc.MirrorRecycler(self, 1)
        self.recycler.start()
        if (self.cleanup_freq != None):
            reactor.callLater(self.cleanup_freq, self.periodic)
        import apt_pkg
        apt_pkg.InitSystem()
    def clean_versions(self, packages):
        """
        Remove entries for package versions which are not in cache, and delete
        some files if needed to respect the max_versions configuration.

        NOTE: This should probably be done per distribution.
        """
        if self.max_versions == None:
            #max_versions is disabled
            return
        
        cache_dir = self.cache_dir
        info = {}
        def compare(a, b):
            """ This function is just for string.sort """
            def version(uri):
                return info[uri]['Version']
            import apt_pkg
            return apt_pkg.VersionCompare(version(a), version(b))

        if len(packages) <= self.max_versions:
            return

        from packages import AptDpkgInfo
        for uri in packages[:]:
            if not os.path.exists(cache_dir +'/'+ uri):
                packages.remove(uri)
            else:
                try:
                    info[uri] = AptDpkgInfo(cache_dir +'/'+ uri)
                except SystemError:
                    log.msg("Found problems with %s, aborted cleaning"%(uri),
                            'max_versions')
                    return
                
        packages.sort(compare)
        log.debug(str(packages), 'max_versions')
        while len(packages) > self.max_versions:
            os.unlink(cache_dir +'/'+ packages[0])
            del packages[0]

    def clean_old_files(self):
        """
        Remove files which haven't been accessed for more than 'max_age' and
        all entries for files which are no longer there.
        """
        if self.max_age == None:
            #old file cleaning is disabled
            return
        cache_dir = self.cache_dir
        files = self.access_times.keys()
        min_time = time.time() - self.max_age

        for file in files:
            local_file = cache_dir + '/' + file
            if not os.path.exists(local_file):
                log.debug("old_file: non-existent "+file)
                del self.access_times[file]
            elif self.access_times[file] < min_time:
                log.debug("old_file: removing "+file)
                os.unlink(local_file)
                del self.access_times[file]

        #since we are at it, clear update times for non existent files
        files = self.update_times.keys()
        for file in files:
            if not os.path.exists(cache_dir+'/'+file):
                log.debug("old_file: non-existent "+file)
                del self.update_times[file]

    def file_served(self, uri):
        "Update the databases, this file has just been served."
        self.access_times[uri]=time.time()
        if re.search("\.deb$", uri):
            package = re.sub("^.*/", "", uri)
            package = re.sub("_.*$", "", package)
            if not self.packages.has_key(package):
                packages = [uri]
                self.packages[package] = packages
            else:
                packages = self.packages[package]
                if not uri in packages:
                    packages.append(uri)
                self.clean_versions(packages)
                self.packages[package] = packages
        self.dumpdbs()

    def stopFactory(self):
        self.dumpdbs()
        self.update_times.close()
        self.access_times.close()
        self.packages.close()
        packages.cleanup(self)

    def dumpdbs (self):
        def dump_update(key, value):
            log.msg("%s: %s"%(key, time.ctime(value)),'db')
        def dump_access(key, value):
            log.msg("%s: %s"%(key, time.ctime(value)),'db')
        def dump_packages(key, list):
            log.msg("%s: "%(key),'db')
            for file in list:
                log.msg("\t%s"%(file),'db')
        def dump(db, func):
            keys = db.keys()
            for key in keys:
                func(key,db[key])

        if log.isEnabled('db'):
            log.msg("=========================",'db')
            log.msg("Dumping update times",'db')
            log.msg("=========================",'db')
            dump(self.update_times, dump_update)
            log.msg("=========================",'db')
            log.msg("Dumping access times",'db')
            log.msg("=========================",'db')
            dump(self.access_times, dump_access)
            log.msg("=========================",'db')
            log.msg("Dumping packages",'db')
            log.msg("=========================",'db')
            dump(self.packages, dump_packages)


    def buildProtocol(self, addr):
        proto = Channel()
        proto.factory = self;
        return proto

    def log(self, request):
        return

    def debug(self, message):
        log.debug(message)
