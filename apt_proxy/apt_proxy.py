#!/usr/bin/python
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

from twisted.internet import reactor, defer
from twisted.protocols import http, protocol, ftp
from twisted.web import static
import os, stat, signal
from os.path import dirname, basename
import re
import urlparse
import time
import string
import shelve
from cStringIO import StringIO

#sibling imports
import packages, misc

status_dir = '.apt-proxy'

from twisted import copyright
if copyright.version == "0.18.0":
    #This is a gross hack to get post 0.18.0 features in woody systems
    print "Updating twisted's process module."
    import apt_process

class FileType:
    def __init__ (self, regex, contype, mutable):
        self.regex = regex
        self.contype = contype
        self.mutable = mutable

    def check (self, name):
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

    FileType(re.compile(r"/Packages(\.gz)?$"), "text/plain", 1),
    FileType(re.compile(r"/Release(\.gz)?$"), "text/plain", 1),
    FileType(re.compile(r"/Sources(\.gz)$"), "text/plain", 1),
    FileType(re.compile(r"/Contents-.*(\.gz)$"), "text/plain", 1)
    )

class FileVerifier(protocol.ProcessProtocol):
    def __init__(self, request):
        self.factory = request.factory
        self.deferred = defer.Deferred()
        path = request.local_file

        if re.search(r"\.deb$", path):
            exe = '/usr/bin/dpkg'
            args = (exe, '--fsys-tarfile', path)
        elif re.search(r"\.gz$", path):
            exe = '/bin/gunzip'
            args = (exe, '-t', '-v', path)
        else:
            exe = '/bin/sh'
            args = (exe, '-c', "echo unknown file: not verified 1>&2")

        self.process = reactor.spawnProcess(self, exe, args)
        self.laterID = reactor.callLater(self.factory.timeout, self.timedout)

    def connectionMade(self):
        self.data = ''

    def dataReceived(self, data):
        #we only care about errors
        pass
    def errReceived(self, data):
        self.data = self.data + data

    def timedout(self):
        self.factory.debug("Process Timedout:")
        self.factory.debug("verifier: verication failed")
        self.deferred.errback(None)
        
    def processEnded(self):
        reactor.cancelCallLater(self.laterID)
        self.factory.debug("Process Status: %d" %(self.process.status))
        self.factory.debug("verifier: " + self.data)
        if self.process.status == 0:
            self.deferred.callback(None)
        else:
            self.factory.debug("verifier: verication failed")
            self.deferred.errback(None)

def findFileType(name):
    for type in filetypes:
        if type.check(name):
            return type
    return None

def aptProxyClientDownload(request, serve_cached=1):
    def cached_cb(result, request, serve_cached):
        request.factory.debug("CACHED")
        if serve_cached:
            return request.send_cached()
        else:
            #warning, this may only be right for AptLoopbackRequest
            request.finish()
            return None
    def not_cached_cb(result, request, running):
        request.factory.debug("NOT_CACHED")
        client_class = request.backend.client
        if client_class.gzip_convert.search(request.uri):
            client = AptProxyClientGzip(request)
        else:
            client = client_class(request)

        if (client.post_convert.search(request.uri)
            and not running.has_key(request.uri[:-3])):
            client.factory.debug("post converting: "+request.uri)
            loop = AptLoopbackRequest(request)
            loop.uri = request.uri[:-3]
            loop.local_file = request.local_file[:-3]
            loop.process()
            #AptProxyClientGzip will attach as a request of the
            #original proxy client, efectively waiting for the
            #original file
            AptProxyClientGzip(loop)
        return client

    running = request.factory.runningClients
    if (running.has_key(request.uri)):
        #If we have an active client just use that
        request.factory.debug("have active client")
        running[request.uri].insert_request(request)
        return running[request.uri]

    else:
        request.factory.debug("CHECKING_CACHED")
        d = request.check_cached()
        d.addCallbacks(cached_cb, not_cached_cb,
                       (request,serve_cached,), None,
                       (request,running,), None)
        d.arm()

class AptProxyClient:
    gzip_convert = re.compile(r"/Packages$")
    post_convert = re.compile(r"/Packages.gz$")
    proxy_client = None

    def insert_request(self, request):
        self.requests.append(request)
        request.proxy_client = self

        #get the new request up to date
        if(self.status_code != None):
            request.setResponseCode(self.status_code)
        for name, value in self.request.headers.items():
            request.setHeader(name, value)
        if self.transfered != '':
            request.write(self.transfered)

    def remove_request(self, request):
        self.requests.remove(request)
        if len(self.requests) == 0:
            self.factory.debug("Last request removed")
            if not self.factory.finish_horphans:
                if self.transport:
                    self.factory.debug(
                        "telling the transport to loseConnection")
                    self.transport.loseConnection()
                if hasattr(self, 'loseConnection'):
                    self.loseConnection()
        else:
            self.request = self.requests[0]

    def setResponseCode(self, code):
        self.status_code = code
        for req in self.requests:
            req.setResponseCode(code)

    def setResponseHeader(self, name, value):
        for req in self.requests:
            req.setHeader(name, value)

    def __init__(self, request):
        request.factory.debug(self.__class__)
        self.local_file = request.local_file
        self.local_mtime = request.local_mtime
        self.requests = [request]
        self.status_code = None
        self.length = None
        self.transfered = ''
        self.factory = request.factory
        self.request = request
        self.running_client = None
        data = request.content.read()


        self.factory.debug("Request uri: " + request.uri)

        request.setResponseCode(self.status_code)
        request.proxy_client = self
        if self.factory.runningClients.has_key(request.uri):
            raise 'There already is a running client'
        self.factory.runningClients[request.uri]=self

    def aptDataReceived(self, data):

        if self.length != None:
            self.transfered = self.transfered + data[:self.length]
            for req in self.requests:
                req.write(data[:self.length])
        else:
            self.transfered = self.transfered + data
            for req in self.requests:
                req.write(data)

    def aptDataEnd(self, buffer):
        if (self.status_code == http.OK):
            dir = dirname(self.local_file)
            if(not os.path.exists(dir)):
                os.makedirs(dir)
            f = open(self.local_file, "w")
            f.write(buffer)
            f.close()
            if self.local_mtime != None:
                os.utime(self.local_file, (time.time(), self.local_mtime))
            else:
                self.factory.debug("no local time: "+self.local_file)
                os.utime(self.local_file, (time.time(), 0))

            self.factory.file_served(self.request.uri)
            self.request.backend.packages.packages_file(self.request.uri)
        
        if self.transport:
            self.transport.loseConnection()
        for req in self.requests:
            req.finish()
        self.aptEnd()

    def aptEnd(self):
        del self.factory.runningClients[self.request.uri]

    def connectionFailed(self):
        self.factory.debug("Connection Failed!")
        self.setResponseCode(http.SERVICE_UNAVAILABLE)
        self.aptDataReceived("")
        self.aptDataEnd(self.transfered)
        
class AptProxyClientHttp(AptProxyClient, http.HTTPClient):

    forward_headers = [
        'last-modified',
        'content-length'
        ]
    def __init__(self, request):
        AptProxyClient.__init__(self, request)
        if not request.proxy_client:
            return

        tcpclient = reactor.clientTCP(request.backend.host,
                                      request.backend.port,
                                      self, request.backend.timeout)

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

        for req in self.requests:
            req.setResponseCode(self.status_code)

    def handleHeader(self, key, value):

        key = string.lower(key)

        if key == 'last-modified':
            self.local_mtime = http.stringToDatetime(value)

        if key in self.forward_headers:
            self.setResponseHeader(key, value)

    def handleEndHeaders(self):
        if self.status_code == http.NOT_MODIFIED:
            self.factory.debug("NOT_MODIFIED")
            self.transport.loseConnection()

            self.aptEnd()

            for req in self.requests:
                req.setResponseCode(http.OK)
                req.send_cached()

    def rawDataReceived(self, data):
        self.aptDataReceived(data)
        http.HTTPClient.rawDataReceived(self, data)

    def handleResponse(self, buffer):
        if self.length != 0:
            self.status_code = http.NOT_FOUND
        self.aptDataEnd(buffer)

    def lineReceived(self, line):
        self.factory.debug(line)
        if not re.search('^Location:', line):
            http.HTTPClient.lineReceived(self, line)

    def sendCommand(self, command, path):
        self.factory.debug(command + ":" + path)
        http.HTTPClient.sendCommand(self, command, path)

    def endHeaders(self):
        self.factory.debug("")
        http.HTTPClient.endHeaders(self)

    def sendHeader(self, name, value):
        self.factory.debug(name + ":" + value)
        http.HTTPClient.sendHeader(self, name, value)

class AptProxyClientFtp(AptProxyClient, protocol.Protocol):
    """
    NOTE: Twisted's ftp client code uses it's own timeouts here and there,
    so the timeout specified for the backend may not always be used
    """
    def __init__ (self, request):
        AptProxyClient.__init__(self, request)
        if not request.proxy_client:
            return

        self.remote_file = (self.request.backend.path + "/" 
                            + self.request.backend_uri)
        self.status_code = http.NOT_FOUND
        self.ftpclient = ftp.FTPClient(passive=0)
        self.ftpclient.debug = self.factory.do_debug

        reactor.clientTCP(request.backend.host, request.backend.port,
                          self.ftpclient, request.backend.timeout)
        self.ftpFetchMtime()

    def ftpFinish(self, code):
        self.ftpclient.quit()
        self.setResponseCode(code)
        self.aptDataReceived("")
        self.aptDataEnd(self.transfered)

    def ftpFinishCached(self):
        self.ftpclient.quit()
        self.aptEnd()
        self.setResponseCode(http.OK)
        for req in self.requests:
            req.send_cached()

    def ftpFetchMtime(self):
        def aptFtpMtimeFinish(msgs, client, fail):
            """
            Someone should check that this is timezone independent
            """
            code, msg = msgs[0].split()
            mtime = None
            if (not fail) and (code == '213'):
                time_tuple=time.strptime(msg[:14], "%Y%m%d%H%M%S")
                #replace day light savings with -1 (current)
                time_tuple = time_tuple[:8] + (-1,)
                #correct the result to GMT
                mtime = time.mktime(time_tuple) - time.altzone
            if (client.local_mtime and mtime
                and client.local_mtime >= mtime):
                client.ftpFinishCached()
            else:
                client.local_mtime = mtime
                client.ftpFetchSize()

        d = self.ftpclient.queueStringCommand('MDTM ' + self.remote_file)
        d.addCallbacks(aptFtpMtimeFinish, aptFtpMtimeFinish,
                       (self, 0), None, (self, 1), None)
        d.arm()

    def ftpFetchSize(self):
        def aptFtpSizeFinish(msgs, client, fail):
            code, msg = msgs[0].split()
            if fail or code != '213':
                client.factory.debug("ftp:SIZE FAILED")
                client.ftpFetchList()
            else:
                client.setResponseHeader('content-length', msg)
                client.ftpFetchFile()

        d = self.ftpclient.queueStringCommand('SIZE ' + self.remote_file)
        d.addCallbacks(aptFtpSizeFinish, aptFtpSizeFinish,
                       (self, 0), None, (self, 1), None)
        d.arm()

    def ftpFetchList(self):
        def aptFtpListFinish(msg, filelist, client, fail):
            if fail:
                client.ftpFinish(http.INTERNAL_SERVER_ERROR)
                return
            if len(filelist.files)== 0:
                client.ftpFinish(http.NOT_FOUND)
                return
            file = filelist.files[0]
            client.setResponseHeader('content-length', file['size'])
            client.ftpFetchFile()
        filelist = ftp.FTPFileListProtocol()
        d = self.ftpclient.list(self.remote_file, filelist)
        d.addCallbacks(aptFtpListFinish, aptFtpListFinish,
                       (filelist, self, 0), None,
                       (filelist, self, 1), None)
        d.arm()

    def ftpFetchFile(self):
        def aptFtpFetchFinish(msg, code, status, client):
            client.ftpFinish(code)
        d = self.ftpclient.retrieveFile(self.remote_file, self)
        d.addCallbacks(aptFtpFetchFinish, aptFtpFetchFinish,
                       (http.OK, "good", self), None,
                       (http.NOT_FOUND, "fail", self), None)
        d.arm()

    def dataReceived(self, data):
        self.setResponseCode(http.OK)
        self.aptDataReceived(data)

    def connectionLost(self):
        self.factory.debug("ftp: lost connection")

    def connectionFailed(self):
        self.factory.debug("ftp: connection failed")
        self.setResponseCode(http.NOT_FOUND)
        self.aptDataReceived("")
        self.aptDataEnd(self.transfered)

class AptProxyClientGzip(AptProxyClient, protocol.ProcessProtocol):
    post_convert = re.compile(r"^Should not match anithing$")
    gzip_convert = post_convert

    exe = '/bin/gzip'
    def __init__(self, request):
        AptProxyClient.__init__(self, request)
        if not request.proxy_client:
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

        loop = AptLoopbackRequest(request, self.host_transfer_done)
        loop.uri = host_uri
        loop.local_file = self.host_file
        loop.process()
        self.loop_req = loop
        aptProxyClientDownload(loop, serve_cached=0)

    def host_transfer_done(self):
        if self.loop_req.code != http.OK:
            self.setResponseCode(self.loop_req.code)
            self.aptDataReceived("")
            self.aptDataEnd("")
            return

        self.local_mtime = os.stat(self.host_file)[stat.ST_MTIME]
        old_mtime = None
        if os.path.exists(self.local_file):
            old_mtime = os.stat(self.local_file)[stat.ST_MTIME]
        if self.local_mtime == old_mtime:
            self.aptEnd()
            for req in self.requests:
                req.setResponseCode(http.OK)
                req.send_cached()
        else:
            self.process = reactor.spawnProcess(self, self.exe, self.args)

    def dataReceived(self, data):
        self.setResponseCode(http.OK)
        self.aptDataReceived(data)

    def errReceived(self, data):
        self.factory.debug(data)

    def loseConnection(self):
        """
        This is a bad workaround Process.loseConnection not doing it's
        job right.
        The problem only happends when we try to finish the process
        while decompresing.
        """
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.connectionLost()

    def processEnded(self):
        self.factory.debug("Status: %d" %(self.process.status))
        if self.process.status != 0:
            self.setResponseCode(http.NOT_FOUND)

        self.aptDataReceived("")
        self.aptDataEnd(self.transfered)

class AptProxyClientRsync(AptProxyClient, protocol.ProcessProtocol):
    post_convert = re.compile(r"^Should not match anything$")
    gzip_convert = re.compile(r"/Packages.gz$")

    LD_PRELOAD=os.environ.get('APT_PROXY_RSYNC_HACK')
    if not LD_PRELOAD:
        LD_PRELOAD=os.getcwd() + "/rsync_hack/rsync_hack.so"
        if not os.path.exists(LD_PRELOAD):
            LD_PRELOAD='/usr/lib/apt-proxy/rsync_hack.so'

    def __init__ (self, request):
        AptProxyClient.__init__(self, request)
        if not request.proxy_client:
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

    def dataReceived(self, data):
        self.setResponseCode(http.OK)
        self.aptDataReceived(data)

    def errReceived(self, data):
        self.factory.debug(data)

    def processEnded(self):
        self.factory.debug("Status: %d" %(self.process.status))
        if self.process.status != 0:
            self.setResponseCode(http.NOT_FOUND)
            if not os.path.exists(self.local_file):
                try:
                    os.removedirs(self.local_dir)
                except:
                    pass

        elif self.transfered == '':
            self.factory.debug("NOT_MODIFIED")
            self.aptEnd()
            for req in self.requests:
                req.setResponseCode(http.OK)
                req.send_cached()
            return
        if os.path.exists(self.local_file):
            self.local_mtime = os.stat(self.local_file)[stat.ST_MTIME]
        self.aptDataReceived("")
        self.aptDataEnd(self.transfered)

class AptProxyBackend:
    clients = {
        'http' : AptProxyClientHttp,
        'ftp'  : AptProxyClientFtp,
        'rsync': AptProxyClientRsync,
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
        self.client = self.clients[self.scheme]

    def check_path(self, path):
        if re.search("^/"+self.base+"/", path):
            return  path[len(self.base)+2:]
        else:
            return None

class AptProxyRequest(http.Request):
    def simplify_path(self, path):
        """
        change //+ with /
        change /directory/../ with /
        More than three ocurrences of /../ together will not be
        properly handled
        """
        path = re.sub(r"//+", "/", path)
        new_path = re.sub(r"/[^/]+/\.\./", "/", path)
        while (new_path != path):
            path = new_path
            new_path = re.sub(r"/[^/]+/\.\./", "/", path)
        return path

    def finishCode(self, responseCode):
        self.setResponseCode(responseCode)
        self.write("")
        self.finish()

    def check_cached(self):
        def file_ok(result, deferred, self):
            stat_tuple = os.stat(self.local_file)

            self.local_mtime = stat_tuple[stat.ST_MTIME]
            self.local_size = stat_tuple[stat.ST_SIZE]
            update_times = self.factory.update_times

            if update_times.has_key(self.uri): 
                last_access = update_times[self.uri]
            else:
                last_access = self.local_mtime

            cur_time = time.time()
            min_time = cur_time - self.factory.max_freq

            if self.filetype.mutable and last_access < min_time:
                update_times[self.uri] = cur_time
                deferred.errback()
            else:
                deferred.callback(None)

        deferred = defer.Deferred()
        self.local_mtime = None
        if os.path.exists(self.local_file):
            verifier = FileVerifier(self)
            verifier.deferred.addCallbacks(file_ok, deferred.errback,
                                           (deferred, self), None,
                                           None, None)
            verifier.deferred.arm()
        else:
            deferred.errback()
        return deferred

    def send_cached(self):
        if_modified_since = self.getHeader('if-modified-since')
        if if_modified_since != None:
            if_modified_since = http.stringToDatetime(
                    if_modified_since)

        if self.local_mtime <= if_modified_since:
            self.setResponseCode(http.NOT_MODIFIED)
            self.setHeader("Content-Length", 0)
            self.write("")
            self.finish()
            return None

        f = open(self.local_file,'rb')
        self.setHeader("Content-Length", self.local_size)
        self.setHeader("Last-modified",
                       http.datetimeToString(self.local_mtime))
        self.factory.file_served(self.uri)
        return static.FileTransfer(f, self.local_size, self)

    def __init__(self, channel, queued):
        self.factory=channel.factory
        http.Request.__init__(self, channel, queued)

    def connectionLost(self):
        #If it is waiting for a file verification it may not have a
        #proxy_client assigned
        if hasattr(self, 'proxy_client'):
            self.proxy_client.remove_request(self)

    def process(self):
        self.uri = self.simplify_path(self.uri)
        self.local_file = self.factory.cache_dir + self.uri

        if self.factory.disable_pipelining:
            self.setHeader('Connection','close')

        if self.method != 'GET':
            #we currently only support GET
            self.finishCode(http.NOT_IMPLEMENTED)
            return

        if re.search('/../', self.uri):
            self.factory.debug("/../ in simplified uri")
            self.finishCode(http.FORBIDDEN)
            return

        self.backend = None
        for backend in self.factory.backends:
            uri = backend.check_path(self.uri)
            if uri:
                self.backend = backend
                self.backend_uri = uri

        if not self.backend:
            self.factory.debug("non existent Backend")
            self.finishCode(http.NOT_FOUND)
            return

        self.filetype = findFileType(self.uri)

        if not self.filetype:
            self.factory.debug("unknown extension")
            self.finishCode(http.NOT_FOUND)
            return

        self.setHeader('content-type', self.filetype.contype)

        if os.path.isdir(self.local_file):
            self.factory.debug("Directory listing not allowed")
            self.finishCode(http.FORBIDDEN)
            return

        aptProxyClientDownload(self)

class AptLoopbackRequest(AptProxyRequest):
    local_mtime = None
    headers = {}
    content = StringIO()
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
        pass
    def send_cached(self):
        if self.finish_cb:
            self.finish_cb()
        pass
    def finish(self):
        if self.finish_cb:
            self.finish_cb()
        self.transport = None
        pass

class AptProxy(http.HTTPChannel):

    requestFactory = AptProxyRequest

    def headerReceived(self, line):
        self.factory.debug(line)
        http.HTTPChannel.headerReceived(self, line)

    def allContentReceived(self):
        self.factory.debug("")
        http.HTTPChannel.allContentReceived(self)

    def connectionLost(self):
        for req in self.requests:
            req.connectionLost()
        self.factory.debug("Client connection closed")

class AptProxyFactory(protocol.ServerFactory):

    def periodic(self):
        self.debug("Doing periodic cleaning up")
        self.clean_old_files()
        self.recycler.start()
        self.debug("Periodic cleaning done")
        reactor.callLater(self.cleanup_freq, self.periodic)

    def __init__ (self):
        self.runningClients = {}
        pass

    def startFactory(self):
        db_dir = self.cache_dir+'/'+status_dir+'/db'
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.update_times = shelve.open(db_dir+'/update.db')
        self.access_times = shelve.open(db_dir+'/access.db')
        self.packages = shelve.open(db_dir+'/packages.db')
        #start periodic updates
        reactor.callLater(self.cleanup_freq, self.periodic)
        self.recycler = misc.MirrorRecycler(self, 1)
        self.recycler.start()
    def clean_versions(self, packages):
        cache_dir = self.cache_dir
        if len(packages) <= self.max_versions:
            return

        for package in packages[:]:
            if not os.path.exists(cache_dir +'/'+ package):
                packages.remove(package)

        # this is not the right way to do it, we should sort the list
        # by package version first or something
        while len(packages) > self.max_versions:
            os.unlink(packages[0])
            del packages[0]

    def clean_old_files(self):
        cache_dir = self.cache_dir
        files = self.access_times.keys()
        min_time = time.time() - self.max_age

        for file in files:
            local_file = cache_dir + '/' + file
            if not os.path.exists(local_file):
                self.debug("old_file: non-existent "+file)
                del self.access_times[file]
            elif self.access_times[file] < min_time:
                self.debug("old_file: removing "+file)
                os.unlink(local_file)
                del self.access_times[file]

        #since we are at it, clear update times for non existent files
        files = self.update_times.keys()
        for file in files:
            if not os.path.exists(cache_dir+'/'+file):
                self.debug("old_file: non-existent "+file)
                del self.update_times[file]

    def file_served(self, uri):
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
            print "%s: %s"%(key, time.ctime(value))
        def dump_access(key, value):
            print "%s: %s"%(key, time.ctime(value))
        def dump_packages(key, list):
            print "%s: "%(key)
            for file in list:
                print "\t%s"%(file)
        def dump(db, func):
            keys = db.keys()
            for key in keys:
                func(key,db[key])

        if self.do_db_debug:
            print "========================="
            print "Dumping update times"
            print "========================="
            dump(self.update_times, dump_update)
            print "========================="
            print "Dumping access times"
            print "========================="
            dump(self.access_times, dump_access)
            print "========================="
            print "Dumping packages"
            print "========================="
            dump(self.packages, dump_packages)


    def buildProtocol(self, addr):
        proto = AptProxy()
        proto.factory = self;
        return proto

    def log(self, request):
        return

    def debug(self, message):
        if self.do_debug:
            print message
