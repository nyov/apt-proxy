#!/usr/bin/env python

import apt_pkg, sys, time, os
from twisted.internet import reactor, defer
from twisted.protocols import protocol
import re, signal, shelve
from twisted.internet import process
import apt_proxy, copy

class AptDpkgInfo(protocol.ProcessProtocol):
    version_re = re.compile(r'^ Version: *([^ ]*)$', re.M)
    package_re = re.compile(r'^ Package: *([^ ]*)$', re.M)
    exe = '/usr/bin/dpkg'
    args = (exe, '--info')

    def __init__(self, filename):
        self.args += (filename,)
        self.process = reactor.spawnProcess(self, self.exe, self.args)
        self.deferred = defer.Deferred()
        self.data = ''
    def dataReceived(self, data):
        self.data += data
    def processEnded(self):
        if self.process.status != 0:
            self.deferred.errback(self)
            raise 'dpkg return status code: %d'%(self.process.status)
        self.version = (self.version_re.search(self.data).
                        expand(r'\1'))
        self.package = (self.package_re.search(self.data).
                        expand(r'\1'))
        self.deferred.callback(self)

class AptPackagesServerOLD(protocol.ProcessProtocol):
    exe = './packages_server.py'
    args = (exe,)
    finish=0
    answer_pending=0
    ready = re.compile("\nREADY\n$")
    def __init__(self):
        self.process = reactor.spawnProcess(self, self.exe, self.args)
        self.stdin_flush = os.fdopen(self.process.stdin, "w").flush
        self.data = ''
    def dataReceived(self, data):
        if self.ready.search(data):
            self.answer_pending = 0
            data = data[:-7]
        self.data += data
    def errReceived(self, data):
        print "error:", data
    def processEnded(self):
        self.finish = 1
        if self.process.status != 0:
            raise 'status code: %d'%(os.WEXITSTATUS(self.process.status))
        print "PROCESS_ENDED"
    def kill(self):
        os.kill(self.process.pid,signal.TERM)
    def wait(self):
        while not self.finish:
            reactor.iterate()
    def writeCode(self, code):
        self.data='' #discard all unread data
        self.answer_pending=1
        code += "\nprint 'READY'\n"
        code = apt_pkg.QuoteString(code,'\n')
        self.process.write(code+'\n')
        self.stdin_flush()
    def readAnswer(self):
        while self.answer_pending:
            reactor.iterate()
        data=self.data
        self.data = ''
        return data
    
class AptPackagesServer:
    exe = './packages_server.py'
    args = (exe,)
    finish=0
    answer_pending=0
    ready = re.compile("READY\n$")
    def __init__(self):
        self.stdin, self.stdout = os.popen2('./packages_server.py')
    def kill(self):
        self.stdin.close()
        self.stdout.close()
    def writeCode(self, code):
        self.data='' #discard all unread data
        self.answer_pending=1
        code += "\nprint 'READY'\n"
        code = apt_pkg.QuoteString(code,'\n')
        self.stdin.write(code+'\n')
        self.stdin.flush()
    def readAnswer(self):
        data = ''
        while 1:
            new_data = self.stdout.readline()
            if new_data != 'READY\n':
                data += new_data
            else:
                return data
    
class AptPackages:
    local_config = {
        #'APT' : '',
        'APT::Architecture' : apt_pkg.CPU,
        #'APT::Default-Release' : 'unstable',
   
        'Dir':'/home/ranty/work/apt-proxy/twisted/cache/', # /
        'Dir::State' : 'apt/', # var/lib/apt/
        'Dir::State::Lists': 'lists/', # lists/
        #'Dir::State::cdroms' : 'cdroms.list',
        #'Dir::State::userstatus' : 'status.user',
        'Dir::State::status': 'dpkg/status', # '/var/lib/dpkg/status'
        'Dir::Cache' : '.apt/cache/', # var/cache/apt/
        #'Dir::Cache::archives' : 'archives/',
        'Dir::Cache::srcpkgcache' : 'srcpkgcache.bin',
        'Dir::Cache::pkgcache' : 'pkgcache.bin',
        'Dir::Etc' : 'apt/etc/', # etc/apt/
        'Dir::Etc::sourcelist' : 'sources.list',
        'Dir::Etc::vendorlist' : 'vendors.list',
        'Dir::Etc::vendorparts' : 'vendors.list.d',
        #'Dir::Etc::main' : 'apt.conf',
        #'Dir::Etc::parts' : 'apt.conf.d',
        #'Dir::Etc::preferences' : 'preferences',
        #'Dir::Bin' : '',
        #'Dir::Bin::methods' : '', #'/usr/lib/apt/methods'
        #'Dir::Bin::dpkg' : '/usr/bin/dpkg',
        #'DPkg' : '',
        #'DPkg::Pre-Install-Pkgs' : '',
        #'DPkg::Tools' : '',
        #'DPkg::Tools::Options' : '',
        #'DPkg::Tools::Options::/usr/bin/apt-listchanges' : '',
        #'DPkg::Tools::Options::/usr/bin/apt-listchanges::Version' : '2',
        #'DPkg::Post-Invoke' : '',
        }
    essential_dirs = ('apt', 'apt/cache', 'apt/dpkg', 'apt/etc', 'apt/lists',
                      'apt/lists/partial')
    essential_files = ('apt/dpkg/status', 'apt/etc/sources.list',)
        
    def __init__(self, backend, factory):
        self.backend = backend
        self.factory = factory
        backend.packages = self
        self.local_config = copy.copy(self.local_config)

        self.status_dir = (factory.cache_dir+'/'+ apt_proxy.status_dir
                           +'/backends/'+backend.base)
        for dir in self.essential_dirs:
            path = self.status_dir+'/'+dir
            if not os.path.exists(path):
                os.makedirs(path)
        for file in self.essential_files:
            path = self.status_dir+'/'+file
            if not os.path.exists(path):
                f = open(path,'w')
                f.close()
                del f
                
        self.local_config['Dir'] = self.status_dir

        self.packages = shelve.open(self.status_dir+'/'+'packages.db')

        self.loaded = 0
        
    def packages_file(self, uri):
        mtime = os.stat(self.factory.cache_dir+'/'+uri)
        self.packages[uri] = mtime
        
    def load(self):
        self.loaded = 1
        server = self.server_process = AptPackagesServer()
        server.writeCode("init(%s)"%(self.local_config))
        print server.readAnswer()
            
    def unload(self):
        print "unloading packages"
        self.loaded = 0
        self.server_process.writeCode('sys.exit(0)')

    def get_mirror_path(self, filename):
        def get_mirror_path_real(info, server, deferred):
            server.writeCode('print get_mirror_path("%s", "%s")'
                             %(info.package,info.version))
            ans = server.readAnswer()
            if ans == 'None':
                ans = None
            deferred.callback(ans)

        if not self.loaded:
            self.load()
            
        deferred = defer.Deferred()
        info = AptDpkgInfo(filename)
        info.deferred.addCallback(get_mirror_path_real,
                                  self.server_process, deferred)
        info.deferred.arm()
        return deferred
    
def test(factory):
    def test_cb(path):
        print "FileName: ", path
        
    for backend in factory.backends:
        file = (
            '/home/ranty/work/apt-proxy/twisted/tools/galeon_1.2.5-1_i386.deb')
        d = backend.packages.get_mirror_path(file)
        d.addCallback(test_cb)
        d.arm()
    print "FINISHED"
    for backend in factory.backends:
        backend.packages.unload()

if __name__ == '__main__':
    signal.signal(signal.SIGCHLD, process.reapProcess)
    from apt_proxy_conf import aptProxyFactoryConfig
    class DummyFactory:
        def debug(self, msg):
            pass
    factory = DummyFactory()
    aptProxyFactoryConfig(factory)
    test(factory)

