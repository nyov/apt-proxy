#!/usr/bin/env python
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

import apt_pkg, sys, time, os, stat
from os.path import dirname, basename
import re, signal, shelve, shutil
from twisted.internet import process
import apt_proxy, copy

class AptDpkgInfo:
    """
    Gets package name and version from a .deb file.

    self.version
    self.package
    self.failed: evaluates to true if the action failed.
    """
    version_re = re.compile(r'^ Version: *([^ ]*)$', re.M)
    package_re = re.compile(r'^ Package: *([^ ]*)$', re.M)

    version = None
    package = None
    failed = 0
    def __init__(self, filename):
        self.stdout = os.popen('/usr/bin/dpkg --info %s'%(filename), 'r')
        self.data = ''
        while 1:
            new_data = self.stdout.read()
            if new_data == '':
                break
            self.data += new_data

        self.stdout.close()
        if self.data == '':
            self.failed=1
            return
        self.version = (self.version_re.search(self.data).expand(r'\1'))
        self.package = (self.package_re.search(self.data).expand(r'\1'))
        if (not self.version) or (not self.package):
            self.failed=1

class AptPackagesServer:
    """
    Handles communication with the packages server.

    This is just a hack because python-apt has a known huge memory leak, this
    way we can just kill the process to free the memory. Then that is fixed
    this hack should probably be removed.
    """
    finish=0
    answer_pending=0
    ready = re.compile("READY\n$")
    command=os.environ.get('APT_PROXY_PACKAGES')
    if not command:
        command=os.getcwd() + "/bin/apt_proxy_packages.py"
        if not os.path.exists(command):
            command='/usr/share/apt-proxy/apt_proxy_packages.py'

    def __init__(self):
        self.stdin, self.stdout = os.popen2(self.command)
    def kill(self):
        """
        This is probably not the right name for it, but since we don't know the
        pid of the process is as much as we can do to kill it.
        """
        self.stdin.close()
        self.stdout.close()
    def writeCode(self, code):
        """
        Write the code as a single line, Quoting newline chars, the server will
        dequote it.

        We force it to print 'READY' as a marker to know then we got the whole
        answer.
        """
        self.data='' #discard all unread data
        self.answer_pending=1
        code += "\nprint 'READY'\n"
        code = apt_pkg.QuoteString(code,'\n')
        self.stdin.write(code+'\n')
        self.stdin.flush()
    def readAnswer(self):
        """
        Read all output from the server until the 'READY' marker.
        """
        data = ''
        while 1:
            new_data = self.stdout.readline()
            if new_data == '':
                raise 'no data'
            if new_data != 'READY\n':
                data += new_data
            else:
                if data == 'None\n':
                    return None
                return data[:-1] #remove the last newline
    
class AptPackages:
    """
    Uses AptPackagesServer to answer queries about packages.

    Makes a fake configuration for python-apt for each backend.

    self.packages: a list of files which should go in the fake source.list
    along with their mtime.
    """
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
        """
        Called from apt_proxy.py when files get updated so we can update our
        fake lists/ directory and sources.list.
        """
        if basename(uri)=="Packages" or basename(uri)=="Release":
            self.factory.debug("REGISTERING PACKAGE:"+uri)
            mtime = os.stat(self.factory.cache_dir+'/'+uri)
            self.packages[uri] = mtime
            self.unload()
        
    def load(self):
        """
        Regenerates the fake configuration and load the packages server.
        """
        if not self.loaded:
            shutil.rmtree(self.status_dir+'/apt/lists/')
            os.makedirs(self.status_dir+'/apt/lists/partial')
            sources = open(self.status_dir+'/'+'apt/etc/sources.list', 'w')
            for file in self.packages.keys():
                # we should probably clear old entries from self.packages and
                # take into account the recorded mtime as optimization
                fake_uri='http://apt-proxy:'+file
                source_line='deb '+dirname(fake_uri)+'/ /'
                listpath=(self.status_dir+'/apt/lists/'
                          +apt_pkg.URItoFileName(fake_uri))
                sources.write(source_line+'\n')

                try:
                    #we should empty the directory instead
                    os.unlink(listpath)
                except:
                    pass
                os.symlink('../../../../../'+file, listpath)
            sources.close()
            server = self.server_process = AptPackagesServer()
            server.writeCode("init(%s)"%(self.local_config))
            server.readAnswer()
            self.loaded = 1
            
    def unload(self):
        "Tryes to make the packages server quit."
        if self.loaded:
            self.server_process.writeCode('sys.exit(0)')
            self.server_process.kill()
            del self.server_process
            self.loaded = 0
            
    def cleanup(self):
        self.unload()
        self.packages.close()

    def get_mirror_path(self, info):
        "Find the path for the package descrived by 'info'"
        self.load()
        server = self.server_process
        server.writeCode('print get_mirror_path("%s", "%s")'
                             %(info.package,info.version))
        ans = server.readAnswer()
        return ans

def cleanup(factory):
    for backend in factory.backends:
        backend.packages.cleanup()

def get_mirror_path(factory, file):
    """
    Look for the path of 'file' in all backends.
    """
    info = AptDpkgInfo(file)
    paths = []
    for backend in factory.backends:
        path = backend.packages.get_mirror_path(info)
        if path:
            paths.append('/'+backend.base+'/'+path)
    if len(paths):
        return paths
    else:
        return None

def import_debs(factory, dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    for file in os.listdir(dir):
        if file[-4:]!='.deb':
            factory.debug("IGNORING:"+ file)
            continue
        factory.debug("considering:"+ dir+'/'+file)
        paths = get_mirror_path(factory, dir+'/'+file)
        if paths:
            if len(paths) != 1:
                factory.debug("WARNING: multiple ocurrences")
                factory.debug(str(paths))
            path = paths[0]
            
            factory.debug("MIRROR_PATH:"+ path)
            spath = dir+'/'+file
            dpath = factory.cache_dir+path
            if not os.path.exists(dpath):
                print "IMPORTING:"+spath
                if not os.path.exists(dirname(dpath)):
                    os.makedirs(dirname(dpath))
                shutil.copy2(spath, dpath)
                if hasattr(factory, 'access_times'):
                    atime = os.stat(spath)[stat.ST_ATIME]
                    factory.access_times[path] = atime
    for backend in factory.backends:
        backend.packages.unload()
                
def test(factory):
    "Just for testing purposes, this should probably go to hell soon."
    for backend in factory.backends:
        backend.packages.load()

    file = ('/home/ranty/work/apt-proxy/related/tools/galeon_1.2.5-1_i386.deb')
    path = get_mirror_path(factory, file)
    print "FileName: '%s'"%(path)

if __name__ == '__main__':
    from apt_proxy_conf import aptProxyFactoryConfig
    class DummyFactory:
        def debug(self, msg):
            pass
    factory = DummyFactory()
    aptProxyFactoryConfig(factory)
    test(factory)
    cleanup(factory)

