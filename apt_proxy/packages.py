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

import apt_pkg, apt_inst, sys, time, os, stat
from os.path import dirname, basename
import re, signal, shelve, shutil, fcntl
from twisted.internet import process
import apt_proxy, copy, UserDict
from misc import log

class AptDpkgInfo(UserDict.UserDict):
    """
    Gets control fields from a .deb file.

    And then behaves like a regular python dictionary.

    See AptPackages.get_mirror_path
    """
    data = {}
    def __init__(self, filename):
        try:
            self.control = apt_inst.debExtractControl(open(filename))
        except SystemError:
            import traceback
            traceback.print_exc()
            log.msg("Had problems reading: %s"%(filename), 'AptDpkgInfo')
            return
        for line in self.control.split('\n'):
            if line.find(': ') != -1:
                key, value = line.split(': ', 1)
                self.data[key] = value

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
            log.msg("REGISTERING PACKAGE:"+uri,'apt_pkg')
            mtime = os.stat(self.factory.cache_dir+'/'+uri)
            self.packages[uri] = mtime
            self.unload()
        
    def __fake_stdout(self):
        import tempfile
        null = tempfile.TemporaryFile()
        self.real_stdout_fd = os.dup(sys.stdout.fileno())
        os.dup2(null.fileno(), sys.stdout.fileno())
    def __restore_stdout(self):
        os.dup2(self.real_stdout_fd, sys.stdout.fileno())
        os.close(self.real_stdout_fd)
        del self.real_stdout_fd

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
            for key, value in self.local_config.items():
                apt_pkg.Config[key] = value
            apt_pkg.InitSystem()

            if log.isEnabled('apt'):
                self.cache = apt_pkg.GetCache()
            else:
                self.__fake_stdout()
                self.cache = apt_pkg.GetCache()
                self.__restore_stdout()

            self.records = apt_pkg.GetPkgRecords(self.cache)
            self.loaded = 1
    def unload(self):
        "Tryes to make the packages server quit."
        if self.loaded:
            del self.cache
            del self.records
            self.loaded = 0
            
    def cleanup(self):
        self.unload()
        self.packages.close()

    def get_mirror_path(self, name, version):
        "Find the path for version 'version' of package 'name'"
        self.load()
        try:
            for pack_vers in self.cache[name].VersionList:
                if(pack_vers.VerStr == version):
                    file, index = pack_vers.FileList[0]
                    self.records.Lookup((file,index))
                    return self.records.FileName
        except KeyError:
            pass
        return None
      

    def get_mirror_versions(self, info):
        "Find the available versions of the package descrived by 'info'"
        self.load()
        name=info['Package']
        vers = []
        try:
            for pack_vers in self.cache[name].VersionList:
                vers.append(pack_vers.VerStr)
        except KeyError:
            pass
        return vers


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
        path = backend.packages.get_mirror_path(info['Package'],
                                                info['Version'])
        if path:
            paths.append('/'+backend.base+'/'+path)
    return paths

def get_mirror_versions(factory, file):
    """
    Look for the available version of a package in all backends.
    """
    info = AptDpkgInfo(file)
    all_vers = []
    for backend in factory.backends:
        vers = backend.packages.get_mirror_versions(info)
        for ver in vers:
            path = backend.packages.get_mirror_path(info['Package'], ver)
            all_vers.append((ver, "%s/%s"%(backend.base,path)))
    return all_vers

def closest_match(info, others):
    def compare(a, b):
        return apt_pkg.VersionCompare(a[0], b[0])

    others.sort(compare)
    version = info['Version']
    match = None
    for ver,path in others:
        if version <= ver:
            match = path
            break
    if not match:
        if not others:
            return None
        match = others[-1][1]

    dirname=re.sub(r'/[^/]*$', '', match)
    version=re.sub(r'^[^:]*:', '', info['Version'])
    if dirname.find('/pool/') != -1:
        return "/%s/%s_%s_%s.deb"%(dirname, info['Package'],
                                  version, info['Architecture'])
    else:
        return "/%s/%s_%s.deb"%(dirname, info['Package'], version)


    
def import_debs(factory, dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    for file in os.listdir(dir):
        if file[-4:]!='.deb':
            log.msg("IGNORING:"+ file, 'import')
            continue
        log.msg("considering:"+ dir+'/'+file, 'import')
        paths = get_mirror_path(factory, dir+'/'+file)
        if paths:
            if len(paths) != 1:
                log.msg("WARNING: multiple ocurrences", 'import')
                log.msg(str(paths), 'import')
            path = paths[0]
        else:
            log.msg("Not found, trying to guess", 'import')
            path = closest_match(AptDpkgInfo(dir+'/'+file),
                                 get_mirror_versions(factory, dir+'/'+file))
        if path:
            log.msg("MIRROR_PATH:"+ path, 'import')
            spath = dir+'/'+file
            dpath = factory.cache_dir+path
            if not os.path.exists(dpath):
                log.msg("IMPORTING:"+spath, 'import')
                dpath = re.sub(r'/\./', '/', dpath)
                if not os.path.exists(dirname(dpath)):
                    os.makedirs(dirname(dpath))
                f = open(dpath, 'w')
                fcntl.lockf(f.fileno(), fcntl.LOCK_EX)
                f.truncate(0)
                shutil.copy2(spath, dpath)
                f.close()
                if hasattr(factory, 'access_times'):
                    atime = os.stat(spath)[stat.ST_ATIME]
                    factory.access_times[path] = atime
    for backend in factory.backends:
        backend.packages.unload()
                
def test(factory, file):
    "Just for testing purposes, this should probably go to hell soon."
    for backend in factory.backends:
        backend.packages.load()

    info = AptDpkgInfo(file)
    path = get_mirror_path(factory, file)
    print "Exact Match:"
    print "\t%s:%s"%(info['Version'], path)

    vers = get_mirror_versions(factory, file)
    print "Other Versions:"
    for ver in vers:
        print "\t%s:%s"%(ver)
    print "Guess:"
    print "\t%s:%s"%(info['Version'], closest_match(info, vers))
if __name__ == '__main__':
    from apt_proxy_conf import factoryConfig
    class DummyFactory:
        def debug(self, msg):
            pass
    factory = DummyFactory()
    factoryConfig(factory)
    if factory.do_debug:
        log.addDomains(factory.debug)
    test(factory,
         '/home/ranty/work/apt-proxy/related/tools/galeon_1.2.5-1_i386.deb')
    test(factory,
         '/storage/apt-proxy/debian/dists/potato/main/binary-i386/base/'
         +'libstdc++2.10_2.95.2-13.deb')

    cleanup(factory)

