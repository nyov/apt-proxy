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

from apt_proxy import Backend
from misc import log
import packages
import ConfigParser, os
from ConfigParser import DEFAULTSECT
    
class MyConfigParser(ConfigParser.ConfigParser):
    """
    Adds 'gettime' to ConfigParser to interpret the suffixes.
    Interprets 'disabled_keyword' as disabled (None).
    """
    time_multipliers={
        's': 1,    #seconds
        'm': 60,   #minutes
        'h': 3600, #hours
        'd': 86400,#days
        }
    disabled_keyword = 'off'
    def getint(self, section, option, allow_disabled=0):
        value = self.get(section, option)
        if allow_disabled and value == self.disabled_keyword:
            return None
        return int(value)
    def gettime(self, section, option, allow_disabled=0):
        mult = 1
        value = self.get(section, option)
        if allow_disabled and value == self.disabled_keyword:
            return None
        suffix = value[-1].lower()
        if suffix in self.time_multipliers.keys():
            mult = self.time_multipliers[suffix]
            value = value[:-1]
        return int(value)*mult
    
def factoryConfig(factory):
    "Loads the configuration file into 'factory'"
    defaults = {
        'port': '9999',
        'min_refresh_delay': '30',
        'complete_clientless_downloads': '0',
        'debug': '0',
        'timeout': '30',
        'cleanup_freq': '600',
        'cache_dir': '/var/cache/apt-proxy',
        'max_versions': '3',
        'max_age': '10',
        'import_dir': '/var/cache/apt-proxy/import',
        'disable_pipelining': '0'
        }
    conf = MyConfigParser(defaults)
    if os.path.exists('/etc/apt-proxy/apt-proxy-v2.conf'):
        conf.read('/etc/apt-proxy/apt-proxy-v2.conf')
    elif os.path.exists('/etc/apt-proxy/apt-proxy-2.conf'):
        conf.read('/etc/apt-proxy/apt-proxy-2.conf')
    else:
        conf.read('/etc/apt-proxy/apt-proxy.conf')

    factory.proxy_port = conf.getint(DEFAULTSECT, 'port')
    factory.cache_dir = conf.get(DEFAULTSECT, 'cache_dir')
    factory.max_freq = conf.gettime(DEFAULTSECT, 'min_refresh_delay')
    factory.max_versions = conf.getint(DEFAULTSECT, 'max_versions', 1)
    factory.max_age = conf.gettime(DEFAULTSECT, 'max_age', 1)
    factory.timeout = conf.gettime(DEFAULTSECT, 'timeout')
    factory.cleanup_freq = conf.gettime(DEFAULTSECT, 'cleanup_freq', 1)
    factory.do_debug = conf.get(DEFAULTSECT, 'debug')
    if factory.debug != '0':
        factory.debug = {'debug':'9'}
        for domain in factory.do_debug.split():
            if domain.find(':') != -1:
                name, level = domain.split(':')
            else:
                name, level = domain, 9
            factory.debug[name] = int(level)

        factory.do_debug = 1
    else:
        factory.debug = 0
        factory.do_debug = 0
    factory.finish_horphans = conf.getboolean(DEFAULTSECT,
                                              'complete_clientless_downloads')
    factory.import_dir = conf.get(DEFAULTSECT, 'import_dir')
    factory.disable_pipelining = conf.getboolean(DEFAULTSECT,
                                                 'disable_pipelining')
    factory.backends = []
    for name in conf.sections():
        if name.find('/') != -1:
            log.msg("WARNING: backend %s contains '/' (ignored)"%(name))
            continue
        servers = conf.get(name, 'backends').split()
        if len(servers) == 0:
            log.msg("WARNING: [%s] has no backend servers (skiped)"%name)
            continue
        server = servers[0]
        if server[-1] == '/':
            log.msg ("WARNING: removing slash at the end of %s"%(server))
            server = server[0:-1]
        backend = Backend(name, server)
        if conf.has_option(name, 'timeout'):
            backend.timeout = conf.gettime(name, 'timeout')
        else:
            backend.timeout = factory.timeout
        #Create a packages parser object for the backend
        packages.AptPackages(backend, factory)
        factory.backends.append(backend)
        if len(servers) > 1:
            log.msg("WARNING: using only first server on backend "+name)
