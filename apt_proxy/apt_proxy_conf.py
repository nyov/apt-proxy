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

from apt_proxy import AptProxyBackend
import packages
import ConfigParser, os
from ConfigParser import DEFAULTSECT

def aptProxyFactoryConfig(factory):
    defaults = {
        'port': '8000',
        'min_refresh_delay': '30',
        'complete_clientless_downloads': '0',
        'debug': '1',
        'db_debug': '0',
        'timeout': '30',
        'cleanup_freq': '600',
        'cache_dir': '/var/cache/apt-proxy',
        'max_versions': '3',
        'max_age': '10',
        'import_dir': '/var/cache/apt-proxy/import',
        'disable_pipelining': '0'
        }
    conf = ConfigParser.ConfigParser(defaults)
    if os.path.exists('/etc/apt-proxy/apt-proxy-v2.conf'):
        conf.read('/etc/apt-proxy/apt-proxy-v2.conf')
    elif os.path.exists('/etc/apt-proxy/apt-proxy-2.conf'):
        conf.read('/etc/apt-proxy/apt-proxy-2.conf')
    else:
        conf.read('/etc/apt-proxy/apt-proxy.conf')

    factory.proxy_port = conf.getint(DEFAULTSECT, 'port')
    factory.cache_dir = conf.get(DEFAULTSECT, 'cache_dir')
    factory.max_freq = conf.getint(DEFAULTSECT, 'min_refresh_delay')
    factory.max_versions = conf.getint(DEFAULTSECT, 'max_versions')
    factory.max_age = conf.getint(DEFAULTSECT, 'max_age')
    factory.timeout = conf.getint(DEFAULTSECT, 'timeout')
    factory.cleanup_freq = conf.getint(DEFAULTSECT, 'cleanup_freq')
    factory.do_debug = conf.getboolean(DEFAULTSECT, 'debug')
    factory.do_db_debug = conf.getboolean(DEFAULTSECT, 'db_debug')
    factory.finish_horphans = conf.getboolean(DEFAULTSECT,
                                              'complete_clientless_downloads')
    factory.import_dir = conf.get(DEFAULTSECT, 'import_dir')
    factory.disable_pipelining = conf.getboolean(DEFAULTSECT,
                                                 'disable_pipelining')
    factory.backends = []
    for name in conf.sections():
        if name.find('/') != -1:
            print "WARNING: backend %s contains '/' (ignored)"%(name)
            continue
        servers = conf.get(name, 'backends').split()
        server = servers[0]
        if server[-1] == '/':
            print "WARNING: removing slash at the end of %s"%(server)
            server = server[0:-1]
        backend = AptProxyBackend(name, server)
        if conf.has_option(name, 'timeout'):
            backend.timeout = conf.getint(name, 'timeout')
        else:
            backend.timeout = factory.timeout
        packages.AptPackages(backend, factory)
        factory.backends.append(backend)
        if len(servers) > 1:
            factory.debug("WARNING: using only first server on backend "+name)
