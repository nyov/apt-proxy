#!/usr/bin/python -u
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

import sys, signal
import apt_pkg

cache=None
records=None

# we should wait for apt-proxy to send us "sys.exit"
signal.signal(signal.SIGINT, signal.SIG_IGN)

def init(local_config):
    global cache, records
    #apt_pkg.InitConfig()
    for key, value in local_config.items():
        apt_pkg.Config[key] = value
    apt_pkg.InitSystem()
            
    cache = apt_pkg.GetCache()
    records = apt_pkg.GetPkgRecords(cache)

def get_mirror_path(name, version):
    try:
        for pack_vers in cache[name].VersionList:
            if(pack_vers.VerStr == version):
                file, index = pack_vers.FileList[0]
                records.Lookup((file,index))
                return records.FileName
    except KeyError:
        pass
    return None
        
while 1:
    code = apt_pkg.DeQuoteString(sys.stdin.readline())
    exec(code)
    sys.stdout.flush()
