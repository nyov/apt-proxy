#!/usr/bin/python -u
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
