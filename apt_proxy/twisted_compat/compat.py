from twisted import copyright

#This is a gross hack to get non-released features
update_needed=0
if copyright.version in ("0.99.2","1.0.0", "1.2.0", "1.3.0rc1"):
    print "Updating twisted's process module."
    if not update_needed:
        print "No updating required."
else:
    print "WARNING: apt-proxy has not been tested under this version of"\
          " twisted (%s)."%(copyright.version)
    if not update_needed:
        print "WARNING: although it should work without problem."
