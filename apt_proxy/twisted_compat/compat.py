from twisted import copyright

#This is a gross hack to get non-released features
update_needed=0
if copyright.version in ("0.99.2",):
    print "Updating twisted's process module."
    if not update_needed:
        print "No updating required."
else:
    print "WARNING: apt-proxy has not been tested under this version of"\
          " twisted."
    if not update_needed:
        print "WARNING: although it should work without problem."
