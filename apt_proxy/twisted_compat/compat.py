from twisted import copyright

#This is a gross hack to get non-released features
if copyright.version in ("0.99.0","0.99.1rc4"):
    print "Updating twisted's process module."
    import process as new_process
    from twisted.internet import process

    process.reapProcessHandlers = new_process.reapProcessHandlers
    process.registerReapProccessHandler = \
        new_process.registerReapProccessHandler
    process.unregisterReapProccessHandler = \
        new_process.unregisterReapProccessHandler
    process.Process = new_process.Process
    process.reapProcess = new_process.reapProcess

else:
    print "WARNING: apt-proxy has not been tested under this version of"\
          " twisted."
