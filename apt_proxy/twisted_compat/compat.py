from twisted import copyright

#This is a gross hack to get non-released features
if copyright.version == "0.19.0":
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

    # Disable logfile rotation (this doesn't work if twistd has no write permissions
    # in the directory that contains the logfile).  Chris reported this on #twisted
    # and this hack was suggested:
    from twisted.python.logfile import LogFile
    LogFile.rotate = lambda s: None

else:
    print "WARNING: apt-proxy has not been tested under this version of"\
          " twisted."
