from twisted import copyright

#This is a gross hack to get post-0.18.0 features
if copyright.version == "0.18.0":
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

    print "Updating twisted's http module"
    import http as new_http
    from twisted.protocols import http

    http.Request = new_http.Request
