import apt_proxy
from apt_proxy_conf import aptProxyFactoryConfig
from apt_proxy import AptProxyFactory
from twisted.internet.app import Application

from twisted.python import usage        # twisted command-line processing

class Options(usage.Options):
    optParameters = [];

def updateApplication(app, config):
    factory = AptProxyFactory()
    aptProxyFactoryConfig(factory)
    app = Application("AptProxy")
    app.listenTCP(factory.proxy_port, factory)

