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

import os
from twisted.internet import reactor

class MirrorRecycler:
    working = 0
    
    def __init__(self, factory, timer):
        self.timer = timer
        self.factory = factory
        self.backends = factory.backends
        self.cache_dir = factory.cache_dir
    def start(self):
        if not self.working:
            if self.backends == []:
                self.factory.debug("NO BACKENDS FOUND")
                return
            self.cur_uri = '/'
            self.cur_dir = self.cache_dir
            self.pending = []
            for backend in self.backends:
                 self.pending.append(backend.base)
            self.stack = []
            reactor.callLater(self.timer, self.process)
            self.working = 1
    def pop(self):
        if self.stack:
            (self.cur_dir, self.cur_uri, self.pending) = self.stack.pop()
        else:
            self.working = 0
    def push(self):
        if self.pending:
            self.stack.append((self.cur_dir, self.cur_uri, self.pending))
        
    def process(self):
        entry = self.pending.pop()
        uri  = os.path.join(self.cur_uri, entry)
        path = os.path.join(self.cur_dir, entry)
        if not os.path.exists(path):
            pass
        elif os.path.isdir(path):
            self.push()
            self.cur_dir = path
            self.cur_uri = uri
            self.pending = os.listdir(self.cur_dir)
            if not self.pending:
                self.factory.debug("PRUNING EMPTY:"+path)
                os.removedirs(path)
        else:
            if os.path.isfile(path):
                #print "PATH:", path
                #print "URI: ", uri
                if not self.factory.access_times.has_key(uri):
                    self.factory.debug("RECYCLING:"+ uri)
                    self.factory.access_times[uri] = os.path.getatime(path)
            else:
                self.factory.debug("UNKNOWN:"+path)

        if not self.pending:
            self.pop()
        if self.working:
            reactor.callLater(self.timer, self.process)

if __name__ == '__main__':
    from apt_proxy_conf import aptProxyFactoryConfig
    import shelve
    
    class DummyFactory:
        def debug(self, msg):
            pass
    factory = DummyFactory()
    aptProxyFactoryConfig(factory)
    factory.access_times=shelve.open("tmp.db")
    recycle = MirrorRecycler(factory, 10)
    recycle.start()
    while recycle.working:
        recycle.process()

    factory.access_times.close()
