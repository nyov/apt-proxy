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
from twisted import python

class DomainLogger:
    """
    This class should help us classify messages into domains and levels.

    This way we can select messages by kind and level.

    You just have to set in the configuration file something like:

        debug = db:3 import:8

      Which means that we only want to see messages of domain 'db' and
      level <= 3 and domain 'import' and level <= 8

      There are three special domains:

         all: if enabled all messages will be shown.
         log: is on by default and only the level can be changed
              it is meant for production logging.
         debug: aptProxyConfig will define it if you select any loging
                domains.

    Pretended meaning of levels:
       0: nothing or maybe critical information
       1: important information
       ...
       9: useless information
    """
    def __init__(self, enabled={'log':9}):
        self.enabled = enabled

    def addDomains(self, domains):
        self.enabled.update(domains)
        #print "enabled: ", self.enabled
    def isEnabled(self, domain, level=9):
        domains = self.enabled.keys()
        if domain in domains and level > self.enabled[domain]:
            return 0
        if(('all' in domains and level <= self.enabled['all'])
           or (domain in domains and level <= self.enabled[domain])):
            return 1
        else:
            return 0

    def msg(self, msg, domain='log', level=4):
        "Logs 'msg' if domain and level are appropriate"
        #print 'domain:', domain, 'level:', level
        if self.isEnabled(domain, level):
            try:
                python.log.msg("[%s] %s"%(domain, msg))
            except IOError:
                pass
    def debug(self, msg, domain='debug', level=9):
        "Useful to save typing on new debuging messages"
        if self.isEnabled(domain, level):
            try:
                python.log.debug("[%s] %s"%(domain, msg))
            except IOError:
                pass
    def err(self, msg, domain='error', level=9):
        "Log an error message"
        try:
            python.log.err("[%s] %s"%(domain, msg))
        except IOError:
            pass
        

# Prevent log being replace on reload.  This only works in cpython.
try:
    log
except NameError:
    log = DomainLogger()



class MirrorRecycler:
    """
    Reads the mirror tree looking for 'forgotten' files and adds them to
    factory.access_times so they can age and be removed like the others.

    It processes one directory entry per 'timer' seconds, which unless
    set to 0 is very slow, but it is also very light weight. And files
    which get recuested are recycled automatically anyway, so it is
    not urgent to find forgotten files. If also uses the files oun
    atime, so if the files has been there for a long time it will soon
    be removed anyway.
    
    """
    working = 0
    
    def __init__(self, factory, timer):
        self.timer = timer
        self.factory = factory
        self.cache_dir = factory.cache_dir
    def start(self):
        """
        Starts the Recycler if it is not working, it will use
        callLater to keep working until it finishes with the whole
        tree.
        """
        if not self.working:
            if self.factory.backends == []:
                log.msg("NO BACKENDS FOUND",'recycle')
                return
            self.cur_uri = '/'
            self.cur_dir = self.cache_dir
            self.pending = []
            for backend in self.factory.backends:
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
        """
        Process the next entry, is called automatically via callLater.
        """
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
                log.msg("Pruning empty directory: "+path,'recycle')
                os.removedirs(path)
        else:
            if os.path.isfile(path):
                #print "PATH:", path
                #print "URI: ", uri
                if not self.factory.access_times.has_key(uri):
                    log.msg("Adopting new file: "+ uri,'recycle')
                    self.factory.access_times[uri] = os.path.getatime(path)
            else:
                log.msg("UNKNOWN:"+path,'recycle')

        if not self.pending:
            self.pop()
        if self.working:
            reactor.callLater(self.timer, self.process)

if __name__ == '__main__':
    #Just for testing purposes.
    from apt_proxy_conf import aptProxyFactoryConfig
    import shelve
    
    class DummyFactory:
        pass
    factory = DummyFactory()
    aptProxyFactoryConfig(factory)
    factory.access_times=shelve.open("tmp.db")
    recycle = MirrorRecycler(factory, 10)
    recycle.start()
    while recycle.working:
        recycle.process()

    factory.access_times.close()
