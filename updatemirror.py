#!/usr/bin/python2
#
# Mirror a portion of the Debian FTP site
#
# Chris Lawrence <lawrencc@debian.org> - 15 January 1999

import os, string, glob, time, re, gzip

DEBUG = 0

# Configurable section
DISTS = ['main', 'contrib', 'non-free'] # Non-US is handled separately
#DISTS = ['main', 'contrib'] # Non-US is handled separately
RELEASES = ['potato', 'woody', 'sid']
#RELEASES = ['potato', 'sid']

ARCHES = { 'slink' : ('all', 'm68k', 'i386'),
           'potato' : ('all', 'powerpc', 'm68k', 'i386'),
           'sid' : ('all', 'powerpc', 'm68k', 'i386'),
           'woody' : ('all', 'powerpc', 'm68k', 'i386'),
         }

if DEBUG:
    DISTS = ['contrib']
    RELEASES = ['sid']

# Root of local mirror
DEBROOT = '/sda1/debian/'

# List packages and files to exclude here...
# must be in glob(7) format (not regexes)

EXCLUDE = ['Packages.gz', # We make our own Packages files
	   #'gmt-*'
           ]

# Sites to use
#US_RSYNC = 'ftp.stormix.com::debian/'
#US_RSYNC = 'download.sourceforge.net::debian/'
#US_RSYNC = 'ike.egr.msu.edu::debian/'
#US_RSYNC = 'saens.debian.org::debian/'
#US_RSYNC = 'debian.uchicago.edu::debian/'
US_RSYNC = 'linux.eecs.umich.edu::debian/'
#US_RSYNC = 'ftp.kernel.org::mirrors/debian/'

NONUS_RSYNC = 'www.uk.debian.org::debian/non-US/'

NONUS   = 0 # Broken anyway...
PROJECT = 0
SOURCE  = 1
# End of configurable section

pools_to_mirror = []
if EXCLUDE: 
    exclude = EXCLUDE
else:
    exclude = []

exclude_debs = ['*.deb', '*.diff.gz', '*.dsc', '*.tar.gz']
exclude2 = exclude + exclude_debs

def parse_packages_file(packages):
    files = []
    bpackre = re.compile(r'^Filename: ((?:pool|dists)/.+)$', re.M | re.I)
    
    try:
        packfile = open(packages).read()
    except IOError:
        try:
            packfile = gzip.open(packages+'.gz').read()
        except IOError, x:
            print x
            return []
        
    packs = string.split(packfile, '\n\n')
    del packfile

    for package in packs:
        ob = bpackre.search(package)
        if ob:
            filename = ob.group(1)
            #print filename
            files.append(filename)
    print len(packs), len(files)
    return files

def parse_sources_file(sources):
    files = []
    spackre = re.compile(r'^Directory: ((?:pool|dists)/.+)$', re.M | re.I)
    spackre2 = re.compile(r'^Files:$', re.M | re.I)

    try:
        packfile = gzip.open(sources).read()
    except IOError, x:
        print x
        return []
    
    packs = string.split(packfile, '\n\n')
    del packfile

    for package in packs:
        ob = spackre.search(package)
        ob2 = spackre.search(package)
        if ob and ob2:
            dirname = ob.group(1)
            #print dirname
            
            pos = ob2.end()
            rest = package[pos+1:]
            filelist = string.split(rest, '\n')
            for name in filelist:
                name = name.strip()
                if not name: continue
                try:
                    filename = dirname+'/'+string.split(name)[2]
                    files.append(filename)
                    #print filename
                except:
                    pass
                
    print len(packs), len(files)
    return files

def generate_packages_file(debroot, binarydir, override, filename,
                           pathprefix=""):
    print 'Generating Packages file for %s%s' % (debroot, binarydir)
    os.system('cd "%s"; dpkg-scanpackages "%s" "%s" "%s" > "%s"' %
              (debroot, binarydir, override, pathprefix, filename) )

def rsync(src, dest, include=None, exclude=None, remove=1, removelots=0,
          copylinks=0):
    try:
        os.makedirs(dest)
    except OSError:
        pass

    cmd = []
    if remove: cmd.append("--delete")
    #if removelots:
    #    cmd.append('-n')
    #    cmd.append('--delete-excluded')

    if copylinks: cmd.append('--copy-links')

    if include:
        cmd.append('--include-from')
        cmd.append('.include')
        open('.include', 'w').write(string.join(include, '\n')+'\n- *\n')

    if exclude:
        cmd.append('--exclude-from')
        cmd.append('.exclude')
        open('.exclude', 'w').write(string.join(exclude, '\n')+'\n')

    os.system('rsync --rsh=ssh -rltDv --partial '+string.join(cmd, ' ')+
              ' --progress --cvs-exclude "'+src+'" "'+
              dest+'"')

def mirror_directory(srctree, subdir, exclude="", debroot="", release="",
                     dist="", arch=""):
    global pools_to_mirror

    bindir = 'dists/%s/%s/binary-%s' % (release, dist, arch)
    dest = debroot+bindir+'/'
    packages = dest+'Packages'
##    if dist == 'main':
##        overridefile = debroot+'indices/override.%s' % release
##    elif dist == 'non-US':
##        # non-US has a non-standard filename
##        overridefile = debroot+'indices/override.%s.nonus' % release
##    else:
##        overridefile = debroot+'indices/override.'+release+'.'+dist
        
    if not os.path.exists(dest):
        os.makedirs(dest)

    rsync(srctree+subdir, dest, exclude=exclude)
    if arch != "all": 
        pools_to_mirror.append( (srctree, debroot,
                                       bindir, packages) )

def main():
    if not DEBUG:
        print 'Mirroring README files'
        src = US_RSYNC+'README.*'
        dest = DEBROOT
        rsync(src, dest)

##        print 'Mirroring override files'
##        src = US_RSYNC+'indices/override.*'
##        dest = DEBROOT+'indices/'
##        if not os.path.exists(dest):
##            os.makedirs(dest)
##        rsync(src, dest, exclude=['*.gz'])

##        if NONUS:
##            src = NONUS_RSYNC+'indices/override.*'
##            dest = DEBROOT+'indices/'
##            if not os.path.exists(dest):
##                os.makedirs(dest)
##            rsync(src, dest)

##        # Uncompressed override files are needed for dpkg-scanpackages 
##        files = glob.glob(dest+'override*.gz')
##        for file in files:
##            dest = file[:-3]
##            os.system('gunzip -f < '+file+' > '+dest)

##        print 'Mirroring documentation'
##        rsync(US_RSYNC+'doc', DEBROOT)

        print 'Mirroring tools'
        rsync(US_RSYNC+'tools', DEBROOT)

        print 'Mirroring release information'
        files = []
        for release in RELEASES:
            #files.append('dists/'+release+'/main/Release*')
            files.append('dists/'+release+'/Release')
            files.append('dists/'+release+'/ChangeLog')
        rsync(US_RSYNC, dest, include=files)

        #for release in RELEASES:
        #    src = US_RSYNC+'dists/'+release+'/main/Release*'
        #    dest = DEBROOT+'dists/'+release+'/main/'
        #    if not os.path.exists(dest):
        #        os.makedirs(dest)
        #    rsync(src, dest)

        if PROJECT:
            print 'Mirroring project'
            rsync(US_RSYNC+'project', DEBROOT)

    sources = []
    for release in RELEASES:
        constr = ('%s/Contents-*.gz' % release)
        print "Mirroring", constr
        src = US_RSYNC+'dists/'+constr
        dest = DEBROOT+'dists/%s/' % release
        rsync(src, dest, exclude=exclude)

        if release == 'sid':
            rsync(DEBROOT+'dists/woody/main/binary-all',
                  DEBROOT+'dists/sid/main', exclude, remove=0)
            rsync(DEBROOT+'dists/woody/contrib/binary-all',
                  DEBROOT+'dists/sid/contrib', exclude, remove=0)
            rsync(DEBROOT+'dists/woody/main/binary-powerpc',
                  DEBROOT+'dists/sid/main', exclude, remove=0)
            rsync(DEBROOT+'dists/woody/contrib/binary-powerpc',
                  DEBROOT+'dists/sid/contrib', exclude, remove=0)

        for dist in DISTS:
            if SOURCE:
                print "Mirroring %s/%s/source" % (release, dist)
                src = US_RSYNC+'dists/%s/%s/source' % (release, dist)
                dest = DEBROOT+'dists/%s/%s/' % (release, dist)
                rsync(src, dest, exclude=exclude2)
                sources.append( (dest+'source/Sources.gz', US_RSYNC, DEBROOT) )

            for arch in ARCHES[release]:
                # We don't need to mirror arch=all anymore, since
                # pools will catch that
                if arch == 'all':
                    continue
                
                print "Mirroring %s/%s/binary-%s" % (release, dist, arch)
                srctree, subdir = US_RSYNC, 'dists/%s/%s/binary-%s/' % (release, dist, arch)
                mirror_directory(srctree, subdir,
                                 debroot=DEBROOT, dist=dist, arch=arch,
                                 exclude=exclude2, release=release)

                if dist == 'main' and arch != 'all':
                    print "Mirroring %s/%s/disks-%s" % (release, dist, arch)
                    src = US_RSYNC+'dists/%s/%s/disks-%s/' % (release, dist, arch)
                    dest = DEBROOT+'dists/%s/%s/disks-%s' % (release, dist, arch)
                    if not os.path.exists(dest): os.makedirs(dest)
                    rsync(src, dest, exclude=exclude)

                    print "Mirroring %s/%s/upgrade-*%s" % (release, dist, arch)
                    src = US_RSYNC+'dists/%s/%s/upgrade-*%s' % (release, dist,
                                                                arch)
                    dest = DEBROOT+'dists/%s/%s/' % (release, dist)
                    rsync(src, dest, exclude=exclude)

    ##    if NONUS:
    ##        for arch in ARCHES:
    ##            print "Mirroring %s/non-US/binary-%s" % (release, arch)
    ##            mirror_directory(NONUS_RSYNC+'dists/%s/binary-%s/*' % (arch),
    ##                             debroot=DEBROOT,dist='non-US', arch=arch,
    ##                             exclude=exclude)

    if not DEBUG:
        OTHERSITES = [
##	              ('spidermonkey.ximian.com::http/distributions/debian/',
##                       'helix-gnome', ['main'], ['i386'], ['woody']),
##	              ('spidermonkey.ximian.com::http/evolution-snapshots/distributions/Debian/',
##                       'evolution', ['main'], ['i386'], ['woody'])
                      ]

        for (site, name, dists, arches, releases) in OTHERSITES:
            print 'Accessing '+site
            for release in releases:
                for dist in dists:
                    if SOURCE:
                        print "Mirroring %s/%s/source" % (release, dist)
                        src = site+'dists/%s/%s/source' % (release, dist)
                        dest = DEBROOT+name+'/dists/%s/%s/' % (release, dist)
                        rsync(src, dest, exclude=exclude2)
                        sources.append( (dest+'source/Sources.gz', site, DEBROOT+name) )

                    for arch in arches:
                        print "Mirroring %s/%s/binary-%s" % (release, dist, arch)
                        srctree, subdir = site, 'dists/%s/%s/binary-%s/' % (release,
                                                                            dist, arch)
                        mirror_directory(srctree, subdir,
                                         debroot=DEBROOT+name+'/', dist=dist,
                                         arch=arch, exclude=exclude_debs,
                                         release=release)

        MISC = [
                ('lawrencc@master.debian.org:~kitame/public_html/gnome/',
                 'nautilus'),
                ]

        for site, name in MISC:
            print 'Accessing '+site
            rsync(site, DEBROOT+name)

    for info in pools_to_mirror:
        (src, debroot, bindir, packages) = info

        print 'Compressing '+packages
        os.system('gzip -9 -f < "'+packages+'" > "'+packages+'.gz"')

        print 'Generating pool'
        files = parse_packages_file(packages)
        if files:
            newfiles = []
            for file in files:
                dirpart = os.path.dirname(file)
                while dirpart and dirpart not in newfiles:
                    newfiles.append(dirpart)
                    dirpart = os.path.dirname(dirpart)
                newfiles.append(file)

            newfiles.sort()
            rsync(src, debroot, include=newfiles, copylinks=1,
                  removelots=1)

    for (sourcefile, site, debroot) in sources:
        print 'Generating pool'
        files = parse_sources_file(sourcefile)
        if files:
            newfiles = []
            for file in files:
                dirpart = os.path.dirname(file)
                while dirpart and dirpart not in newfiles:
                    newfiles.append(dirpart)
                    dirpart = os.path.dirname(dirpart)
                newfiles.append(file)

            newfiles.sort()
            rsync(site, debroot, include=newfiles, copylinks=1, removelots=1)

    print time.ctime(time.time())

if __name__ == '__main__':
    main()
