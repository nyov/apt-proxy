.\" Man page was originaly copied from apt-proxy man page.
[NAME]
apt-proxy-import - A script for importing packages into the apt-proxy cache.

/apt-proxy-import imports /
It uses the package lists to determine where each file should be
placed, so you should run \fBapt-get update\fP to allow apt-proxy to 
update the package lists before running apt-proxy-import.

[OPTIONS]
\fBconfig_file\fP is used to find the backend directories and file lists.

[USING TO BOOTSTRAP A NEW APT-PROXY CACHE]
If you have been using apt standalone, you probably have built up a
large collection of .debs in apt's cache directory.  You can import 
these files into apt-proxy as follows:
.PP
1. Update apt-proxy's filelists.  You must have at least one apt client visit
   your brand new, empty cache to initialise it.  This client must have lines
   in its sources.list that point to the apt-proxy and sucessfully run 'apt-get
   update' or equivalent:
.nf
    apt-get update
.fi
.PP
2. Import files from apt's cache:
.nf
    apt-proxy-import /var/cache/apt/archives
.fi

[IMPORTING APT-MOVE CACHE]
You can import the apt-move generated cache into apt-proxy using the following command:
.PP
.nf
    find /var/cache/apt-move -type d | xargs apt-proxy-import
.fi
.PP
This runs apt-proxy-import in each directory in the apt-file cache.

[FILES]
\ /etc/apt-proxy/apt-proxy\&.conf

[SEE ALSO]
.na
.nh
.BR apt-proxy (8),
.BR apt-proxy.conf (5)
.hy
.ad

[BUGS]
apt-proxy-import does not use MAX_VERSIONS to clean the cache directory on import.
.PP
It does not yet import source.tar.gz or Packages files.
.PP
You must run it as the apt-proxy user or as root.

[AUTHORS]
Chris Halls <chris.halls@gmx.de>, Manuel Estrada Sainz <ranty@debian.org>
