.\" Man page was originaly copied from apt-proxy man page.
[NAME]
apt\-proxy\-import - Import packages into the apt-proxy cache.

/apt\-proxy\-import imports /
It uses the package lists to determine where each file should be
placed, so you should run \fB'apt\-get update'\fP to allow apt\-proxy to 
update the package lists before running apt\-proxy\-import.

[USING TO BOOTSTRAP A NEW APT-PROXY CACHE]
If you have been using apt standalone, you probably have built up a
large collection of .debs in apt's cache directory.  You can import 
these files into apt\-proxy as follows:
.PP
1. Update apt\-proxy's filelists:
.nf
    apt\-get update
.fi
.PP
2. Import files from apt's cache:
.nf
    apt\-proxy\-import \-i /var/cache/apt/archives
.fi

[IMPORTING APT\-MOVE CACHE]
You can import the apt\-move generated cache into apt\-proxy using the following command:
.PP
.nf
    apt\-proxy\-import \-r /var/cache/apt\-move
.fi
.PP
This tells apt\-proxy\-import to recuse over each directory in the apt\-move cache.

[FILES]
\ /etc/apt\-proxy/apt\-proxy\&.conf

[SEE ALSO]
.na
.nh
.BR apt\-proxy (8),
.BR apt\-proxy.conf (5)
.hy
.ad

[BUGS]
apt\-proxy\-import does not use \fImax_age\fR or \fImax_versions\fR to clean the
cache directory on import.
.PP
It does not yet import source.tar.gz or Packages files.
.PP
You must run it as the apt\-proxy user or as root.

[AUTHORS]
Chris Halls <halls@debian.org>, Manuel Estrada Sainz <ranty@debian.org>
