#!/bin/sh

SELF=`basename ${0}`
if ! [ -f ./$SELF ]; then
	echo "need to run from script location."
	exit 1
fi

PROJECTNAME="apt-proxy"
CVS_MODULE="apt-proxy"

rsync -av rsync://$PROJECTNAME.cvs.sourceforge.net/cvsroot/$PROJECTNAME/ $PROJECTNAME.source

git cvsimport -p x -v -d `pwd`/$PROJECTNAME.source $CVS_MODULE

git shortlog -se
