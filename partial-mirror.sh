#!/bin/sh -e
# Anon rsync partial mirror of Debian with package pool support.
# Copyright 1999, 2000 by Joey Hess <joeyh@debian.org>, GPL'd.

# Flags to pass to rsync. More can be specified on the command line.
# These flags are always passed to rsync:
FLAGS="$@ -rLpt --partial"
# These flags are not passed in when we are getting files from pools.
# In particular, --delete is a horrid idea at that point, but good here.
FLAGS_NOPOOL="$FLAGS --exclude Packages --delete"
# And these flags are passed in only when we are getting files from pools.
# Remember, do _not_ include --delete.
FLAGS_POOL="$FLAGS"
# The host to connect to. Currently must carry both non-us and main
# and support anon rsync, which limits the options somewhat.
HOST=ftp.stormix.com
# Where to put the mirror (absolute path, please):
DEST=/mirror/debian
# The distribution to mirror:
DIST=unstable
# Architecture to mirror:
ARCH=i386
# Should source be mirrored too?
SOURCE=yes
# The sections to mirror (main, non-free, etc):
SECTIONS="main contrib non-free"
# Should a contents file kept up to date?
CONTENTS=yes
# Should symlinks be generated to every deb, in an "all" directory?
# I find this is very handy to ease looking up deb filenames.
SYMLINK_FARM=yes

###############################################################################

mkdir -p $DEST/dists $DEST/pool

# Snarf the contents file.
if [ "$CONTENTS" = yes ]; then
	mkdir -p $DEST/misc
	rsync $FLAGS_NOPOOL \
		$HOST::debian/dists/$DIST/Contents-${ARCH}.gz \
		$DEST/misc/
fi

if [ "$SOURCE" = yes ]; then
	SOURCE=source
else
	SOURCE=""
fi

# Download packages files (and .debs and sources too, until we move fully
# to pools).
for type in binary-${ARCH} $SOURCE; do
	for section in $SECTIONS; do
		mkdir -p $DEST/non-US/$section/$type $DEST/$section/$type
		rsync $FLAGS_NOPOOL \
			$HOST::debian-non-US/dists/$DIST/non-US/$section/$type \
			$DEST/non-US/$section/
		rsync $FLAGS_NOPOOL \
			$HOST::debian/dists/$DIST/$section/$type \
			$DEST/$section/
	done
done

# Update the package pool.
# Note that the same pool is used for non-us as everything else.
# TODO: probably needs to be optimized, we'll see as time goes by..
cd $DEST/pool || exit 1
rm -f .filelist

# Get a list of all the files that are in the pool based on the Packages
# files that were already updated. Thanks to aj for the awk-fu.
for file in `find $DEST -name Packages.gz | \
		xargs -r zgrep -i ^Filename: | cut -d ' ' -f 2 | grep ^pool/` \
	    `find $DEST -name Sources.gz | xargs -r zcat | \
		    awk '/^Directory:/ {D=$2} /Files:/,/^$/ { \
			if ($1 != "Files:" && $0 != "") print D "/" $3; \
		}' | grep ^pool/`
do
	DIRS="`dirname $file` $DIRS"
	echo $file >> .filelist
done

# Remove leading "pool" from all files in the file list.
# The "./" we change it to is there so the file names
# exactly match in the delete step and the files that get downloaded
# are not deleted.
sed 's!^pool/!./!' .filelist > .filelist.new
mv -f .filelist.new .filelist

(cd .. && mkdir -p $DIRS)
# Tell rsync to download only the files in the list. The exclude is here 
# to make the recursion not get anything else.
# TODO: main pool needs to be donwloaded from too, once there is one.
rsync $FLAGS_POOL \
	$HOST::debian-non-US/pool/ --include-from .filelist --exclude '*' .
# Delete all files that are not in the list, then any empty directories.
# This also kills the filelist.
find -type f | fgrep -vxf .filelist | xargs -r rm -f
find -type d -empty | xargs -r rmdir -p --ignore-fail-on-non-empty
# End of package pool update.

# Update symlinks (I like to have a link to every .deb in one directory).
if [ "$SYMLINK_FARM" = yes ]; then
	install -d  $DEST/all
	cd $DEST/all || exit 1
	find -name \*.deb | xargs -r rm -f
	find .. -name "*.deb" -type f | grep -v ^../all | \
		xargs -r -i ln -sf {} .
fi

# Waste bandwidth. Put a partial mirror on your laptop today!
