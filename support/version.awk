#!/usr/bin/awk
#
# Mac ZFS 'official' releases are tagged as follows:
#
# maczfs_<onnvsnyc>(-<rel>)?
#
# where onnvsync is the number corresponding to the onnv release
# e.g. maczfs_72 corresponds with onnv_72
#
# Should additional releases on the same tag happen, then they
# will be denoted as:
#   maczfs_72-01
#   maczfs_72-02
# and so on
#
# These are then pulled out with git describe to get the offset
# from the original release e.g.
# maczfs_72-8-g626d83e
#
# The -8- indicates 8 commits since maczfs_72 was released; the
# g626d83e is commit node at the current stage. From this, we 
# can recreate any version of the build.
#
# These are merged into version numbers as follows:
#
# <onnvsync>.<rel>.<commits>
#
# If rel is missing in the original tag, then it is treated as 0.
#
# So, a git describe of:
#
# maczfs_72-8-g626d83e
#
# will result in a version of 72.0.8, whilst a git describe of:
#
# maczfs_72-01-3-b58df311 
#
# will result in a version number of 72.1.3.
#
# This version number is used as the kernel module version, the
# ZFS project identifier, and the Info.plist entries, as stamped by the
# build script in the zfs.kext target.
#
BEGIN {
	FS = "_|-";
}

function max(a,b) { 
	if (int(a)<int(b)) 
		return int(a) 
	else 
		return int(b) 
}

/maczfs_/ {
	ONNV = $2
	if (NF<5) {
		REL = 0
		COMMIT = max($3,99)
	} else {
		REL = max($3,99)
		COMMIT = max($4,99)
	}
	print ONNV "." REL "." COMMIT
}


