#!/bin/bash
DESCRIPTION=`git describe --tags --long --match 'maczfs*' 2> /dev/null`
#fixme - find out how to get the right dir here
DIR=`dirname $0`
VERSION=`echo ${DESCRIPTION} | awk -f ${DIR}/version.awk`
echo $VERSION
