#!/bin/bash
DESCRIPTION=`git describe --tags --long --match 'maczfs*' 2> /dev/null`
if [ "$1" = "--long" ]
then
	echo -n "${DESCRIPTION}: "
fi
DIR=`dirname $0`
VERSION=`echo ${DESCRIPTION} | awk -f ${DIR}/version.awk`
echo ${VERSION}
