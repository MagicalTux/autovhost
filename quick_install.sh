#!/bin/sh

APXS=`PATH="/usr/local/httpd/bin:$PATH" which apxs 2>/dev/null`

if [ x"$APXS" = x ]; then
	echo "APXS not found, make sure you have it in PATH!"
	exit 1
fi

"$APXS" -i -a -c mod_autovhost.c
