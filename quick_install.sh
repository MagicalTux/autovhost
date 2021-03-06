#!/bin/sh

APXS=`PATH="/usr/local/httpd/bin:$PATH" which apxs 2>/dev/null`

if [ x"$APXS" = x ]; then
	echo "APXS not found, make sure you have it in PATH!"
	exit 1
fi

APACHECTL=`PATH="$(dirname "$APXS"):$PATH" which apache2ctl 2>/dev/null`

if [ x"$APACHECTL" = x ]; then
	APACHECTL=`PATH="$(dirname "$APXS"):$PATH" which apachectl 2>/dev/null`
fi

if [ x"$APACHECTL" = x ]; then
	echo "apache2ctl not found, make sure you have it in PATH!"
	exit 1
fi

"$APACHECTL" stop
"$APXS" -i -a -Wc,-Wall -Wc,--std=gnu99 -n autovhost -c mod_autovhost.c
sleep 1
env -i "$APACHECTL" start

