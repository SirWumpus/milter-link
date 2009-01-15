#!/bin/sh
#
# NOTE to make this work, you require nc(1) and the following
# entries in access.db:
#
#	GreatPause:127.0.0.1			0
#	milter-NAME-command:127.0.0.1		OK
#
# where NAME is the milter name that should accept commands.
#

if test $# -lt 2 ; then
        echo "usage: milter-cmd name command [args...]"
        exit 1
fi

name="$1"
command="$2"
shift 2
hostname=`hostname`

nc 127.0.0.1 25 <<EOT | sed -n -e 's/500 5\.[0-9]*\.[0-9]* \(.*\)/\1/p'
HELO ${hostname}
MAIL FROM:<>
milter-${name} ${command} $*
QUIT
EOT

exit 0
