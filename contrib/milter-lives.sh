#!/bin/sh
#
# milter-lives.sh
#
# Contributed by Anthony Howe.
#

PATH='/usr/local/bin:/bin:/usr/bin'

WARN='postmaster@[127.0.0.1]'
ALERT='postmaster@[127.0.0.1]'
SNERT_MILTER_LIST='milter-7bit milter-ahead milter-bcc milter-date milter-gris milter-limit milter-sender milter-siq milter-spamc'

if test -d '/usr/local/etc/rc.d'; then
	# Some BSD
	STARTUP_DIR='/usr/local/etc/rc.d/'
	STARTUP_EXT='.sh'
elif test -d '/etc/init.d'; then
	# SunOS, Debian Linux
	STARTUP_DIR='/etc/init.d/'
elif test -d '/etc/rc.d/init.d'; then
	# System V, Linux
	STARTUP_DIR='/etc/rc.d/init.d/'
else
	echo "unknown STARTUP_DIR" 
	exit 1
fi	

if test -d '/var/state'; then
	# A directory with a meaningful name.
	STATE_DIR='/var/state/'
elif test -d '/var/lib'; then
	# A Linux that follows http://www.pathname.com/fhs/
	STATE_DIR='/var/lib/'
elif test -d '/var/spool'; then
	# Pretty much any unix.
	STATE_DIR='/var/spool/'
else
	echo "unknown STATE_DIR" 
	exit 1
fi

host=`hostname`

for i in ${SNERT_MILTER_LIST}; do
	msg=''
	sendto=''
	
#	# Milter is installed?
#	if test ! -d ${STATE_DIR}$i; then
#		continue
#	fi

	# Is the milter running.
        if test -f /var/run/$i.pid; then
                pid=`/var/run/$i.pid`
                pid_file="/var/run/$i.pid"
                unix_socket=="/var/run/$i.socket"
        elif test -f ${STATE_DIR}$i/pid; then
                pid=`cat ${STATE_DIR}$i/pid`
                pid_file="${STATE_DIR}$i/pid"
                unix_socket="${STATE_DIR}$i/socket"
        else
                # The milter is not running.
                ${STARTUP_DIR}$i${STARTUP_EXT} start
                msg="$i $host started (1)"
                sendto=${WARN}
                sleep 1

        fi

        # Milter is running.	

	# Are you sure?	
	ps -p "$pid" >/dev/null
	if test $? -ne 0; then	
		# The milter is not running.
		${STARTUP_DIR}$i${STARTUP_EXT} start	
		msg="$i $host started (2)"
		sendto=${WARN}
		sleep 1
	fi

	# THIS TEST SHOULD ONE DAY GO AWAY WHEN THE BUG IS FIXED.
	# 
	# Sudden on rush of email causing memory leak?
	#
	# /bin/ps axfl column output order on FreeBSD
	#  UID   PID  PPID CPU PRI NI   VSZ  RSS WCHAN  STAT  TT       TIME COMMAND
	#
	# /bin/ps axfl column output order on Linux
	#  F   UID   PID  PPID PRI  NI   VSZ  RSS WCHAN  STAT TTY        TIME COMMAND
	#
	# Ignore first 6 columns...
	# 	^( +[0-9]+){6}
	# Check size of VSZ, 5 digits or more is probably a runaway.
	# 	[ ]+[0-9]{5,}[ ]
	#
	ps axfl | grep -qE '^( +[0-9]+){6} +[0-9]{5,} .+'$i
	if test $? -eq 0; then	
		# The milter may have hung.
		${STARTUP_DIR}$i${STARTUP_EXT} restart	
		msg="$i $host restarted (3)"
		sendto=${WARN}
		sleep 1
	fi
		
	# THIS BLOCK ASSUMES THAT ALL MILTERS ARE USING DOMAIN
	# SOCKETS TO TALK WITH SENDMAIL.
	#
	# Has it hung?
	if test ! -e $unix_socket ; then
		# Missing the socket file, milter hung or dead.		
		${STARTUP_DIR}$i${STARTUP_EXT} restart	
		msg="$i $host restarted (4)"
		sendto=${WARN}
		sleep 1
		
		newpid=`cat $pid_file`

		# Did it really restart?
		if test $pid -eq $newpid; then
			# Milter failed to restart normally.
			kill -9 $pid

			# Clean up mutex, in case its an old startup script.
			if test -s "${STATE_DIR}$i/mutex"; then
				case $os in
				Linux*)
					ipcrm sem `cat ${STATE_DIR}$i/mutex`
					;;
				*BSD*|SunOS)
					ipcrm -s `cat ${STATE_DIR}$i/mutex`
					;;
				esac
			fi
			rm -f ${STATE_DIR}$i/mutex

			# Start the milter.
			${STARTUP_DIR}$i${STARTUP_EXT} start	
			msg="$i $host killed and started (5)"
			sendto=${WARN}
			sleep 1
		fi

		# Is it running now?
		if test ! -f $pid_file; then
			# Still will not running, inform support.
			msg="$i $host not running (6)"
			sendto=${ALERT}
		fi
	fi
		
	if test -n "$msg"; then
		# Give cron a copy of the message for root.
		echo "$msg"
		
		# Send a message to support.
		echo "$msg" | mail -s "$msg" ${sendto}
	fi
done

exit 0
