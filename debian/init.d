#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin

rundir=/var/run/apt-proxy/ 
pidfile=$rundir/apt-proxy.pid 
logfile=/var/log/apt-proxy.log
application=/usr/sbin/apt-proxy
twistd=/usr/bin/twistd
user=aptproxy
group=nogroup

[ -r /etc/default/apt-proxy ] && . /etc/default/apt-proxy

test -x $twistd || exit 0
test -r $application || exit 0

# return true if at least one pid is alive
function alive()
{
    if [ -z "$*" ]; then
	return 1
    fi
    for i in $*; do
	if kill -0 $i 2> /dev/null; then
	    return 0
	fi
    done

    return 1
}


case "$1" in
    start)
	echo -n "Starting apt-proxy"
	[ ! -d $rundir ] && mkdir $rundir
	[ ! -f $logfile ] && touch $logfile
	chown $user $rundir $logfile 
	[ -f $pidfile ] && chown $user $pidfile
	# Make cache files readable
	umask 022
	start-stop-daemon --start --quiet --exec $twistd -- \
            --pidfile=$pidfile 	--rundir=$rundir --python=$application \
	    --logfile=$logfile 	--no_save
	echo "."	
    ;;

    stop)
	echo -n "Stopping apt-proxy"
	count=0
	pid=$(cat $pidfile 2>/dev/null)
	while alive $pid; do
		start-stop-daemon --stop --quiet --pidfile $pidfile
		count=$(expr $count + 1)
		if [ $count -gt 20 ]; then
			break;
		elif [ $count = 2 ]; then
			echo -n " [wait $count"
		elif [ $count -gt 2 ]; then
			echo -n " $count"
		fi
		sleep 1
	done
	if [ $count -gt 2 ]; then
		echo -n "]"
	fi
	echo "."	
    ;;

    restart)
	$0 stop
	$0 start
    ;;
    
    force-reload)
        $0 restart
    ;;

    *)
	echo "Usage: /etc/init.d/apt-proxy {start|stop|restart|force-reload}" >&2
	exit 1
    ;;
esac

exit 0
