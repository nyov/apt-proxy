#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin

pidfile=/var/run/apt-proxy-v2.pid 
rundir=/var/lib/apt-proxy-v2/ 
file=/etc/apt-proxy/apt-proxy.tap 
logfile=/var/log/apt-proxy-v2.log

[ -r /etc/default/apt-proxy-v2 ] && . /etc/default/apt-proxy-v2

test -x /usr/bin/twistd || exit 0
test -r $file || exit 0


case "$1" in
    start)
	echo -n "Starting apt-proxy-v2"
	start-stop-daemon --start --quiet --exec /usr/bin/twistd -- \
            --pidfile=$pidfile 	--rundir=$rundir --file=$file --logfile=$logfile 	                  --quiet
	echo "."	
    ;;

    stop)
	echo -n "Stopping apt-proxy-v2"
	start-stop-daemon --stop --quiet \
		--pidfile $pidfile
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
	echo "Usage: /etc/init.d/apt-proxy-v2 {start|stop|restart|force-reload}" >&2
	exit 1
    ;;
esac

exit 0
