#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin

rundir=/var/run/apt-proxy-v2/ 
pidfile=$rundir/apt-proxy-v2.pid 
logfile=/var/log/apt-proxy-v2.log
application=/usr/sbin/apt-proxy-v2
twistd=/usr/bin/twistd2.2
user=aptproxy
group=nogroup

[ -r /etc/default/apt-proxy-v2 ] && . /etc/default/apt-proxy-v2

test -x $twistd || exit 0
test -r $application || exit 0


case "$1" in
    start)
	echo -n "Starting apt-proxy-v2"
	[ ! -d $rundir ] && mkdir $rundir && chown $user:$group $rundir
	[ ! -f $logfile ] && touch $logfile && chown $user:$group $logfile
	start-stop-daemon --start --quiet --exec $twistd --chuid $user:$group -- \
            --pidfile=$pidfile 	--rundir=$rundir --python=$application \
	    --logfile=$logfile 	--no_save
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
