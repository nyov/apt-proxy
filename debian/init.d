#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin

rundir=/var/run/apt-proxy/ 
pidfile=$rundir/apt-proxy.pid 
logfile=/var/log/apt-proxy.log
application=/usr/sbin/apt-proxy
twistd=/usr/bin/twistd2.3
user=aptproxy
group=nogroup

[ -r /etc/default/apt-proxy ] && . /etc/default/apt-proxy

test -x $twistd || exit 0
test -r $application || exit 0


case "$1" in
    start)
	echo -n "Starting apt-proxy"
	[ ! -d $rundir ] && mkdir $rundir
	[ ! -f $logfile ] && touch $logfile
	chown $user:$group $rundir $logfile 
	[ -f $pidfile ] && chown $user:$group $pidfile
	start-stop-daemon --start --quiet --exec $twistd --chuid $user:$group -- \
            --pidfile=$pidfile 	--rundir=$rundir --python=$application \
	    --logfile=$logfile 	--no_save
	echo "."	
    ;;

    stop)
	echo -n "Stopping apt-proxy"
	start-stop-daemon --stop --quiet \
		--pidfile $pidfile
	echo "."	
    ;;

    restart)
	$0 stop
	sleep 1
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
