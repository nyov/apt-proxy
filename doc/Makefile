apt-proxy-import.8: ../bin/apt-proxy-import apt-proxy-import.8.inc
	PYTHONPATH=../apt_proxy \
	  help2man \
		-N \
		-i apt-proxy-import.8.inc \
		--section="8" \
		--source="Debian GNU/Linux" \
		--manual=" " \
		-o $@ \
		../bin/apt-proxy-import

clean:
	rm -f apt-proxy-import.8
