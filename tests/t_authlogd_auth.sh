
# -------------------------------------------------------------------------
# Auxiliary functions.
# -------------------------------------------------------------------------

start_authlogd() {
	echo "Starting authlogd server"
	
	test_dir=$(atf_get_srcdir);
	authlogd_dir="/usr/src/local/devel/authlogd";
	
	#remove auth log socket
	rm /var/run/authlog
	
	$authlogd_dir/authlogd -D -c $authlogd_dir/doc/authlogd_app.xml -p $authlogd_dir/doc/dsapubkey.pem \
	-P $authlogd_dir/doc/dsaprivkey.pem -C $authlogd_dir/doc/dsacert.pem 2>$test_dir/msg 1>$test_dir/log &
	
	echo $! >authlogd.pid
	echo "Authlogd server started (pid $(cat authlogd.pid))"
}

stop_authlogd() {
	if [ -f authlogd.pid ]; then
		echo "Stopping Authlogd server (pid $(cat authlogd.pid))"
		kill $(cat authlogd.pid)
	fi
	if [ -f mdg ]; then
		echo "Server output was:"
		sed -e 's,^,    ,' msg
	fi
}

#
# Mounts the given source directory on the target directory using psshfs.
# Both directories are supposed to live on the current directory.
#
mount_psshfs() {
	atf_check -s eq:0 -o empty -e empty \
	    mount -t psshfs -o -F=$(pwd)/ssh_config localhost:$(pwd)/${1} ${2}
}

# -------------------------------------------------------------------------
# The test cases.
# -------------------------------------------------------------------------

atf_test_case authlogd_auth_tc
authlogd_auth_tc_head() {
	atf_set "descr" "Check if output of authlogd is correct or not."
}
authlogd_auth_tc_body() {

	start_authlogd
}
authlogd_auth_tc_cleanup() {
	stop_authlogd
}


# -------------------------------------------------------------------------
# Initialization.
# -------------------------------------------------------------------------

atf_init_test_cases() {
	atf_add_test_case authlogd_auth_tc
}
