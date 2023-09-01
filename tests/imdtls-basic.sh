#!/bin/bash
# added 2023-10-05 by alorbach
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=10000
generate_conf
export PORT_RCVR="$(get_free_port)"
add_conf '
global(	defaultNetstreamDriverCAFile="'$srcdir/tls-certs/ca.pem'"
	defaultNetstreamDriverCertFile="'$srcdir/tls-certs/cert.pem'"
	defaultNetstreamDriverKeyFile="'$srcdir/tls-certs/key.pem'"
#	debug.whitelist="on"
#	debug.files=["nsd_ossl.c", "tcpsrv.c", "nsdsel_ossl.c", "nsdpoll_ptcp.c", "dnscache.c"]
)

module(	load="../plugins/imdtls/.libs/imdtls"
	tls.authmode="anon" )
input(type="imdtls"
	port="'$PORT_RCVR'")

template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(	type="omfile" 
					template="outfmt"
					file=`echo $RSYSLOG_OUT_LOG`)
'
# Begin actual testcase
startup
tcpflood -p$PORT_RCVR -m$NUMMESSAGES -Ttls -x$srcdir/tls-certs/ca.pem -Z$srcdir/tls-certs/cert.pem -z$srcdir/tls-certs/key.pem
wait_file_lines
shutdown_when_empty
wait_shutdown
seq_check
exit_test
