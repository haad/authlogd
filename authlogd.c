/*
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Adam Hamsik.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
     
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

static struct event * allocev(void);
static void dolog(int, short, void *);
static int openauthlog(const char *);
static int opensyslog(const char *);
static auth_msg_t * unptoauth(struct unpcbid *);
static char * find_msg(char *, size_t, size_t *);
static void usage(void);

/*! 
 * Authenticated Logging Deamon 
 * Descr:
 * This is deamon used for authentication of logging aplications.
 * Authenticated messages are marked with special created SD element which contains
 * digitaly signed hash of application PID.
 *
 * Several Auth. modules are supported and more can be easily added
 * there are auth_mod_hash and auth_mod_gid modules which uses application
 * binary hash and efective GroupID of running application to authenticate it.
 *
 * Authentication info is loaded to module with configuration file which must be in
 * proplib internalize form. Example of self signed configuration file can be found 
 * in doc/authlogd_app.xml.
 *
 */

const char *syslog_path;
char cert_file[MAXPATHLEN];
char pubk_file[MAXPATHLEN];
char privk_file[MAXPATHLEN];

uint8_t flg_debug; /** Debug flag */
int syssoc;    /** Slyslogd socket */

int
main(int argc, char **argv)
{
	int ch, soc, ret;
	int flg_cert, flg_cnf, flg_dump;
	size_t len;
	prop_dictionary_t conf_buf;
	struct event *ev;

	conf_buf = NULL;
	syslog_path = SYSLOG_PATH;
	len = 0;
	flg_dump = 0;
	flg_cnf = 0;
	flg_cert = 0;
	
  	while ((ch = getopt(argc, argv, "P:p:C:c:S:hdD")) != -1 )
		switch(ch){
			
		case 'h':
			usage();
			/* NOTREACHED */
			break;
		case 'C':
		{
			/* Public key certificate to verify config file. */
			flg_cert = 1;
			if ((len = strlen((char *)optarg)) > MAXPATHLEN)
				len = MAXPATHLEN - 1;
			
			strncpy(cert_file, (char *)optarg, len);
			cert_file[len + 1] = '\0';
		}
		break;
		case 'c':
		{
			DPRINTF(("Internalizing proplib authenticated application file %s\n", (char *)optarg));
			if ((conf_buf = prop_dictionary_internalize_from_file((char *)optarg)) == NULL)
				err(EXIT_FAILURE, "Cannot Internalize config file to buffer %s %s %.4d\n",
				 __FILE__, __func__, __LINE__);
			flg_cnf = 1;
		}
		break;
		case 'P':
		{
			/* Private key used to sign auth messages. */
			if ((len = strlen((char *)optarg)) > MAXPATHLEN)
				len = MAXPATHLEN - 1;
			
			strncpy(privk_file, (char *)optarg, len);
			privk_file[len + 1] = '\0';
		}
		break;
		case 'p':
		{
			/* Public key used to verify config file. */
			if ((len = strlen((char *)optarg)) > MAXPATHLEN)
				len = MAXPATHLEN - 1;
			
			strncpy(pubk_file, (char *)optarg, len);
			pubk_file[len + 1] = '\0';
		}
		break;
		case 'd':
		{
			flg_dump = 1;
		}
		break;
		case 'D':
		{
			flg_debug = 1;
		}
		break;
		case'S':
		{
			syslog_path = (const char *)optarg;
			DPRINTF(("Syslog socket path is %s\n", syslog_path));
			
		}
		break;
		default:
			usage();
			/* NOTREACHED */
		}
	argc-=optind;
	argv+=optind;

	if (!flg_cnf)
		return EXIT_FAILURE;

	/** Dump part of configuration file which can be used for signing */
	if (flg_dump) {
		DPRINTF(("Dumping configuration file to: config.xml\n"));
		dump_config(conf_buf, "config.xml");
		return EXIT_SUCCESS;
	}

	if (!flg_cert)
	  return EXIT_FAILURE;
	
	/** Initialize ssl subsystem */
	authlogd_ssl_init();
	authlogd_sign_init();
	authlogd_verify_init();

	/** Initialize precompiled authentication modules. */
	auth_mod_init();

	/** Parse configuration file and init auth modules info. */
	parse_config(conf_buf);

	/*
	 * Create the global kernel event descriptor.
	 */
	(void)event_init();
	
	/** Open Syslog socket */
	syssoc = opensyslog(syslog_path);
	
	/** Open authenticated log */
	soc = openauthlog(AUTH_LOG_PATH);

	/** Listen on auth log and process received packets */
	ev = allocev();
	event_set(ev, soc, EV_READ | EV_PERSIST, dolog, ev);
	event_add(ev, NULL);
	
	ret = event_dispatch();
	/* normal termination via die(), reaching this is an error */
	DPRINTF(("event_dispatch() returned %d\n", ret));
	
	return ret;
}

/*!
 * Authenticate Logging process after accept and do Logging after it.
 * We will authenticate every application only after calling connect/accept.
 * @param[in] soc socket opened with openauthlog()
 * @see openauthlog()
 */
static void
dolog(int fd, short event, void *ev)
{
	struct sockaddr_un addr;
	struct unpcbid unp;
	auth_msg_t *auth;
	msg_t *msg;
	socklen_t i, unp_size = sizeof(unp);
	ssize_t msg_size;		/** length of received stream */
	size_t idx;
	
	int ret, nsoc;
	char buf[AUTHLOG_MESSAGE_LEN];	/** buffer for receiving message */
	char *msg_p;
	
	idx = 0;
	msg_p = NULL;
	msg_size = 0;
		
	i = sizeof(struct sockaddr_un);
	/*!
	 * Call accept() to accept connection request. This call will block
	 * until a connection request arrives.
	 */
	if ((nsoc = accept(fd, (struct sockaddr *)&addr, &i)) == -1)
		err(EXIT_FAILURE, "Accept failed %s %s %.4d\n",
		 __FILE__, __func__, __LINE__);
			
	/** Get information about connected peer */
	if (getsockopt(nsoc, 0, LOCAL_PEEREID, &unp, &unp_size) < 0)
		err(EXIT_FAILURE, "Cannot get LOCAL_PEERID message from" 
		"socket %s %s %.4d\n", __FILE__, __func__, __LINE__);

	/** Convert info to our representation */
	auth = unptoauth(&unp);

	/** Check all configured auth modules */
	ret = auth_mod_loop(auth);

	DPRINTF(("Authentication module framework returned %d\n", ret));

	if ((msg = malloc(sizeof(msg_t))) == NULL)
		err(EXIT_FAILURE, "Cannot allocate more memory %s %s %.4d\n",
		__FILE__, __func__, __LINE__);
	memset(msg, 0, sizeof(msg_t));

	msg->auth_msg = auth;
	msg->msg_auth_status = ret;
	
	while (1) {
		memset(msg, 0, sizeof(msg_t));
		idx = 0;
		
		msg_size = recv(nsoc, buf, (sizeof(buf) - 1), 0);
		if (msg_size == -1)
			err(EXIT_FAILURE, "Recv call failed %s %s %.4d\n",
			__FILE__, __func__, __LINE__);
		
		/** recv_size 0 means EOF from other side. */
		if (msg_size == 0)
			break;
		
		/** Set last character in receiving buffer to \0 for extra insurance */	
		buf[AUTHLOG_MESSAGE_LEN - 1] = '\0';
			
		DPRINTF(("Received %d bytes long buffer.\n", msg_size));	
		
		while ((msg_p = find_msg(buf, msg_size, &idx)) != NULL) {
			msg->msg_size = strlen(msg_p);
			
			strncpy(msg->msg_buf, msg_p, msg->msg_size);
			
			/** Parse msg_t and create authlogd sd elements save result to msg_t::msg_new. */
			parse_msg(msg);

			DPRINTF(("Sending message to syslog\n"));
			if (flg_debug)
				fprintf(stderr, "%s\n", msg->msg_new);
			else
				/** Send message with auth SD element to syslog. */
				send(syssoc, msg->msg_new, strlen(msg->msg_new), 0);
		}
	}
	
	free(msg);
	close(nsoc);
	free(auth);
		    
	return;
}

/*!
 * Find message in suplied buffer there can be more than one message there
 * SOCK_STREAM can put more than one message in to buffer. Messages are cut
 * with '\0'.
 * @param[in] msg  buffer where recv placed data
 * @param[in] msg_size size of msg buffer
 * @param[out] idx last idx in msg
 * @return pointer to msg buffer where message after idx len starts
 */
static char *
find_msg(char *msg, size_t msg_size, size_t *idx) 
{
	char *msg_p;
	
	DPRINTF(("%s: idx = %zu\n", __func__, *idx));
	if (msg == NULL)
		return NULL;
	
	if (*idx == msg_size)
		return NULL;
		
	/** find_msg was called for the first time set idx to 
	    msg strlen and return msg start */
	if (*idx == 0) {
		*idx = strlen(msg) + 1; /** get length of first message */
		return msg;
	}
	
	msg_p = msg + *idx;

	*idx += strlen(msg + *idx) + 1; 
	
	return msg_p;
}

static int
opensyslog(const char *path)
{
	struct sockaddr_un addr;
	int ret;

	/** Create socket for authenticated logging */
	if ((syssoc = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		err(EXIT_FAILURE, "Error: %s %s %.4d\n",
		 __FILE__, __func__, __LINE__);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	if (strlen(path) >= sizeof(addr.sun_path))
		err(EXIT_FAILURE, "Path to soc si too long %s %s %s %.4d\n",
		 path, __FILE__, __func__, __LINE__);

	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if ((ret = connect(syssoc, (const struct sockaddr *)&addr, SUN_LEN(&addr))) != 0)
		err(EXIT_FAILURE, "Cannot connect to syslog log socket %s %s %s %.4d\n",
		path, __FILE__, __func__, __LINE__);

	return syssoc;
}

/*!
 * Open Authentiticated log socket for logging.
 * @param[in] path Path to unix domain socket.
 * @return opened authenticated socket
 */
static int
openauthlog(const char *path)
{
	struct sockaddr_un addr;
	int soc;
	int ret;

	/** Create socket for authenticated logging */
	if ((soc = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0)
		err(EXIT_FAILURE, "Error: %s %s %.4d\n",
		 __FILE__, __func__, __LINE__);

//	if (setsockopt(soc, SOL_SOCKET, LOCAL_CREDS, &on, sizeof(on)) < 0)
//		err(EXIT_FAILURE, "Cannot set LOCAL_CREDS flag on %s soc\n", path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	if (strlen(path) >= sizeof(addr.sun_path))
		err(EXIT_FAILURE, "Path to soc si too long %s %s %s %.4d\n",
		 path, __FILE__, __func__, __LINE__);

	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if ((ret = bind(soc, (const struct sockaddr *)&addr, SUN_LEN(&addr))) != 0)
		err(EXIT_FAILURE, "Cannot bind to auth log soc %s %s %s %.4d\n",
		 path, __FILE__, __func__, __LINE__);

	if ((listen(soc, 0)) == -1)
		err(EXIT_FAILURE, "Listen Call failed %s %s %s %.4d\n",
		 path, __FILE__, __func__, __LINE__);

	return soc;
}

/*!
 * Convert unpcbid structure to internal auth_msg_t structure with some 
 * additional data fields.
 * @param[in] unp unpcbid structure from getsockopt
 * @return malloced structure from heap caller is responsible for freeing
 * @bug There is small window between calling getsockopt and unptoauth,
 * where application can exit and we can't find it in /proc anymore. We
 * need to find way howto fix this problem. This can be problem on low
 * memory systems where malloc can take some time. Size of this window is
 * getsockopt + malloc until readlink.
 */
static auth_msg_t *
unptoauth(struct unpcbid *unp)
{
	auth_msg_t *auth;
	char path[MAXPATHLEN];
	char proc_path[MAXPATHLEN];
	ssize_t len;
	
	if ((auth = malloc(sizeof(auth_msg_t))) == NULL)
		err(EXIT_FAILURE, "Cannot Allocate memory %s %s %.4d\n",
		 __FILE__, __func__, __LINE__);

	/** This requires proc filesystem mounted in linux compatible option */
	snprintf(path, MAXPATHLEN, "/proc/%d/exe", unp->unp_pid);

	if((len = readlink(path, proc_path, sizeof(proc_path) - 1)) == -1) {
		free(auth);
		return NULL;
	}

	proc_path[len] = '\0';
	strncpy(auth->msg_path, proc_path, len);
	
	printf("Peer eids are gid: %d, eid: %d, pid: %d\n", unp->unp_egid,
	    unp->unp_euid, unp->unp_pid);
	
	auth->msg_euid = unp->unp_euid;
	auth->msg_egid = unp->unp_egid;
	auth->msg_pid = unp->unp_pid;
	
	DPRINTF(("Application path %s\n", proc_path));
	
	return auth;
}

/*!
 * Allocate event structure for later usage.
 */
struct event *
allocev(void)
{
	struct event *ev;

	if ((ev = malloc(sizeof(struct event))) == NULL)
		err(EXIT_FAILURE, "Cannot allocate memory %s\n", __func__);
	
	memset(ev, 0, sizeof(struct event));	
		
	return ev;
}

static void 
usage(void)
{

  printf("Authlogd daemon accept these switches\n");

  exit(EXIT_FAILURE);
}
