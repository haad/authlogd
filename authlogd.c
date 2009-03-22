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

#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

static int dolog(int, int);
static int openauthlog(const char *);
static int opensyslog(const char *);
static auth_msg_t * unptoauth(struct unpcbid *);
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

int
main(int argc, char **argv)
{
	int ch, soc, syssoc;
	int conf_cert;
	prop_dictionary_t conf_buf;

	syslog_path = SYSLOG_PATH;
	
  	while ((ch = getopt(argc, argv, "P:p:C:c:S:h")) != -1 )
		switch(ch){
			
		case 'h':
			usage();
			/* NOTREACHED */
			break;
		case 'C':
		{
			/* Public key used to verify config file. */
			conf_cert = 1;
			/** @bug Load Cert from file and pass it to config
			   file parsing routines */
		}
		break;
		case 'c':
		{
			DPRINTF(("Internalizing proplib authenticated application file %s\n", (char *)optarg));
			if ((conf_buf = prop_dictionary_internalize_from_file((char *)optarg)) == NULL)
				err(EXIT_FAILURE, "Cannot Internalize config file to buffer\n");
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

	if (!conf_cert)
		return EXIT_FAILURE;

	/** Initialize precompiled authentication modules. */
	auth_mod_init();

	/** Parse configuration file and init auth modules info. */
	parse_config(conf_buf);

	/** Open Syslog socket */
	syssoc = opensyslog(syslog_path);
	
	/** Open authenticated log */
	soc = openauthlog(AUTH_LOG_PATH);

	/** Listen on auth log and process receiveed packets */
	dolog(soc, syssoc);

	
	return EXIT_SUCCESS;
}

/*!
 * Authenticate Logging process after accept and do Logging after it.
 * We will authenticate every application only after calling connect/accept.
 * @param[in] soc socket opened with openauthlog()
 * @see openauthlog()
 */
static int
dolog(int soc, int syssoc)
{
	struct sockaddr_un addr;
	struct unpcbid unp;
	auth_msg_t *auth;
	msg_t *msg;
	int unp_size = sizeof(unp);
	int i, ret, recv_size;
	int nsoc;

	if ((listen(soc, 0)) == -1)
		err(EXIT_FAILURE, "Listen Call failed %s\n.", __func__);

	while(1) {
		
		i = sizeof(struct sockaddr_un);
		/*!
		 * Call accept() to accept connection request. This call will block
		 * until a connection request arrives.
		 */
		if ((nsoc = accept(soc, (struct sockaddr *)&addr, &i)) == -1)
			err(EXIT_FAILURE, "Accept failed %s\n", __func__);
		/** Get information about connected peer */
		if (getsockopt(nsoc, 0, LOCAL_PEEREID, &unp, &unp_size) < 0)
			err(EXIT_FAILURE, "Cannot get LOCAL_PEERID message from soc\n");

		/** convert info to our representation */
		auth = unptoauth(&unp);

		/** Check all configured auth modules */
		ret = auth_mod_loop(auth);

		DPRINTF(("Authentication module framework returned %d\n", ret));

		while (1) {
			if ((msg = malloc(sizeof(msg_t))) == NULL)
				err(EXIT_FAILURE, "Cannot allocate more memory %s.\n", __func__);

			memset(msg, 0, sizeof(msg_t));

			msg->auth_msg = auth;
			
			msg->msg_size = recvfrom(nsoc, msg->msg_buf, sizeof(msg->msg_buf), 0, NULL, NULL);
			if (msg->msg_size == -1)
				err(EXIT_FAILURE, "Recv call failed %s\n.", __func__);

			/** recv_size 0 means EOF from other side. */
			if (msg->msg_size == 0)
				break;

			parse_msg(msg);

			send(syssoc, msg->msg_new, strlen(msg->msg_new), 0);
			
			free(msg);
		}
		close(nsoc);
		free(auth);
	}
		    
	return 0;
}

static int
opensyslog(const char *path)
{
	struct sockaddr_un addr;
	int on = 1;
	int syssoc;
	int ret;

	/** Create socket for authenticated logging */
	if ((syssoc = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0)
		err(EXIT_FAILURE, "%s call failed\n", __func__);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	if (strlen(path) >= sizeof(addr.sun_path))
		err(EXIT_FAILURE, "Path to soc si too long %s\n", path);

	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if ((ret = connect(syssoc, (const struct sockaddr *)&addr, SUN_LEN(&addr))) != 0)
		err(EXIT_FAILURE, "Cannot bind to auth log soc %s\n", path);

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
	int on = 1;
	int soc;
	int ret;

	/** Create socket for authenticated logging */
	if ((soc = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0)
		err(EXIT_FAILURE, "%s call failed\n", __func__);

//	if (setsockopt(soc, SOL_SOCKET, LOCAL_CREDS, &on, sizeof(on)) < 0)
//		err(EXIT_FAILURE, "Cannot set LOCAL_CREDS flag on %s soc\n", path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	if (strlen(path) >= sizeof(addr.sun_path))
		err(EXIT_FAILURE, "Path to soc si too long %s\n", path);

	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if ((ret = bind(soc, (const struct sockaddr *)&addr, SUN_LEN(&addr))) != 0)
		err(EXIT_FAILURE, "Cannot bind to auth log soc %s\n", path);

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
	size_t len;
	
	if ((auth = malloc(sizeof(auth_msg_t))) == NULL)
		err(EXIT_FAILURE, "Cannot Allocate memory %s\n", __func__);

	/** This requires proc filesystem mounted in linux compatible option */
	snprintf(path, MAXPATHLEN, "/proc/%d/exe", unp->unp_pid);

	if((len = readlink(path, proc_path, sizeof(proc_path) - 1)) == -1)
		warn("Cannot read proc link\n");

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

static void 
usage(void)
{

  printf("Authlogd daemon accept these switches\n");

  exit(EXIT_FAILURE);
}
