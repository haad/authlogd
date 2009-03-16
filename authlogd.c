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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

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


int
main(int argc, char **argv)
{
	int ch;
	int conf_cert;
	prop_dictionary_t conf_buf;
	
  	while ((ch = getopt(argc, argv, "P:p:C:c:h")) != -1 )
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

	return EXIT_SUCCESS;
}

static void 
usage(void)
{

  printf("Authlogd daemon accept these switches\n");

  exit(EXIT_FAILURE);
}
