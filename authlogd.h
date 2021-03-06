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
#ifndef _AUTHLOGD_H_
#define _AUTHLOGD_H_

#include <sys/queue.h>

#include <assert.h>

#include <prop/proplib.h>

#ifdef AUTHLOGD_DEBUG
#define DPRINTF(arg) printf arg
#else
#define DPRINTF(arg)
#define NDEBUG
#endif

#ifdef AUTHLOGD_DEBUG
#define DUMP_DICT(dict, buf) do {				\
		buf = prop_dictionary_externalize(dict);	\
		printf("%s\n", buf);				\
		free(buf);					\
	} while(/*CONSTCOND*/0)
#define DUMP_ARRAY(array, buf) do {				\
		buf = prop_array_externalize(array);		\
		printf("%s\n", buf);				\
		free(buf);					\
	} while(/*CONSTCOND*/0)
#endif

#define SYSLOG_PATH "/var/run/log"

#define AUTH_LOG_PATH "/var/run/authlog"
#define AUTHLOG_VERSION 1

#define AUTHLOG_MESSAGE_LEN 4096

#define AUTHLOG_AUTH_SD 512

typedef struct auth_msg {
	char    msg_path[MAXPATHLEN]; /** Path to application */
	uid_t   msg_euid;             /** Effective user id */
	gid_t   msg_egid;             /** Effective group id */
	pid_t   msg_pid;              /** Process id */
} auth_msg_t;

typedef struct msg {
	ssize_t msg_size;
	char msg_buf[AUTHLOG_MESSAGE_LEN];
	char msg_new[AUTHLOG_MESSAGE_LEN];
	char msg_auth_sd[AUTHLOG_AUTH_SD];
	char *msg_header;
	char *msg_body;
	int  msg_auth_status;      /** Status of message after auth process */
	auth_msg_t *auth_msg;
} msg_t;

#define AUTH_MODULE_DENY 	0
#define AUTH_MODULE_ALLOW 	1
#define AUTH_MODULE_UNKNOWN 	2

#define MAX_NAME_LEN 32
/* Structure defining authentication module */
typedef struct auth_mod {
	char name[MAX_NAME_LEN];
	/** Initialize auth_mod defaults from dictionary */
  	int (*init)(prop_dictionary_t, void **);
	/** Configure application details for auth_mod */
	int (*conf)(prop_object_t, const char *, void *);
	/** Remove auth module configuration structure and destroy application list */
	void (*destroy)(void **);
	/** Authorize application for loggind */
	int (*auth)(auth_msg_t *, void *);
	/** Module config */
	void *config;
	SLIST_ENTRY(auth_mod) next_mod;
} auth_mod_t;

/* auth_mod.c */
void auth_mod_init(void);
auth_mod_t*  auth_mod_search(const char *);
int auth_mod_loop(auth_msg_t *);

/* auth_mod_hash.c */
int auth_mod_hash_init(prop_dictionary_t, void **);
int auth_mod_hash_conf(prop_object_t, const char *, void *);
void auth_mod_hash_destroy(void **);
int auth_mod_hash_auth(auth_msg_t *, void *);

/* auth_mod_gid.c */
int auth_mod_gid_init(prop_dictionary_t, void **);
int auth_mod_gid_conf(prop_object_t, const char *, void *);
void auth_mod_gid_destroy(void **);
int auth_mod_gid_auth(auth_msg_t *, void *);

/* config.c */
void parse_config(prop_dictionary_t);
void dump_config(prop_dictionary_t, const char *);

/* msg.c */
void parse_msg(msg_t *);

/* ssl.c */
void authlogd_ssl_init(void);
void authlogd_sign_init(void);
void authlogd_verify_init(void);
char * authlogd_sign_buf(const char *, size_t);
int authlogd_verify_buf(const char *, size_t, const char *, size_t);

#endif
