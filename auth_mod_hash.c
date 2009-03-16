#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

/** Structure describing every application entry */
typedef struct hash_app_entry {
	
	
} hash_app_entry_t;

/** Strucutre storing default settings for hash auth module */
typedef struct mod_hash_conf {

	
	
} mod_hash_conf_t;

/*!
 * Initialize auth_module defaults. This routine is being run from
 * config.c::parse_authmod_sect function.
 *
 * @param double pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_hash_init(void **auth_mod_config)
{

	return 0;
}

/*!
 * Initialize auth hash module aplication entries, this routine will create an entry
 * in a application list and add digital hash of application to it for every application
 * in configuration file. This routine is being run from config.c::parse_app_sect function.
 *
 * @param app_auth_mod configuration dictionary
 * @param pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_hash_conf(prop_dictionary_t conf_dict, void *auth_mod_config)
{

	return 0;
}

/*!
 * Destroy Authentication module config structure.
 */
void
auth_mod_hash_destroy(void **auth_mod_config)
{

	return;
}

/*!
 * Authenticate message message from application described by information from
 * auth_msg_t.
 * @param Structure containig information used for application authentication.
 * @bug I need to findsending application in a application list somehow.
 */
int
auth_mod_hash_auth(auth_msg_t *auth_msg)
{

	return 0;
}
