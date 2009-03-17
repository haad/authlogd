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
typedef struct gid_app_entry {
	
	
} gid_app_entry_t;

/** Strucutre storing default settings for gid auth module */
typedef struct mod_gid_conf {
	gid_t default_gid;
} mod_gid_conf_t;

/* First level entries in hash module configuration dictionary */
#define AUTHMOD_GID_ID "group_id"

#define DEFAULT_GROUP_ID 0

/*!
 * Initialize auth_module defaults. This routine is being run from
 * config.c::parse_authmod_sect function.
 * 
 * @param authentication module specific details which are parsed by module it self.
 * @param double pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_gid_init(prop_dictionary_t gid_dict, void **auth_mod_config)
{
	mod_gid_conf_t *conf;
	gid_t gid;
	
	DPRINTF(("Auth gid mod init function called.\n"));

	if (!prop_dictionary_get_uint32(gid_dict, AUTHMOD_GID_ID, (uint32_t *)&gid)) {
		warn("Default group id was not found in gid module configuration dict default is %d\n",
		    DEFAULT_GROUP_ID);
		gid = DEFAULT_GROUP_ID;
	}
	if ((conf = malloc(sizeof(mod_gid_conf_t))) == NULL)
	    err(EXIT_FAILURE, "Cannot allocate memmory for hash mod configuration structure\n");

	memset(conf, 0, sizeof(mod_gid_conf_t));

	conf->default_gid = gid;

	*auth_mod_config = conf;

	return 0;
}

/*!
 * Initialize auth gid module aplication entries, this routine will create an entry
 * in a application list for every application in configuration file. And add default
 * or defined gid to it.
 * This routine is being run from config.c::parse_app_sect function.
 *
 * @param app_auth_mod configuration dictionary
 * @param pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_gid_conf(prop_object_t conf_obj, void *auth_mod_config)
{

}

/*!
 * Destroy Authentication module config structure.
 */
void
auth_mod_gid_destroy(void **auth_mod_config)
{

}

/*!
 * Authenticate message message from application described by information from
 * auth_msg_t.
 * @param Structure containig information used for application authentication.
 * @bug I need to findsending application in a application list somehow.
 */
int
auth_mod_gid_auth(auth_msg_t *auth_msg)
{

}
