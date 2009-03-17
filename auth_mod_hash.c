#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sha1.h>
#include <sha2.h>

#include "authlogd.h"


/* this struct defines a hash algorithm */
typedef struct hash_t {
	const char *hashname; /* algorithm name */
	char* (*filefunc)(const char *, char *); /* function */
} hash_t;

/* define the possible hash algorithms */
static hash_t hashes[] = {
	{ "SHA1", SHA1File },
	{ "SHA256", SHA256_File },
	{ "SHA384", SHA384_File },
	{ "SHA512", SHA512_File },
	{ NULL, NULL },
};

/** Structure describing every application entry */
typedef struct hash_app_entry {
	
	
} hash_app_entry_t;

/** Strucutre storing default settings for hash auth module */
typedef struct mod_hash_conf {
	hash_t *mod_hash; /* Hash function used as default */
} mod_hash_conf_t;

/* First level entries in hash module configuration dictionary */
#define AUTHMOD_HASH_TYPE "hash_type"

/*!
 * Initialize auth_module defaults. This routine is being run from
 * config.c::parse_authmod_sect function.
 *
 * @param authentication module specific details which are parsed by module it self.
 * @param double pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_hash_init(prop_dictionary_t hash_dict, void **hash_config)
{
	mod_hash_conf_t *conf;
	hash_t *hash;
	const char *hash_type;
	
	DPRINTF(("Auth hash mod init function called.\n"));

	if (!prop_dictionary_get_cstring_nocopy(hash_dict, AUTHMOD_HASH_TYPE, &hash_type)) {
		warn("Hash_type was not found in hash module configuration dict default is %s\n",
		    hashes[0].hashname);
		hash_type = hashes[0].hashname;
	}	    
	if ((conf = malloc(sizeof(mod_hash_conf_t))) == NULL)
	    err(EXIT_FAILURE, "Cannot allocate memmory for hash mod configuration structure\n");

	memset(conf, 0, sizeof(mod_hash_conf_t));

	for (hash = hashes; hash->hashname != NULL; hash++)
		if (strncasecmp(hash_type, hash->hashname, strlen(hash->hashname)) == 0)
			conf->mod_hash = hash;

	*hash_config = conf;
	
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
auth_mod_hash_conf(prop_object_t conf_obj, const char *path, void *auth_mod_config)
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
