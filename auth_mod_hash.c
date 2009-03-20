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
	uint16_t digest_len;
} hash_t;

/* define the possible hash algorithms */
static hash_t hashes[] = {
	{ "SHA1", SHA1File, SHA1_DIGEST_STRING_LENGTH },
	{ "SHA256", SHA256_File, SHA256_DIGEST_STRING_LENGTH },
	{ "SHA384", SHA384_File, SHA384_DIGEST_STRING_LENGTH },
	{ "SHA512", SHA512_File, SHA512_DIGEST_STRING_LENGTH },
	{ NULL, NULL },
};

static TAILQ_HEAD(app_head, hash_app_entry) hash_apps_list;

/** Structure describing every application entry */
typedef struct hash_app_entry {
        char  app_path[MAXPATHLEN];
	char *app_hash; /* use longest digest string length here */
	TAILQ_ENTRY(hash_app_entry) next_app;
} hash_app_entry_t;

/** Strucutre storing default settings for hash auth module */
typedef struct mod_hash_conf {
	hash_t *mod_hash; /* Hash function used as default */
} mod_hash_conf_t;

/* First level entries in hash module configuration dictionary */
#define AUTHMOD_HASH_TYPE "hash_type"

/*!
 * Search for application in hash_apps_list. 
 * @param app_path application path.
 */
static hash_app_entry_t *
search_app(const char *app_path) {
	hash_app_entry_t *app;

	app = NULL;
	
	TAILQ_FOREACH(app, &hash_apps_list, next_app) {
		if (strncmp(app->app_path, app_path, strlen(app->app_path)) == 0)
			return app;
	}

	return app;
}

/*!
 * Initialize auth_module defaults. This routine is being run from
 * config.c::parse_authmod_sect function.
 *
 * @param hash_dict authentication module specific details which are parsed by module it self.
 * @param hash_config double pointer to auth_mod_configuration from auth_mod::auth_mod_config.
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

	TAILQ_INIT(&hash_apps_list);
	
	return 0;
}

/*!
 * Initialize auth hash module aplication entries, this routine will create an entry
 * in a application list and add digital hash of application to it for every application
 * in configuration file. This routine is being run from config.c::parse_app_sect function.
 *
 * @param conf_obj app_auth_mod configuration dictionary
 * @param path path to authenticated application
 * @param config pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_hash_conf(prop_object_t conf_obj, const char *path, void *config)
{
	hash_app_entry_t *app;
	mod_hash_conf_t *conf;
	gid_t gid;

	assert(config != NULL);
	
	conf = config;
	
	DPRINTF(("HASH auth module configuration routine called\n"));

	if (prop_object_type(conf_obj) != PROP_TYPE_STRING) {
		warn("Gid module config element for application %s require <integer> tag\n", path);
		return EXIT_FAILURE;
	}

	if ((app = malloc(sizeof(hash_app_entry_t))) == NULL)
		err(EXIT_FAILURE, "Cannot Allocate memory %s\n", __func__);
	
	memset(app, 0, sizeof(hash_app_entry_t));

	app->app_hash = prop_string_cstring(conf_obj);
	strncpy(app->app_path, path, MAXPATHLEN);

	TAILQ_INSERT_HEAD(&hash_apps_list, app, next_app);
	
	return 0;
}

/*!
 * Destroy Authentication module config structure.
 */
void
auth_mod_hash_destroy(void **config)
{
	hash_app_entry_t *app;
	mod_hash_conf_t *conf;

	conf = *config;

	while ((app = TAILQ_FIRST(&hash_apps_list)) != NULL) {
		TAILQ_REMOVE(&hash_apps_list, app, next_app);
		free(app->app_hash);
		free(app);
	}

	free(conf);

	*config = NULL;

	return;
}

/*!
 * Authenticate message message from application described by information from
 * auth_msg_t.
 * @param auth_msg Structure containig information used for application authentication.
 * @bug I need to findsending application in a application list somehow.
 */
int
auth_mod_hash_auth(auth_msg_t *auth_msg, void *config)
{
	hash_app_entry_t *app;
	mod_hash_conf_t *conf;
	char *hash;
	int ret;

	conf = config;
	ret = AUTH_MODULE_DENY;
	
	if ((app = search_app(auth_msg->msg_path)) == NULL)
		ret = AUTH_MODULE_UNKNOW;

	if ((hash = conf->mod_hash->filefunc(auth_msg->msg_path, NULL)) == NULL)
		ret = AUTH_MODULE_UNKNOW;

	if (strncasecmp(app->app_hash, hash, strlen(app->app_hash)) == 0)
		ret = AUTH_MODULE_ALLOW;
	
	return ret;
}
