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
	char app_path[MAXPATHLEN];
	gid_t app_gid;
	TAILQ_ENTRY(gid_app_entry) next_app;
} gid_app_entry_t;

static TAILQ_HEAD(gid_head, gid_app_entry) gid_apps_list;

/** Strucutre storing default settings for gid auth module */
typedef struct mod_gid_conf {
	gid_t default_gid;
} mod_gid_conf_t;

/* First level entries in hash module configuration dictionary */
#define AUTHMOD_GID_ID "group_id"

#define DEFAULT_GROUP_ID 0

/*!
 * Search for application in gid_apps_list. 
 * @param app_path application path.
 */
static gid_app_entry_t *
search_app(const char *app_path)
{
	gid_app_entry_t *app;

	app = NULL;
	
	TAILQ_FOREACH(app, &gid_apps_list, next_app) {
		if (strncmp(app->app_path, app_path, strlen(app->app_path)) == 0)
			return app;
	}

	return app;
}

/*!
 * Initialize auth_module defaults. This routine is being run from
 * config.c::parse_authmod_sect function.
 * 
 * @param gid_dict authentication module specific details which are parsed by module it self.
 * @param auth_mod_config double pointer to auth_mod_configuration from auth_mod::auth_mod_config.
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
	    err(EXIT_FAILURE, "Cannot allocate memmory for gid mod configuration structure\n");

	memset(conf, 0, sizeof(mod_gid_conf_t));

	conf->default_gid = gid;

	*auth_mod_config = conf;

	TAILQ_INIT(&gid_apps_list);
	
	return 0;
}

/*!
 * Initialize auth gid module aplication entries, this routine will create an entry
 * in a application list for every application in configuration file. And add default
 * or defined gid to it.
 * This routine is being run from config.c::parse_app_sect function.
 *
 * @param conf_obj app_auth_mod configuration dictionary
 * @param path path to authenticated application
 * @param config pointer to auth_mod_configuration from auth_mod::auth_mod_config.
 */
int
auth_mod_gid_conf(prop_object_t conf_obj, const char *path, void *config)
{
	gid_app_entry_t *app;
	mod_gid_conf_t *conf;
	gid_t gid;

	assert(config != NULL);
	
	conf = config;
	
	DPRINTF(("GID auth module configuration routine called\n"));

	if (prop_object_type(conf_obj) != PROP_TYPE_NUMBER) {
		warn("Gid module config element for application %s require <integer> tag\n", path);
		DPRINTF(("Using default value %d\n", conf->default_gid));
		gid = conf->default_gid;
	}

	gid = prop_number_integer_value(conf_obj);
	
	if ((app = malloc(sizeof(gid_app_entry_t))) == NULL)
		err(EXIT_FAILURE, "Cannot Allocate memory %s\n", __func__);
	
	memset(app, 0, sizeof(gid_app_entry_t));

	app->app_gid = gid;

	strncpy(app->app_path, path, MAXPATHLEN);

	TAILQ_INSERT_HEAD(&gid_apps_list, app, next_app);
	
	return 0;
}

/*!
 * Destroy Authentication module config structure.
 * This functions should be called from sighup signall handler.
 * @param config double pointer to configuration structure
 */
void
auth_mod_gid_destroy(void **config)
{
	gid_app_entry_t *app;
	mod_gid_conf_t *conf;

	conf = *config;

	while ((app = TAILQ_FIRST(&gid_apps_list)) != NULL) {
		TAILQ_REMOVE(&gid_apps_list, app, next_app);
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
auth_mod_gid_auth(auth_msg_t *auth_msg, void *config)
{
	gid_app_entry_t *app;
	mod_gid_conf_t *conf;
	int ret;
	
	conf = config;
	ret = AUTH_MODULE_DENY;
	
	if ((app = search_app(auth_msg->msg_path)) == NULL)
		return AUTH_MODULE_UNKNOW;

	if (auth_msg->msg_egid == app->app_gid)
		ret = AUTH_MODULE_ALLOW;

	return ret;
}
