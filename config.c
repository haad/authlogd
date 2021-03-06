#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

/*
 * Parse configuration file, verify file version and
 * initialize authentication modules.
 */

/* First level key names in config dictionary. */
#define CF_CONFIG "config"
#define CF_SIGN   "sign"

/* Second level key names in config dictionary. */
#define CF_CONF_APP     "app"
#define CF_CONF_AUTHMOD "authmod"
#define CF_CONF_VERSION "conf_version"

#define CF_SIGN_BLOCK   "sign_block"
#define CF_SIGN_CERT    "sign_cert"

/* Third level key names in config dictionary */
#define CF_CONF_AUTH_NAME   "authmod_name"
#define CF_CONF_AUTH_CONFIG "authmod_config"

#define CF_CONF_APP_PATH    "app_path"
#define CF_CONF_APP_DATA    "appmod_config"

/* Fourth Level key names in config dictionary */

#define CF_CONF_APP_DATA_NAME "auth_mod"
#define CF_CONF_APP_DATA_DATA "auth_mod_data"

static int verify_config_sign(prop_dictionary_t, prop_dictionary_t);
static void parse_authmod_sect(prop_array_t);
static void parse_app_sect(prop_array_t);

/*!
 * Parse configuration file given by user, check file and daemon versions
 * and check if signature for externalized config dictionary is same as
 * givenone.
 * @param dict whole configuration file dictionary
 * @see verify_config_sign()
 * @todo Add verify code
 * @bug I have to add certificate to argument list
 */
void
parse_config(prop_dictionary_t dict)
{
	uint32_t version;
	prop_dictionary_t config, sign;
	prop_array_t authmod, app;

	if ((config = prop_dictionary_get(dict, CF_CONFIG)) == NULL)
		err(EXIT_FAILURE, "Config file doesn't have required %s section.\n", CF_CONFIG);
	
	if ((sign = prop_dictionary_get(dict, CF_SIGN)) == NULL)
		err(EXIT_FAILURE, "Config file doesn't have required %s section.\n", CF_SIGN);

	/* Compare Server and Config file versions and continue only if server => file */
	prop_dictionary_get_uint32(config, CF_CONF_VERSION, &version);
	if (version > AUTHLOG_VERSION)
		err(EXIT_FAILURE, "Config file version %d id incompatible "
		    "with authlogd version %d.\n", version, AUTHLOG_VERSION);

	DPRINTF(("Config File version validated continue parsing\n"));

	/* Verify config dictionary signature */
	if (verify_config_sign(config, sign) != 0)
		err(EXIT_FAILURE, "Config Signature doesn't match exiting.\n");

	if ((app = prop_dictionary_get(config, CF_CONF_APP)) == NULL)
		err(EXIT_FAILURE, "Config file doesn't have required %s section.\n", CF_CONF_APP);
	
	if ((authmod = prop_dictionary_get(config, CF_CONF_AUTHMOD)) == NULL)
		err(EXIT_FAILURE, "Config file doesn't have required %s section.\n", CF_CONF_AUTHMOD);

	parse_authmod_sect(authmod);

	parse_app_sect(app);
	
	return;
}


/*!
 * Verify Signature on config block.
 * @bug Add support for signature checking.
 * @bug I have to add certificate to argument list
 */
static int
verify_config_sign(prop_dictionary_t config, prop_dictionary_t sign)
{
	
	const char *signb;
	const char *conf;
	
	conf = prop_dictionary_externalize(config);
	
	prop_dictionary_get_cstring_nocopy(sign, CF_SIGN_BLOCK, &signb);
		
	if ((authlogd_verify_buf(conf, strlen(conf), signb, strlen(signb))) == 0)
		err(EXIT_FAILURE, "Cannot validate config file\n");
	
	DPRINTF(("Config file digital signature validated!!\n"));
	
	return 0;
}

/*!
 * Parse authentication module part of configuration file init
 * default values for every module.
 * @see authmod::init()
 */
static void
parse_authmod_sect(prop_array_t authmod_array)
{
	prop_object_iterator_t iter;
	prop_dictionary_t authmod_dict, authmod_config_dict;
	auth_mod_t *auth_mod;
	const char *name;

	iter = prop_array_iterator(authmod_array);
	
	while((authmod_dict = prop_object_iterator_next(iter)) != NULL){

		prop_dictionary_get_cstring_nocopy(authmod_dict, CF_CONF_AUTH_NAME, &name);

		DPRINTF(("auth module: %s configuration found in config file\n", name));

		if ((auth_mod = auth_mod_search(name)) == NULL)
			warn("Configuration file is wrong I found auth module in it which is not compiled in\n");

		authmod_config_dict = prop_dictionary_get(authmod_dict, CF_CONF_AUTH_CONFIG);

		auth_mod->init(authmod_config_dict, &auth_mod->config);
	}
	
	return;
}

/*!
 * Parse application part of configuration file set application values
 * to possibly different values.
 * @see authmod::conf()
 */
static void
parse_app_sect(prop_array_t app_array)
{
	prop_object_iterator_t iter, app_iter;
	prop_dictionary_t app_dict, auth_dict;
	prop_array_t app_conf_array;
	prop_object_t obj;
	auth_mod_t *auth_mod;
	const char *path;
	const char *name;
	
	iter = prop_array_iterator(app_array);
	
	while((app_dict = prop_object_iterator_next(iter)) != NULL){

		prop_dictionary_get_cstring_nocopy(app_dict, CF_CONF_APP_PATH, &path);

		DPRINTF(("app path: %s configuration found in config file\n", path));

		/* Get dictionary with auth module auth data */
		app_conf_array = prop_dictionary_get(app_dict, CF_CONF_APP_DATA);

		app_iter = prop_array_iterator(app_conf_array);

		while((auth_dict = prop_object_iterator_next(app_iter)) != NULL) {

			prop_dictionary_get_cstring_nocopy(auth_dict, CF_CONF_APP_DATA_NAME, &name);
						
			if ((auth_mod = auth_mod_search(name)) == NULL)
				warn("Configuration file is wrong I found auth module in it which is not compiled in\n");
			
			obj = prop_dictionary_get(auth_dict, CF_CONF_APP_DATA_DATA);
			
			auth_mod->conf(obj, path, auth_mod->config);
		
		}
	}
	return;
}

/*!
 * Dump part of configuration file used for sign.
 * @param dict Configuration dictionary
 * @param path Path where we are going to externalize config section
 */
void
dump_config(prop_dictionary_t dict, const char *path)
{
	prop_dictionary_t config;

	if ((config = prop_dictionary_get(dict, CF_CONFIG)) == NULL)
		err(EXIT_FAILURE, "Config file doesn't have required %s section.\n", CF_CONFIG);

	prop_dictionary_externalize_to_file(config, path);

	return;
}
