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

static int verify_config_sign(prop_dictionary_t, prop_dictionary_t);
static void parse_authmod_sect(prop_array_t);
static void parse_app_sect(prop_array_t);

/*!
 * Parse configuration file given by user, check file and daemon versions
 * and check if signature for externalized config dictionary is same as
 * givenone.
 * @param whole configuration file dictionary
 * @see verify_config_sign()
 * @todo Add verify code
 * @fixme I have to add certificate to argument list
 */
int
parse_config(prop_dictionary_t dict)
{
	uint32_t version;
	prop_dictionary_t config, sign;
	prop_array_t authmod, app;
	char *buf;

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
	
	return 0;
}


/*!
 * Verify Signature on config block.
 * @fixme Add support for signature checking.
 * @fixme I have to add certificate to argument list
 */
static int
verify_config_sign(prop_dictionary_t config, prop_dictionary_t sign)
{

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

	return;
}
