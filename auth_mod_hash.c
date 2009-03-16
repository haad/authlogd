#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

typedef struct hash_app_entry {
	
	
} hash_app_entry_t;


typedef struct mod_hash_conf {

	
	
} mod_hash_conf_t;


int
auth_mod_hash_init(void **auth_mod_config)
{

}

int
auth_mod_hash_conf(prop_dictionary_t conf_dict, void *auth_mod_config)
{

}

void
auth_mod_hash_destroy(void **auth_mod_config)
{

}

int
auth_mod_hash_auth(auth_msg_t *auth_msg)
{

}
