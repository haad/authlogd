#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authlogd.h"

static SLIST_HEAD(auth_mods, auth_mod) auth_mod_list;

static auth_mod_t * auth_mod_alloc(void);

static auth_mod_t *
auth_mod_alloc(void)
{
	auth_mod_t *mod;

	if ((mod = malloc(sizeof(auth_mod_t))) == NULL)
		err(EXIT_FAILURE, "auth_mod_alloc failed.\n"); 
	
	memset(mod, 0, sizeof(auth_mod_t));

	return mod;
}

static void
auth_mod_add(auth_mod_t *auth_mod)
{

	SLIST_INSERT_HEAD(&auth_mod_list, auth_mod, next_mod);
}

static void
auth_mod_dumplist(void)
{
	auth_mod_t *mod;
	int i;

	i = 1;
	
	DPRINTF(("Dumping auth_mod list entries\n"));
	SLIST_FOREACH(mod, &auth_mod_list, next_mod) {
		DPRINTF(("%d. Module name: %s\n", i, mod->name));
		i++;
	}
	return;
}

int
auth_mod_check(char *auth_mod_name)
{
	auth_mod_t *mod;

	SLIST_FOREACH(mod, &auth_mod_list, next_mod)
		if ((strncmp(mod->name, auth_mod_name, MAX_NAME_LEN)) == 0)
			return 0;
	
	
	return 1;
}

void
auth_mod_init(void)
{
	auth_mod_t *mod1, *mod2;

	SLIST_INIT(&auth_mod_list);
		
	mod1 = auth_mod_alloc();
	strncpy(mod1->name, "auth_hash", MAX_NAME_LEN);
	mod1->init = &auth_mod_hash_init;
	mod1->conf = &auth_mod_hash_conf;
	mod1->destroy = &auth_mod_hash_destroy;
	mod1->auth = &auth_mod_hash_auth;
	auth_mod_add(mod1);
	
	mod2 = auth_mod_alloc();
	strncpy(mod2->name, "auth_gid", MAX_NAME_LEN);
	mod2->init = &auth_mod_gid_init;
	mod2->conf = &auth_mod_gid_conf;
	mod2->destroy = &auth_mod_gid_destroy;
	mod2->auth = &auth_mod_gid_auth;
	auth_mod_add(mod2);

	auth_mod_dumplist();
}
