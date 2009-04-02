# $NetBSD$
.include <bsd.own.mk>

USE_FORT?= yes	# network server
WARN = 4
CC=/usr/bin/pcc
PROG=	authlogd
SRCS=	authlogd.c auth_mod.c auth_mod_hash.c auth_mod_gid.c config.c msg.c ssl.c
MKMAN= no
CPPFLAGS+= -DAUTHLOGD_DEBUG
CFLAGS += -g
DPADD+=${LIBUTIL}
LDADD+=-lutil -lprop

LDADD+=-lssl -lcrypto

.include <bsd.prog.mk>
