# $NetBSD$
.include <bsd.own.mk>

USE_FORT?= yes	# network server
WARNS = 4

PROG=	authlogd
SRCS=	authlogd.c auth_mod.c auth_mod_hash.c auth_mod_gid.c config.c msg.c ssl.c
MAN=    authlogd.8 authlogd.xml.5

CPPFLAGS+= -DAUTHLOGD_DEBUG
CFLAGS += -g
DPADD+=${LIBUTIL}
LDADD+=-lutil -lprop -levent

LDADD+=-lssl -lcrypto

.include <bsd.prog.mk>
