# $NetBSD$
.include <bsd.own.mk>

USE_FORT?= yes	# network server
WARN = 4

PROG=	authlogd
SRCS=	authlogd.c auth_mod.c auth_mod_hash.c auth_mod_gid.c config.c msg.c
MKMAN= no
CPPFLAGS+= -DAUTHLOGD_DEBUG
CFLAGS += -g
DPADD+=${LIBUTIL}
LDADD+=-lutil -lcrypto -lprop

.include <bsd.prog.mk>
