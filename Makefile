# $NetBSD$
.include <bsd.own.mk>

USE_FORT?= yes	# network server

PROG=	authlogd
SRCS=	authlogd.c
MKMAN= no
CFLAGS += -g
DPADD+=${LIBUTIL}
LDADD+=-lutil -lcrypto -lprop

.include <bsd.prog.mk>
