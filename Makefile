PROG_CXX=bcpid
SRCS=	bcpid.cc debug.cc

LDADD= -lelf -lkvm -lpmc -lm -lexecinfo -lprocstat -lpthread

CFLAGS += -std=c++11 -DBCPID_DEBUG

.include <bsd.prog.mk>
