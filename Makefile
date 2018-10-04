PROG_CXX=bcpid
SRCS=	bcpid.cc

LDADD= -lelf -lkvm -lpmc -lm

CXXFLAGS+= -std=c++11

.include <bsd.prog.mk>
