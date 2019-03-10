PROG_CXX=bcpid
SRCS=	bcpid.cc debug.cc ../libbcpi/libbcpi.cc ../libbcpi/crc32.c

LDADD= -lelf -lkvm -lpmc -lm -lexecinfo -lprocstat -lpthread -lz

CXXFLAGS += -std=c++11 -DBCPID_DEBUG
MAN = 

.include <bsd.prog.mk>
