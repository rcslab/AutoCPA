PROG_CXX=bcpiutil
SRCS=	bcpiutil find_an_address.cc ../libbcpi/libbcpi.cc ../libbcpi/crc32.c

LDADD= -lz -ldwarf -lelf

CXXFLAGS += -std=c++11 -DBCPID_DEBUG -Wall
MAN=

.include <bsd.prog.mk>

