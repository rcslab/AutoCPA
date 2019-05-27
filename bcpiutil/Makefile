PROG_CXX=bcpiutil
SRCS=	bcpiutil find_an_address.cpp ../libbcpi/libbcpi.cc ../libbcpi/crc32.c

LDADD= -lz -ldwarf -lelf

CXXFLAGS += -std=c++11 -DBCPID_DEBUG
MAN=

.include <bsd.prog.mk>

