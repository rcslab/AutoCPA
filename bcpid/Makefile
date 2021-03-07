PROG_CXX=bcpid
SRCS= bcpid.cc debug.cc

LDADD= -L../libbcpi -lbcpi -lelf -lkvm -lpmc -lm -lexecinfo -lprocstat -lpthread -lz

CXXFLAGS += -std=c++11 -DBCPID_DEBUG -g -Wall

.ifdef WITH_ASAN
CXXFLAGS += -fsanitize=address
.endif

.ifdef WITH_UBSAN
CXXFLAGS += -fsanitize=undefined
.endif

MAN=

.include <bsd.prog.mk>
