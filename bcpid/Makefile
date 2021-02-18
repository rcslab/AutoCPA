PROG_CXX=bcpid
SRCS= bcpid.cc debug.cc

LDADD= -L../libbcpi -lbcpi -lelf -lkvm -lpmc -lm -lexecinfo -lprocstat -lpthread -lz

CXXFLAGS += -std=c++11 -DBCPID_DEBUG -g -Wall
MAN= 

.include <bsd.prog.mk>
