PROG_CXX=bcpiquery
SRCS= bcpiquery.cc find_an_address.cc

LDADD= -L../libbcpi -lz -ldwarf -lelf -lbcpi

CXXFLAGS += -std=c++11 -DBCPID_DEBUG -Wall
MAN=

.include <bsd.prog.mk>

