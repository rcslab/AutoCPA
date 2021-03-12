PROG_CXX=bcpiquery
SRCS= main.cc check.cc extract.cc util.cc find_an_address.cc

LDADD= -L../libbcpi -lz -ldwarf -lelf -lbcpi

CXXFLAGS += -std=c++20 -DBCPID_DEBUG -g -Wall

.ifdef WITH_ASAN
CXXFLAGS += -fsanitize=address
.endif

.ifdef WITH_UBSAN
CXXFLAGS += -fsanitize=undefined
.endif

MAN=

.include <bsd.prog.mk>

