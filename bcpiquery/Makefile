PROG_CXX=bcpiquery
SRCS= main.cc check.cc dump.cc extract.cc functions.cc programs.cc elfutil.cc util.cc

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

