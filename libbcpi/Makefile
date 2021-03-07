LIB= bcpi
SRCS= crc32.c libbcpi.cc

LDADD= -lelf -lz

CFLAGS += -DBCPID_DEBUG -g -Wall
CXXFLAGS += -std=c++11 -DBCPID_DEBUG -g -Wall

.ifdef WITH_ASAN
CFLAGS += -fsanitize=address
CXXFLAGS += -fsanitize=address
.endif

.ifdef WITH_UBSAN
CFLAGS += -fsanitize=undefined
CXXFLAGS += -fsanitize=undefined
.endif

MAN =

.include <bsd.lib.mk>
