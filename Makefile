SUBDIR = libbcpi bcpid bcpiquery

CXXFLAGS=-std=c++20 -Wall

.dinclude "Makefile.local"

.ifdef WITH_DEBUG
CXXFLAGS += -O0 -DBCPID_DEBUG -g
.endif

.ifdef WITH_ASAN
CXXFLAGS += -fsanitize=address
.endif

.ifdef WITH_UBSAN
CXXFLAGS += -fsanitize=undefined
.endif

.export CXXFLAGS

.include <bsd.subdir.mk>

