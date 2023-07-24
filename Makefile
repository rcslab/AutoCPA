SUBDIR = libbcpi bcpid bcpiquery

.ifdef WITH_DEBUG
CXXFLAGS = -Og -DBCPID_DEBUG
.else
CXXFLAGS = -O3
.endif

CXXFLAGS += -g -std=c++20 -Wall -Wextra -Werror -Wno-missing-field-initializers

.dinclude "Makefile.local"


.ifdef WITH_ASAN
CXXFLAGS += -fsanitize=address
.endif

.ifdef WITH_UBSAN
CXXFLAGS += -fsanitize=undefined
.endif

.export CXXFLAGS

.include <bsd.subdir.mk>

