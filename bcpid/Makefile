PROG_CXX=bcpid
SRCS= bcpid.cc debug.cc

.include <bsd.opts.mk>

.if ${MK_PIE} == "no"
LIBBCPI=bcpi
.else
LIBBCPI=bcpi_pie
.endif

LDADD=-L../libbcpi -l${LIBBCPI} -lelf -lkvm -lpmc -lm -lexecinfo -lprocstat -lpthread -lz

MAN=

.include <bsd.prog.mk>
