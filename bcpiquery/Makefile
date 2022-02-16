PROG_CXX=bcpiquery
SRCS= main.cc check.cc dump.cc extract.cc functions.cc programs.cc elfutil.cc util.cc

.include <bsd.opts.mk>

.if ${MK_PIE} == "no"
LIBBCPI=bcpi
.else
LIBBCPI=bcpi_pie
.endif

LDADD= -L../libbcpi -l${LIBBCPI} -lz -ldwarf -lelf

MAN=

.include <bsd.prog.mk>

