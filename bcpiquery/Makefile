PROG_CXX=bcpiquery
SRCS= main.cc check.cc dump.cc extract.cc functions.cc programs.cc elfutil.cc util.cc

LDADD= -L../libbcpi -lz -ldwarf -lelf -lbcpi

bcpiquery: ../libbcpi/libbcpi.a

MAN=

.include <bsd.prog.mk>

