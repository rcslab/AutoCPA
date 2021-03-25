PROG_CXX=bcpid
SRCS= bcpid.cc debug.cc

LDFLAGS= -L../libbcpi -lbcpi -lelf -lkvm -lpmc -lm -lexecinfo -lprocstat -lpthread -lz

bcpid.full: ../libbcpi/libbcpi.a

MAN=

.include <bsd.prog.mk>
