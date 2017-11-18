TARGETS	= $(OBJDIR)ssl$(SOEXT) $(OBJDIR)ssl4$(SOEXT) $(OBJDIR)ssl6$(SOEXT)
OBJDIR	=
PREFIX	= /usr/local
DESTDIR	=
LIBDIR	= $(PREFIX)/lib
CC	= cc
CPPFLAGSF=
CPPFLAGS=
CFLAGSF	= -W -fPIC `pkg-config --cflags libApp`
CFLAGS	= -Wall -g -O2 -pedantic
LDFLAGSF= `pkg-config --libs libApp`
EXEEXT	=
AR	= ar
ARFLAGS	= -rc
RANLIB	= ranlib
CCSHARED= $(CC) -shared
SOEXT	= .so
RM	= rm -f
LN	= ln -f
MKDIR	= mkdir -m 0755 -p
INSTALL	= install


all: $(TARGETS)

ssl_OBJS = $(OBJDIR)ssl.o
ssl_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
ssl_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)ssl$(SOEXT): $(ssl_OBJS)
	$(CCSHARED) -o $(OBJDIR)ssl$(SOEXT) $(ssl_OBJS) $(ssl_LDFLAGS)

ssl4_OBJS = $(OBJDIR)ssl4.o
ssl4_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
ssl4_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)ssl4$(SOEXT): $(ssl4_OBJS)
	$(CCSHARED) -o $(OBJDIR)ssl4$(SOEXT) $(ssl4_OBJS) $(ssl4_LDFLAGS)

ssl6_OBJS = $(OBJDIR)ssl6.o
ssl6_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
ssl6_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)ssl6$(SOEXT): $(ssl6_OBJS)
	$(CCSHARED) -o $(OBJDIR)ssl6$(SOEXT) $(ssl6_OBJS) $(ssl6_LDFLAGS)

$(OBJDIR)ssl.o: ssl.c common.h common.c
	$(CC) $(ssl_CFLAGS) -o $(OBJDIR)ssl.o -c ssl.c

$(OBJDIR)ssl4.o: ssl4.c ssl.c common.h common.c
	$(CC) $(ssl4_CFLAGS) -o $(OBJDIR)ssl4.o -c ssl4.c

$(OBJDIR)ssl6.o: ssl6.c ssl.c common.h common.c
	$(CC) $(ssl6_CFLAGS) -o $(OBJDIR)ssl6.o -c ssl6.c

clean:
	$(RM) -- $(ssl_OBJS) $(ssl4_OBJS) $(ssl6_OBJS)

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)
	$(MKDIR) $(DESTDIR)$(LIBDIR)/App/transport
	$(INSTALL) -m 0755 $(OBJDIR)ssl$(SOEXT) $(DESTDIR)$(LIBDIR)/App/transport/ssl$(SOEXT)
	$(MKDIR) $(DESTDIR)$(LIBDIR)/App/transport
	$(INSTALL) -m 0755 $(OBJDIR)ssl4$(SOEXT) $(DESTDIR)$(LIBDIR)/App/transport/ssl4$(SOEXT)
	$(MKDIR) $(DESTDIR)$(LIBDIR)/App/transport
	$(INSTALL) -m 0755 $(OBJDIR)ssl6$(SOEXT) $(DESTDIR)$(LIBDIR)/App/transport/ssl6$(SOEXT)

uninstall:
	$(RM) -- $(DESTDIR)$(LIBDIR)/App/transport/ssl$(SOEXT)
	$(RM) -- $(DESTDIR)$(LIBDIR)/App/transport/ssl4$(SOEXT)
	$(RM) -- $(DESTDIR)$(LIBDIR)/App/transport/ssl6$(SOEXT)

.PHONY: all clean distclean install uninstall
