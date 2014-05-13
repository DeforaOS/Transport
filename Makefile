PACKAGE	= Transport
VERSION	= 0.0.0
SUBDIRS	= src/transport
RM	= rm -f
LN	= ln -f
TAR	= tar -czvf


all: subdirs

subdirs:
	@for i in $(SUBDIRS); do (cd "$$i" && $(MAKE)) || exit; done

clean:
	@for i in $(SUBDIRS); do (cd "$$i" && $(MAKE) clean) || exit; done

distclean:
	@for i in $(SUBDIRS); do (cd "$$i" && $(MAKE) distclean) || exit; done

dist:
	$(RM) -r -- $(PACKAGE)-$(VERSION)
	$(LN) -s -- . $(PACKAGE)-$(VERSION)
	@$(TAR) $(PACKAGE)-$(VERSION).tar.gz -- \
		$(PACKAGE)-$(VERSION)/src/transport/ssl.c \
		$(PACKAGE)-$(VERSION)/src/transport/ssl4.c \
		$(PACKAGE)-$(VERSION)/src/transport/ssl6.c \
		$(PACKAGE)-$(VERSION)/src/transport/Makefile \
		$(PACKAGE)-$(VERSION)/src/transport/common.h \
		$(PACKAGE)-$(VERSION)/src/transport/common.c \
		$(PACKAGE)-$(VERSION)/src/transport/project.conf \
		$(PACKAGE)-$(VERSION)/COPYING \
		$(PACKAGE)-$(VERSION)/Makefile \
		$(PACKAGE)-$(VERSION)/project.conf
	$(RM) -- $(PACKAGE)-$(VERSION)

install:
	@for i in $(SUBDIRS); do (cd "$$i" && $(MAKE) install) || exit; done

uninstall:
	@for i in $(SUBDIRS); do (cd "$$i" && $(MAKE) uninstall) || exit; done

.PHONY: all subdirs clean distclean dist install uninstall
