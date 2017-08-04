CC=gcc
INST=install
NAME=dnshook
RM=rm
ARGS=-DEASY_REMOTE
MD=mkdir -p
PKG=arch-armhf
DEB=fakeroot dpkg-deb --build
CHKDEB=lintian

.PHONY: install-base deb clean lintian

$(PKG)/usr/sbin/dnshook: src/dnshook.c
	$(CC) $(ARGS) -o $@ $^

install-base: pkg/usr/sbin/$(NAME)
	$(INST) $(PKG)/etc/network/if-up.d/$(NAME) /etc/network/if-up.d/$(NAME) && \
	$(INST) $(PKG)/etc/network/if-down.d/$(NAME) /etc/network/if-down.d/$(NAME) && \
	$(INST) $(PKG)/etc/init.d/$(NAME) /etc/init.d/$(NAME) && \
	$(INST) $(PKG)/usr/sbin/$(NAME) /usr/sbin/$(NAME)

install-debian: install-base
	update-rc.d $(NAME) defaults

install-redhat: install-base
	chkconfig --add $(NAME) && \
	chkconfig $(NAME) on

deb: $(PKG).deb

$(PKG).deb: $(PKG)/usr/sbin/$(EXEC)
	$(MD) $(PKG)/usr/sbin/ && \
	$(DEB) $(PKG)

lintian: $(PKG).deb
	$(CHKDEB) $(PKG).deb || :

clean:
	$(RM) $(PKG)/usr/sbin/dnshook

