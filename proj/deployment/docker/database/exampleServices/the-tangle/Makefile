#!/usr/bin/make -f

SERVICE := the-tangle
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

HOME = $(CURDIR)

.PHONY: build install


install:
	install -d -m 755 $(DESTDIR)$(SERVICEDIR)/data/
	install -d -m 755 $(DESTDIR)$(SERVICEDIR)/data/api/
	git -C $(DESTDIR)$(SERVICEDIR)/data/api/ init --bare --shared
	git -C $(DESTDIR)$(SERVICEDIR)/data/api/ config --add http.receivepack true
	install -m 755 src/hooks/update $(DESTDIR)$(SERVICEDIR)/data/api/hooks/
	install -m 755 src/setup.sh $(DESTDIR)$(SERVICEDIR)

	install -d -m 755                               $(DESTDIR)/etc/systemd/system/fcgiwrap.service.d/
	install -d -m 755                               $(DESTDIR)/etc/systemd/system/fcgiwrap.socket.d/
	install -m 644 systemd/fcgiwrap.service.d/user.conf     $(DESTDIR)/etc/systemd/system/fcgiwrap.service.d/
	install -m 644 systemd/fcgiwrap.service.d/security.conf $(DESTDIR)/etc/systemd/system/fcgiwrap.service.d/
	install -m 644 systemd/fcgiwrap.socket.d/mode.conf $(DESTDIR)/etc/systemd/system/fcgiwrap.socket.d/
	install -m 644 systemd/the-tangle-setup.service $(DESTDIR)/etc/systemd/system/

#	install -d -m 755                               $(DESTDIR)/etc/default
#	install -m 644 src/fcgiwrap $(DESTDIR)/etc/default/

	install -d -m 755                               $(DESTDIR)/etc/nginx/sites-enabled/
	install -m 644 src/the-tangle-nginx.conf        $(DESTDIR)/etc/nginx/sites-enabled/
