#!/bin/ash

if [ ! -f key.pem ]; then
	openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:4096
	openssl rsa -in key.pem -pubout > key.pub
	git clone ../api /tmp/tangle-api
	cp key.pub /tmp/tangle-api/

	old_cwd="$(pwd)"
	cd /tmp/tangle-api
	git add key.pub
	git config user.email "the-tangle@the-tangle"
	git config user.name "the-tangle"
	git commit -m 'genesis commit'
	git push
	cd "$old_cwd"
	rm -rf /tmp/tangle-api
fi

spawn-fcgi -s /run/the-tangle-fcgi.sock -F 10 $(which fcgiwrap) && nginx -c "$(pwd)/nginx.conf" -g "daemon off;"
