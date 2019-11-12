#!/bin/ash

set -x

addgroup -S the-tangle
adduser -S the-tangle
(cd .. && mkdir api && cd api && git init --bare )

chown -R the-tangle:the-tangle ..
chmod -R 700 ..
