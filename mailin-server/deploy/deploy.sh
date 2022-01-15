#!/bin/sh
set -e

mkdir -p tmp-deploy
cp mailin-server/deploy/install tmp-deploy/
cp mailin-server/deploy/mailin.service tmp-deploy/
cp target/release/mailin-server tmp-deploy/mailin
cd tmp-deploy
tar --zstd -cf mailin.tar.zst \
     install mailin mailin.service

# Use a checksum file to signal that the deploy is complete.
sha256sum "mailin.tar.zst" > "mailin.tar.zst.sha256sum"

sftp -P "${SSH_DEPLOY_PORT}" -o "StrictHostKeyChecking=no" \
     "${SSH_DEPLOY_USER}"@mail.spamtastic.cc:inbox/ << EOF
put -f *.tar.zst
put -f *.sha256sum
ls -lh
EOF
