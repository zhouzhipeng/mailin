#!/bin/sh

set -e

RPM_DIR=$HOME/rpmbuild/RPMS/x86_64/

# Use a checksum file to signal that the deploy is complete.
find "$RPM_DIR" -name '*.rpm' -print0 | \
     xargs -0 -L1 bash -c 'sha256sum "$0" > "$0.sha256sum"'

sftp -P ${SSH_DEPLOY_PORT} -o "StrictHostKeyChecking=no" \
     ${SSH_DEPLOY_USER}@mail.spamtastic.cc:inbox/ << EOF
put -f $RPM_DIR/*.rpm
put -f $RPM_DIR/*.sha256sum
ls -lh
EOF
