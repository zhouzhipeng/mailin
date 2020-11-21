#!/bin/sh

DEPLOY_COMPLETE_FILE=$HOME/rpmbuild/RPMS/commit
RPM_DIR=$HOME/rpmbuild/RPMS/x86_64/

# Use an empty file to signal that the deploy is complete.
touch $DEPLOY_COMPLETE_FILE

sftp -P ${SSH_DEPLOY_PORT} -o "StrictHostKeyChecking=no" \
     ${SSH_DEPLOY_USER}@mail.spamtastic.cc:inbox/ << EOF
put -f $RPM_DIR/*.rpm
put -f $DEPLOY_COMPLETE_FILE
ls -lh
EOF
