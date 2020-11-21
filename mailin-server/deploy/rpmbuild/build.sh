#!/bin/sh

cd ~/rpmbuild/SPECS
ln -f -s ${CI_PROJECT_DIR}/mailin-server/deploy/rpmbuild/mailin.spec
rpmbuild --target x86_64 -bb mailin.spec
