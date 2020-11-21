%define srcroot %{getenv:CI_PROJECT_DIR}
%define ver %{getenv:CI_COMMIT_SHORT_SHA}

Summary: Simple SMTP Server
Name: mailin
Version: %ver
Release: 1
License: MIT
URL: http://gitlab.com/alienscience/mailin
Group: System
Packager: Alienscience
BuildRoot: ~/rpmbuild/

%description
A simple SMTP server

%prep
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
mkdir -p $RPM_BUILD_ROOT/etc/systemd/system

cp %srcroot/target/release/mailin-server $RPM_BUILD_ROOT/usr/local/bin/mailin
cp %srcroot/mailin-server/deploy/mailin.service $RPM_BUILD_ROOT/etc/systemd/system/
exit

%files
%attr(0755, root, root) /usr/local/bin/*
%attr(0644, root, root) %config /etc/systemd/system/mailin.service

%pre
# Setup before files are copied
# User
/usr/bin/getent passwd mailin || /usr/sbin/useradd -r -d /home/mailin -s /sbin/nologin mailin
/usr/bin/mkdir -p /home/mailin/logs
/usr/bin/chown mailin:mailin /home/mailin/logs
exit

%post
# Certs
[ -f /etc/mailin/fullchain.pem -a -f /etc/mailin/privkey.pem ] || {
    certbot -n certonly --standalone --preferred-challenges http -d mail.spamtastic.cc
    mkdir -p /etc/mailin
    cp /etc/letsencrypt/live/mail.spamtastic.cc/fullchain.pem /etc/mailin/
    cp /etc/letsencrypt/live/mail.spamtastic.cc/privkey.pem /etc/mailin/
    chgrp mailin /etc/mailin/*.pem
    chmod g+r /etc/mailin/*.pem
}
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl restart mailin
/usr/bin/systemctl enable mailin
exit

%postun
/usr/bin/systemctl stop mailin
/usr/bin/systemctl disable mailin
exit

%clean
rm -rf $RPM_BUILD_ROOT/usr/local/bin
rm -rf $RPM_BUILD_ROOT/etc/systemd/system
exit
