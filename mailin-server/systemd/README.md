
# Systemd Socket Activation

This directory contains the files needed to enable socket activation on Linux systems that run systemd.

Edit these files as needed and copy to `/etc/systemd/system/` and run:
```
systemctl daemon-reload
systemctl start mailin.socket
systemctl enable mailin.socket
```

## mailin.socket

This contains the Unit file that configures systemd to listen on port 25.

## mailin.service

This file will need to be edited. At the moment the paths in this file are setup to work with Gitlab continious deployment.

