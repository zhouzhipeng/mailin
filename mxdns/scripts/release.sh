#!/bin/sh

[ $# -eq 1 ] || { cat << EOUSE ; exit 1 ; }
  Usage: $0 [major | minor | patch]

Release mxdns.
EOUSE

cargo release --tag-prefix mxdns- --no-dev-version patch
