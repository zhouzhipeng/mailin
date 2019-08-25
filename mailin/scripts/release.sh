#!/bin/sh

[ $# -eq 1 ] || { cat << EOUSE ; exit 1 ; }
  Usage: $0 [major | minor | patch]

Release mailin.
EOUSE

cargo release --dry-run --tag-prefix mailin- --no-dev-version patch
