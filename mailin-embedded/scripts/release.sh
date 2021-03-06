#!/bin/sh

[ $# -eq 1 ] || { cat << EOUSE ; exit 1 ; }
  Usage: $0 [major | minor | patch]

Release mailin-embedded.
EOUSE

cargo release --features 'rtls' --tag-prefix mailin-embedded- --no-dev-version $1
