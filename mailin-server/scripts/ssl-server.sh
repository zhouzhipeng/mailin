#!/bin/sh

cargo run -- \
	--ssl-cert test-certs/cert.pem \
	--ssl-key test-certs/key.pem
