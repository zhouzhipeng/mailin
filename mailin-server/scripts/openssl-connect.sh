#!/bin/sh

openssl s_client -connect localhost:8025 -starttls smtp -crlf
