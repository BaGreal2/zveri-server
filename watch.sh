#!/bin/bash

find . -type f -name '*.go' ! -path './vendor/*' ! -path './.git/*' | entr go run ./cmd/server
