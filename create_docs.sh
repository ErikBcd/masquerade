#!/bin/sh

cargo doc --document-private-items --no-deps
rm -rf ./doc
cp -r target/doc/ ./doc/