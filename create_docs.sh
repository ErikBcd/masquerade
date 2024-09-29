#!/bin/sh

cargo doc --document-private-items --no-deps
rm -rf ./doc/rust_docs/
cp -r target/doc/ ./doc/rust_docs/
