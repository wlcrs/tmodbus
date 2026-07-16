#!/bin/bash

docker run --rm -v "$(pwd):/work" -w /work rust:1-trixie cargo build --release
