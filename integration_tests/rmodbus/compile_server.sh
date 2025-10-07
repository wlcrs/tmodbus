#!/bin/bash

docker run -v $(pwd):/work -w /work rust:1-trixie cargo build --release
