#!/bin/bash

docker run --rm -v "$(pwd)":/work  -w /work golang:1.22 go build -o client client.go
docker run --rm -v "$(pwd)":/work  -w /work golang:1.22 go build -o server server.go
