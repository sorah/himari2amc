#!/bin/bash -xe

docker build -t himari2amc-bundle -f Dockerfile --load .
docker run --rm himari2amc-bundle cat /var/task/layer.zip > layer.zip
