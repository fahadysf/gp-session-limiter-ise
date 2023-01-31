#!/bin/bash
TS=$(date +%Y%m%d%H%M%S) 

if command -v podman 
then
  DOCKER_CMD="podman"
elif command -v docker
then
  DOCKER_CMD="docker"
else
  echo "Docker or Podman not found. Exiting"
  exit 1
fi

# Build
$DOCKER_CMD build . \
-t fahadysf/gptool:2.7-dev \
-t fahadysf/gptool:2.7-$TS \
-t fahadysf/gptool:2.7-latest \
-t fahadysf/gptool:latest

# Push
$DOCKER_CMD push fahdaysf/gptool:2.7-dev
$DOCKER_CMD push fahadysf/gptool:2.7-$TS
$DOCKER_CMD push fahadysf/gptool:2.7-latest
$DOCKER_CMD push fahadysf/gptool:latest
