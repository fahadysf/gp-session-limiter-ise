#!/bin/bash
TS=$(date +%Y%m%d%H%M%S) 
# Build
docker build . -t fahadysf/gptool:dev -t fahadysf/gptool:$TS -t fahadysf/gptool:latest
# Push
docker push fahdaysf/gptool:2.7-dev
docker push fahadysf/gptool:$TS
docker push fahadysf/gptool:2.7-latest
