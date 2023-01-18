#!/bin/bash
TS=$(date +%Y%m%d%H%M%S) 
# Build
docker build . -t fahadysf/gptool:dev -t fahadysf/gptool:$TS -t fahadysf/gptool:latest
# Push
docker push fahdaysf/gptool:dev
docker push fahadysf/gptool:latest
docker push fahadysf/gptool:$TS
