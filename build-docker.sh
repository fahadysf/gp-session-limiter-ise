#!/bin/bash
TS=$(date +%Y%m%d%H%M%S) 
# Build
docker build . -t fahadysf/gptool:2.7-dev -t fahadysf/gptool:2.7-$TS -t fahadysf/gptool:2.7-latest
# Push
docker push fahdaysf/gptool:2.7-dev
docker push fahadysf/gptool:2.7-$TS
docker push fahadysf/gptool:2.7-latest
