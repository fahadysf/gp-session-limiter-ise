#!/bin/bash

DEBUG="False"
CONFIG_FILE="/opt/gptool/config.yaml"
DATA_FOLDER="/opt/gptool/data"
LOG_FOLDER="/opt/gptool/logs"

docker run -itd --rm --name gptool \
	-e "DEBUG=$DEBUG" \
	-v $CONFIG_FILE:/app/config.yaml \
	-v $DATA_FOLDER:/app/data \
	-v $LOG_FOLDER:/app/logs \
	-p 8000:8000 \
	fahadysf/gptool:2.7-latest
