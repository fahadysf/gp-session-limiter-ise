#Dockerfile
FROM python:3.10-slim
MAINTAINER Fahad Yousuf <fyousuf@paloaltonetworks.com>

#Install packages (Network Tools)
RUN apt-get update && apt-get install -yqq git

# Set password and perform cleanup
RUN echo 'root:root' | chpasswd
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#Set Timezone to Dubai GMT+4
ENV TZ=Asia/Dubai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir /app

# Volume definitions
VOLUME [ "/app/data" ]

#Set working Dir to /app
WORKDIR /app

# Copy files to /app
COPY *.py *.txt *.md *.sample /app/
RUN echo "#!/bin/bash \npython3 config.py" > /usr/bin/config && chmod +x /usr/bin/config

#Install Python Packages
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

CMD [ "/usr/local/bin/uvicorn", "apiserver:app", "--host", "0.0.0.0", "--port", "8000"]