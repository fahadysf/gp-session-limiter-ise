#Dockerfile
FROM ubuntu
MAINTAINER Yasser Saied

#Install packages
RUN apt-get update
RUN apt-get install -yqq software-properties-common
RUN apt-get install -yqq iproute2
RUN apt-get install -yqq iputils-ping
RUN apt-get install -yqq python3
RUN apt-get install -yqq python3-pip
RUN apt-get install -yqq net-tools
RUN apt-get install -yqq nano


# Set password and perform cleanup
RUN echo 'root:root' | chpasswd
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#Set Timezone to Dubai GMT+4
ENV TZ=Asia/Dubai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

#Set working Dir to /root
VOLUME [ "/root" ]

COPY *.py ./
RUN chmod +x  *.py
#Install Python Packages
RUN pip3 install -r requirements.txt

ENTRYPOINT ["./main.py"]
