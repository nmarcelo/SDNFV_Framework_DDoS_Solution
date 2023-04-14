FROM ubuntu:latest
COPY ./public-html/ /var/www/html/index.html



# Install dependencies required for Containernet.
RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    iproute2 \
    build-essential \
    htop \
    apache2 \
    wget\
    systemctl\
    iperf

RUN service apache2 start

