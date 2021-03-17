FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y net-tools iputils-ping telnet ssh tcpdump nmap dsniff 
RUN apt-get install -y curl iperf3 netperf ethtool python-scapy python-pip
RUN apt-get install -y iptables bridge-utils apache2 vim
RUN pip install flask

ADD flask/http_test.py /
COPY entrypoint.sh /entrypoint.sh

RUN echo "secret file" >> secret.txt
RUN echo "plain file" >> plain.txt

RUN mkdir /credentials
RUN echo "password file" >> /credentials/password
RUN echo "token file" >> /credentials/token

RUN mkdir -p /credentials/keys
RUN echo "cert file" >> /credentials/keys/cert.ca
RUN echo "key file" >> /credentials/keys/priv.key

CMD [ "/entrypoint.sh" ]
