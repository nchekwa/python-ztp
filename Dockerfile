FROM python:3.8-alpine

WORKDIR /opt/ztp
RUN mkdir -p /opt/ztp/tftp

COPY requirements.txt ./
COPY ztp.py ./

RUN apk update && apk upgrade
RUN apk add --no-cache --virtual .build-deps gcc musl-dev bash zeromq-dev linux-headers tcpdump
RUN pip3 install --no-cache-dir -r requirements.txt
RUN apk del .build-deps 

RUN apk add tcpdump bash

RUN sed -i 's/    67: StrField/    66: "tftp_server_name",\n    67: StrField/g' /usr/local/lib/python3.8/site-packages/scapy/layers/dhcp.py
RUN sed -i 's/    255: "end"/    150: IPField("tftp_server_address", "0.0.0.0"),\n    255: "end"/g' /usr/local/lib/python3.8/site-packages/scapy/layers/dhcp.py

ENV IFACE="eth1"
ENTRYPOINT "python3" "-u" "/opt/ztp/ztp.py" "-p" "/opt/ztp/tftp" "-i" $IFACE
