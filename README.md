ZTP (DHCP/TFTP/HTTP)


```console
./ztp.py -h
usage: ztp.py [-h] [-i INTERFACE] [-l LIMIT] [-p PATH] [--port_tftp PORT_TFTP]
              [--port_http PORT_HTTP] [-d PCAP]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to service requests
  -l LIMIT, --limit LIMIT
                        Limit to hostname or mac
  -p PATH, --path PATH  TFTP folder path. Set `None` to disable TFTP
  --port_tftp PORT_TFTP
                        TFTP port
  --port_http PORT_HTTP
                        HTTP port
  -d PCAP, --pcap PCAP  PCAP file name
```
