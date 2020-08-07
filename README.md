# Zero touch provisioning (ZTP) (include DHCP/TFTP/HTTP)<br>
Simple Python3 script which based on predefined YAML file can offer DHCP/IP for device.<br>
Script has built-in TFTP/HTTP servers, so host would be also able to download config/firmware which will be pointed as dhcp options..<br>

## Syntax:
```console
[root@server ztp]# ./ztp.py -h
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
  
[root@server ztp]# pmap 3068 | grep total
 total           410900K
```

## Example:
![Screenshot](doc/img/example_1.png)
