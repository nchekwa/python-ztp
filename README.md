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


### Config Yaml file
```yaml
VM0021210000:
  mac: 50:00:21:21:00:00
  hostname: Spine-21
  domain: juniper.lab
  ip: 10.240.40.21
  subnet_mask: 255.255.252.0
  router: 10.240.40.1
  name_server: 8.8.8.8
  lease_time: 60
  tftp_server_name: 10.240.40.254
  boot-file-name: juniper.config
  tftp_server_address: 10.240.40.254
  vendor_specific: 0:junos.tgz,1:VM0021210000/juniper.sh,3:http
```