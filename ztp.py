#!/usr/bin/env python3
##########################################################
# ZTP (DHCP+TFTP+HTTP service)
# Created by: Zdolinski Artur
# Version: 0.6a [20200927]
#
# if you need - you can disable cache (__pycache__)
# > bash# export PYTHONDONTWRITEBYTECODE=1
#
# Enable/Disable Verbose Developing Debug
# > bash# export DEBUG=1
# > bash# unset DEBUG
##########################################################
"""
First install all necessary libs
bash# pip3 install -r requirements.txt
"""
from __future__ import print_function
from scapy.all import *
from scapy.utils import PcapWriter
import os, errno
from signal import signal, SIGINT
import netifaces
import argparse
import tftpy
import copy
import yaml
import http.server
import socketserver
import threading
from termcolor import colored
from pprint import pprint 

os.environ['PYTHONUNBUFFERED'] = '1'
conf.sniff_promisc=True


# handle_dhcp_packet(packet)
# get_option(dhcp_options, key)
# threaded(fn)
# handler(signal_received, frame)
# chaddr_to_mac(chaddr)
# op43(text_value)

def handle_dhcp_packet(packet):
    if DHCP in packet:
        # Write PCAP File if needed
        if kwargs['pcap'] != "False":
            pktdump.write(packet)
        
        # Dev Debug if needed
        if os.environ.get("DEBUG") is not None:
            print(packet.summary())
            print(ls(packet))
        
        # Get base information about packet
        DHCP_message_type = get_option(packet[DHCP].options, 'message-type')
        hostname = str(get_option(packet[DHCP].options, 'hostname'))
        xid = packet[BOOTP].xid
        chaddr = packet[BOOTP].chaddr
        src_mac = packet[Ether].src
        dhcp_src_mac = chaddr_to_mac(chaddr)

        # Direction
        if packet[Ether].src == kwargs['my_mac']:
            direction = colored(kwargs['interface']+"| ->[Snd]", 'green')
        else:
            direction = colored(kwargs['interface']+"|<- [Rcv]", 'green')

        # Match DHCP Message Type = Discovery (1)
        if DHCP_message_type == 1:
            print(direction + colored('[Discover]['+str(hex(xid))+'] ', 'blue') + "Host "+hostname+ " ("+dhcp_src_mac+ ") asked for an IP")
            
            # Read configuration as we going to answer
            dhcp = DhcpResponder()
            config = dhcp.get_parameters(kwargs['path'])

            if config.get(hostname) is not None:
                dhcp.send_offer(packet, config[hostname])
            elif config.get("MAC-"+dhcp_src_mac.replace(".","").replace("-","").replace(":","")) is not None:
                dhcp.send_offer(packet, config["MAC-"+dhcp_src_mac.replace(".","").replace("-","").replace(":","")])

        # Match DHCP Message Type = Replay (2)
        elif DHCP_message_type == 2:
            #subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
            lease_time = get_option(packet[DHCP].options, 'lease_time')
            router = get_option(packet[DHCP].options, 'router')
            name_server = get_option(packet[DHCP].options, 'name_server')
            domain = get_option(packet[DHCP].options, 'domain')
            print(direction+colored('[Offer]['+str(hex(xid))+'] ', 'yellow') + "DHCP Server "+packet[IP].src+" ("+src_mac+") offered "+packet[BOOTP].yiaddr+" ("+dhcp_src_mac+")")
            
        # Match DHCP Message Type = Request (3)
        elif DHCP_message_type == 3:
            requested_addr = get_option(packet[DHCP].options, 'requested_addr')
            print(direction+colored('[Request]['+str(hex(xid))+'] ', 'magenta') + "Host "+ str(hostname) +" ("+dhcp_src_mac+") requested " + str(requested_addr))

            # Read configuration as we going to answer
            dhcp = DhcpResponder()
            config = dhcp.get_parameters(kwargs['path'])

            if config.get(hostname) is not None:
                dhcp.send_ack(packet, config[hostname])
            elif config.get("MAC-"+dhcp_src_mac.replace(".","").replace("-","").replace(":","")) is not None:
                dhcp.send_ack(packet, config["MAC-"+dhcp_src_mac.replace(".","").replace("-","").replace(":","")])
        
        # Match DHCP Message Type = Decline (4)
        elif DHCP_message_type == 4:
            print(direction + colored('[Decline]['+str(hex(xid))+'] ', 'red') + "Host ("+dhcp_src_mac+") declined the offer")
            
        # Match DHCP Message Type = Ack (5)
        elif DHCP_message_type == 5:
            print(direction + colored('[Ack]['+str(hex(xid))+'] ', 'yellow') + "DHCP Server "+packet[IP].src+" ("+src_mac+") acked "+packet[BOOTP].yiaddr)

        # Match DHCP Message Type = Release (7)
        elif DHCP_message_type == 7:
            print(direction + colored('[Release]['+str(hex(xid))+'] ', 'red') +'DHCP Release from ('+dhcp_src_mac+') - IP: ' + str(packet[BOOTP].ciaddr) )

        # Match DHCP Message Type = Inform (8)
        elif DHCP_message_type == 8:
            vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')
            print(direction + colored('[Inform]['+str(hex(xid))+'] ', 'blue') + "Packet from "+packet[IP].src+" ("+src_mac+") hostname: "+str(hostname)+", vendor_class_id: "+str(vendor_class_id) )

        else:
            print(direction + colored('[Unknown]['+str(hex(xid))+'] ', 'red') +'Some Other DHCP Packet - DHCP Message Type = ' + str(DHCP_message_type))

        return

# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass

def threaded(fn):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.setDaemon(True)
        thread.start()
        return thread
    return wrapper

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    if kwargs['path'] != "None" and  kwargs['path'] != "none":
        Tftp.stop()
        Http.stop()
        handle_tftp_t._stop
        handle_http_t._stop
    exit(0)

def chaddr_to_mac(chaddr):
    mac_format = ":".join(hex(i)[2:] for i in chaddr[0:6])
    mac_format_fix = ":".join(map("{0:0>2}".format, mac_format.split(':')))
    return str(mac_format_fix)

def op43(text_value):
    ret = b""
    xparam = text_value.replace(" ","").split(",")
    for param in xparam:
        p = param.split(":")
        try:
            p[1]
        except:
            return
        tag = int(p[0])
        value = p[1]
        ret += struct.pack("BB", tag, len(str(value))) + str(value).encode()
    ret += struct.pack("B", 255)
    return(ret)

# DhcpResponder
#   -> __init__(self)
#   -> get_parameters(self, path)
#   -> send_offer(self, packet, offer)
#   -> send_ack(self, packet, offer)
class DhcpResponder(object):
    def __init__(self):
        pass

    def get_parameters(self, path):
        files = []
        # r=root, d=directories, f = files
        #print(os.walk(path))
        for r, d, f in os.walk(path):
            for file in f:
                if file.lower().endswith(('.yaml', '.yml')):
                    files.append(os.path.join(r, file))
        
        #print(files)
        config = {}
        for f in files:
            with open(f) as file:
                d = yaml.load(file, Loader=yaml.FullLoader)
                config.update(d)
     
        # Dupliate sections using as name - MAC so we can easy find config searching by MAC-<mac>
        conf = copy.deepcopy(config)
        for section in config:
            if conf[section].get('mac') is not None:
                mac = str(conf[section]['mac']).replace(".","").replace(":","").replace("-","")
                if mac:
                    conf['MAC-'+mac] = copy.deepcopy(config[section])
                    conf[section]['mac'] = str(mac)
                    conf['MAC-'+mac]['mac'] = str(mac)
            else:
                # If mac is not define - asume that section name is a mac
                mac = str(section).replace(".","").replace(":","").replace("-","")
                conf['MAC-'+mac] = copy.deepcopy(config[section])
                conf[section]['mac'] = str(mac)
                conf['MAC-'+mac]['mac'] = str(mac)
        return conf

    def send_offer(self, packet, offer):
        xid = packet[BOOTP].xid
        chaddr = packet[BOOTP].chaddr   # Client MAC Address
        giaddr = packet[BOOTP].giaddr   # Relay agent IP address
        ciaddr = packet[BOOTP].ciaddr   # Client IP Address
        mac = packet[Ether].src
        
        parameters = copy.deepcopy(offer)
        parameters.pop('mac', None)
        sport = packet[UDP].dport
        dport = packet[UDP].sport

        # If source [Discovery] packet was address from 0.0.0.0
        # reponse by Broadcast
        init_ip_src = packet[IP].src
        if init_ip_src == "0.0.0.0":
            ip_dst = "255.255.255.255"
        else:
            ip_dst = init_ip_src
        
        ethernet = Ether(src=kwargs['my_mac'] , dst=mac, type=0x800)
        ip       = IP(src = kwargs['my_ip'], dst=ip_dst)
        udp      = UDP (sport=sport, dport=dport)
        bootp    = BOOTP(   op=2,
                            flags=32768,            # 0 - unicast / 32768 - broadcast
                            ciaddr=ciaddr,          # (Client IP Address)
                            yiaddr=offer["ip"],     # (Your (client) IP Address)
                            siaddr=kwargs['my_ip'], # (Next server IP address)
                            giaddr=giaddr,          # (Relay agent IP Address)
                            chaddr=chaddr,          # Client MAC Address
                            xid=xid                 # Rransaction ID
        )

        options = [(k, v) for k, v in parameters.items()] 
        options.append(("message-type","offer"))
        options.append(("server_id",kwargs['my_ip']))
        options.append(("end"))
        dhcp     = DHCP(options=options)
        
        packet   = ethernet / ip / udp / bootp / dhcp
        sendp(packet, iface=kwargs['interface'], verbose=False)

    def send_ack(self, packet, offer):
        xid = packet[BOOTP].xid
        chaddr = packet[BOOTP].chaddr   # Client MAC Address
        giaddr = packet[BOOTP].giaddr   # Relay agent IP address
        ciaddr = packet[BOOTP].ciaddr   # Client IP Address
        mac = packet[Ether].src
        
        parameters = copy.deepcopy(offer)
        parameters.pop('mac', None)
        sport = packet[UDP].dport
        dport = packet[UDP].sport

        # If source [Discovery] packet was address from 0.0.0.0
        # reponse by Broadcast
        init_ip_src = packet[IP].src
        if init_ip_src == "0.0.0.0":
            ip_dst = "255.255.255.255"
        else:
            ip_dst = init_ip_src

        ethernet = Ether(src=kwargs['my_mac'] , dst=mac, type=0x800)
        ip       = IP(src = kwargs['my_ip'], dst=ip_dst)
        udp      = UDP (sport=sport, dport=dport)
        bootp    = BOOTP(   op=2,
                            flags=32768,            # 0 - unicast / 32768 - broadcast
                            ciaddr=ciaddr,          # (Client IP Address)
                            yiaddr=offer["ip"],     # (Your (client) IP Address)
                            siaddr=kwargs['my_ip'], # (Next server IP address)
                            giaddr=giaddr,          # (Relay agent IP Address)
                            chaddr=chaddr,          # Client MAC Address
                            xid=xid                 # Rransaction ID
        )

        if parameters.get('vendor_specific') is not None:
            op43_encoded = op43(parameters['vendor_specific'])
            if op43_encoded is not None:
                parameters['vendor_specific'] = op43(parameters['vendor_specific'])
            else:
                parameters.pop('vendor_specific', None)

        options = [(k, v) for k, v in parameters.items()] 
        options.append(("message-type","ack"))
        options.append(("server_id",kwargs['my_ip']))
        options.append(("end"))
        dhcp     = DHCP(options=options)
        packet   = ethernet / ip / udp / bootp / dhcp
        sendp(packet, iface=kwargs['interface'], verbose=False)


# HttpServer(object)
#   -> __init__(self, port=80,  **kwargs)
#   -> start(self)
#   -> stop(self)
class HttpServer(object):
    def __init__(self, port=80,  **kwargs):
        self.port = int(kwargs['port_http'])
        self.path = kwargs['path']
        self.my_ip = kwargs['my_ip']
       
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((self.my_ip, self.port)) == 0:
                print(colored('[Warning]  ', 'red') + 'HTTP '+str(self.my_ip)+':'+str(self.port)+' port in use')
                self.busy = 1
            else:
                self.busy = 0

    @threaded
    def start(self):
        if self.busy != 1:
            os.chdir(self.path)
            server_address = (self.my_ip, self.port)
            try:
                self.httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
                self.httpd.socket.getsockname()
                print (colored('[OK]       ', 'green') + "HTTP server started on "+ str(self.my_ip)+" - port "+ str(self.port))
                self.httpd.serve_forever()
            except OSError:
                print (colored('[Warning]  ', 'red') + 'HTTP '+str(self.my_ip)+':'+str(self.port)+' port in use')
                exit(1)

    def stop(self):
        if self.busy != 1:
            print(colored('[OK]       ', 'yellow') + "HTTP stopping..")
            self.httpd.shutdown()
        return

# TftpServer(object)
#   -> __init__(self, port=69, **kwargs)
#   -> stop(self)
#   -> start(self)
class TftpServer(object):
    def __init__(self, port=69, **kwargs):
        self.port = int(kwargs['port_tftp'])
        self.my_ip = kwargs['my_ip']
        self.path = kwargs['path']        
        self.tftp_server = tftpy.TftpServer(self.path)

    def stop(self):
        print(colored('[OK]       ', 'yellow') + "TFTP stopping..")
        self.tftp_server.stop(False)
        return

    @threaded
    def start(self):
        try: 
            print (colored('[OK]       ', 'green') + "TFTP starting on "+ str(self.my_ip)+" - port "+ str(self.port))
            self.tftp_server.listen(listenip=self.my_ip, listenport=self.port, timeout=5)
        except OSError:
            print (colored('[Warning]  ', 'red') + 'TFTP '+str(self.my_ip)+':'+str(self.port)+' port in use')

############
### MAIN ###
############
if __name__ == "__main__":
    signal(SIGINT, handler) 
    while True:
        parser = argparse.ArgumentParser(prog='ztp.py')
        parser.add_argument('-i', '--interface', help='Interface to service requests', default='eth1')
        # parser.add_argument('-l', '--limit', help='Limit to hostname or mac', default='Spine-20')
        parser.add_argument('-p', '--path', help='TFTP folder path. Set `None` to disable TFTP', default='tftp')
        parser.add_argument('--port_tftp', help='TFTP port', default=69)
        parser.add_argument('--port_http', help='HTTP port', default=80)
        parser.add_argument('-d', '--pcap', help='collect PCAP file name for debug', default='False')
        args = parser.parse_args()
        kwargs = vars(args)
        print('Running. Press CTRL-C to exit.')

        if kwargs['pcap'] != "False":
            pktdump = PcapWriter(kwargs['pcap'].replace(".pcap|.pcapng", "")+".pcap", append=True, sync=True)

        # Collect Facts
        offer = dict()
        print(colored('[facts]    ', 'blue') + "DHCP/TFTP interface: " + colored(kwargs['interface'], 'green'))
        addrs = netifaces.ifaddresses(kwargs['interface'])
        kwargs['my_ip']  = addrs[netifaces.AF_INET][0]['addr']
        print(colored('[facts]    ', 'blue') + kwargs['interface']+" IP: " + colored(kwargs['my_ip'], 'green'))
        kwargs['my_mac']  = addrs[netifaces.AF_LINK][0]['addr']
        print(colored('[facts]    ', 'blue') + kwargs['interface']+" MAC: " + colored(kwargs['my_mac'], 'green'))

        # Normalizing path
        if (re.search('^/', kwargs['path'])):
            pass
        else:
            kwargs['path'] = os.getcwd() + "/"+ kwargs['path']
  
        if not os.path.isdir(kwargs['path']):
            print (colored('[error]', 'red') + "    File folder not exist: "+ kwargs['path'])
            exit(1)
        else:
            print(colored('[facts]    ', 'blue') + "File folder status: "+ colored('exist', 'green'))
        
        if os.environ.get("DEBUG") is not None:
            dh = DhcpResponder()
            pprint(dh.get_parameters(kwargs['path']))
        
        # TFTP
        if kwargs['path'] != "None" and  kwargs['path'] != "none":
            print(colored('[facts]    ', 'blue') +'File Path: ' + colored(kwargs['path'], 'green'))
            Tftp = TftpServer(**kwargs)
            handle_tftp_t = Tftp.start()

        # HTTP
        Http = HttpServer(**kwargs)
        handle_http_t = Http.start()

        # Start Sniffer
        # Open UDP socket to prevent ICMP Destination unreachable (Port unreachable)
        UDP_IP = kwargs['my_ip']
        UDP_PORT = 67
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        sock.bind((UDP_IP, UDP_PORT))
        print (colored('[OK]       ', 'green') + 'DHCP starting sniffer '+kwargs['interface']+' - udp and (port 67 or 68)')
        sniff(iface=kwargs['interface'], filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
