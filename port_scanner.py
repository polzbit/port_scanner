from scapy.all import *
from argparse import ArgumentParser, ArgumentTypeError

def getParse():
    # setup arguments
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip', dest='ip', help='Enter target ip address.')
    parser.add_argument('-s', '--start', dest='start', help='Enter start PORT.', type=check_positive)
    parser.add_argument('-e', '--end', dest='end', help='Enter end PORT.', type=check_positive)
    # check arguments
    arguments = parser.parse_args()
    if not arguments.ip:
        parser.error('[!] Specify target ip address --help for more information')
    elif arguments.start == None:
        parser.error('[!] Specify start port --help for more information')
    elif arguments.end == None:
        parser.error('[!] Specify end port --help for more information')
    else:
        port = range(arguments.start, arguments.end)
        print_res(syn_scan(arguments.ip, port))

def check_positive(value):
    val = int(value)
    if val < 0:
        raise ArgumentTypeError("%s is an invalid positive int value" % value)
    return val

def send_rst(ip, ports):
    src_port = RandShort()
    sr(IP(dst=ip)/TCP(sport=src_port,dport=ports,flags='RA'), timeout=10)

def syn_scan(ip, ports):
    results = {port: None for port in ports}
    rst_list = []
    src_port = RandShort()
    ans, uns = sr(IP(dst=ip)/TCP(sport=src_port,dport=ports,flags='S'), timeout=10)
    for req,resp in ans:
        if resp.haslayer(TCP):
            tcp_pkt = resp.getlayer(TCP)
            if(tcp_pkt.flags == 'SA'):
                results[tcp_pkt.sport] = True
                rst_list.append(tcp_pkt.sport)
            elif(tcp_pkt.flags == 'RA'):
                results[tcp_pkt.sport] = False
    send_rst(ip, rst_list)
    return results

def print_res(results):
    for port, val in sorted(results.items()):
        if val:
            print(str(port) + ' - Open')
        elif not val:
            print(str(port) + ' - Closed')
        else:
            print(str(port) + ' - Filtered')

if __name__ == "__main__":
    getParse()