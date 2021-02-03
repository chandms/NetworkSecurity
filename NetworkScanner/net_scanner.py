import scapy.all as scapy
import optparse

def get_arguments():
    parse = optparse.OptionParser()
    parse.add_option('-t', '--target', dest="ip", help="Input the target ip address")
    options, arguments = parse.parse_args()
    if not options.ip:
        print("User has not provided target ip address")
        exit()
    return options

def auto_scan(ip):
    scapy.arping(ip)


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast/arp_req
    answered = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_table(clients_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for element in clients_list:
        print(element["ip"]+"\t\t"+element["mac"])


options = get_arguments()
result_list = scan(options.ip)
print_table(result_list)
# auto_scan('10.0.2.1/24')


