from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp

def spoof_dns(pkt, spoofed_domains, fake_ip, attacker_mac, iface):
    if DNS in pkt and DNSQR in pkt:
        #Extract the queried domain and remove trailing dot(e.g., 'facebook.com.')
        queried = pkt[DNSQR].qname.decode().strip('.')

        if queried in spoofed_domains:
            print(f"Spoofing DNS response for {queried}")
            # TODO: build and send the DNS reply using attacker_mac and fake_ip
    return