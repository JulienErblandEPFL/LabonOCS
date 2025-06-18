# network_utils.py

from scapy.all import ARP, Ether, srp, get_if_hwaddr, get_if_addr, conf
import socket

def scan_network(ip_range, iface=None):
    """
    Envoie une requête ARP en broadcast sur le sous-réseau donné
    et retourne la liste des hôtes actifs sous forme (IP, MAC).
    """
    print(f"[*] Scanning network: {ip_range} on interface: {iface or 'default'}")

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, iface=iface, verbose=False)

    hosts = []
    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc
        print(f"[+] Found: {ip} at {mac}")
        hosts.append((ip, mac))

    return hosts

def get_attacker_ip(iface=None):
    """
    Retourne l'adresse IP locale de l'attaquant.
    """
    iface = iface or conf.iface
    return get_if_addr(iface)

def get_attacker_mac(iface=None):
    """
    Retourne l'adresse MAC locale de l'attaquant.
    """
    iface = iface or conf.iface
    return get_if_hwaddr(iface)