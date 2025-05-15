

def spoof_dns(pkt, spoofed_domains, fake_ip):
    #pkt : captured packet
    #spoofed_domains : domain we want to poison
    #fake_ip : fake IP address to return in the DNS reply
    return