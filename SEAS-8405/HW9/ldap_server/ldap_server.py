import socket

def main():
    HOST = '172.17.0.1'
    PORT = 1389
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        while(True):
            s.listen(1)
            print(f"[+] LDAP server listening on {HOST}:{PORT}")

            conn, addr = s.accept()
            with conn:
                print(f"[+] Accepted connection from {addr}")
                data = conn.recv(1024)
                print(f"[+] Received data: {data.hex()}")

                conn.close()

if __name__ == '__main__':
    main()