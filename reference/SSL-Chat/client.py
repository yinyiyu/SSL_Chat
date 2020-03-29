import socket
import ssl

class client_ssl:
    def send_hello(self,):
        CA_FILE = "ca/ca.crt"
        KEY_FILE = "client/client.key"
        CERT_FILE = "client/client.crt"

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        
        # 与服务端建立socket连接
        with socket.socket() as sock:
            # 将socket打包成SSL socket
            with context.wrap_socket(sock, server_side=False) as ssock:
                ssock.connect(('127.0.0.1', 5678))
                # 向服务端发送信息
                msg = "do i connect with server ?".encode("utf-8")
                ssock.send(msg)
                # 接收服务端返回的信息
                msg = ssock.recv(1024).decode("utf-8")
                print(f"receive msg from server : {msg}")
                ssock.close()

if __name__ == "__main__":
    client = client_ssl()
    client.send_hello()
