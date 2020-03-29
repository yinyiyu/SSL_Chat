import socket
import ssl

class server_ssl:
    def build_listen(self):
        CA_FILE = "ca/ca.crt"
        KEY_FILE = "server/server.key"
        CERT_FILE = "server/server.crt"
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED

        # 监听端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            # 将socket打包成SSL socket
            with context.wrap_socket(sock, server_side=True) as ssock:
                ssock.bind(('127.0.0.1', 5678))
                ssock.listen(5)
                while True:
                    # 接收客户端连接
                    client_socket, addr = ssock.accept()
                    # 接收客户端信息
                    msg = client_socket.recv(1024).decode("utf-8")
                    print(f"receive msg from client {addr}：{msg}")
                    # 向客户端发送信息
                    msg = f"yes , you have client_socketect with server.\r\n".encode("utf-8")
                    client_socket.send(msg)
                    client_socket.close()


if __name__ == "__main__":
    server = server_ssl()
    server.build_listen()
