from PyQt5.QtWidgets import QApplication ,QWidget
from PyQt5.QtNetwork import  QHostAddress,QTcpServer
from PyQt5 import uic, QtWidgets
from PyQt5.QtGui import QFont
from os.path import basename
import time
from utils import encrypt,decrypt
import ssl
import socket

class Server(QWidget):

    def __init__(self):
        super(Server, self).__init__()
        self.ui = uic.loadUi('ui/MainWindow.ui')
        self.ui.setWindowTitle('CCC')
        self.private_key_path = 'client_private_key'
        self.public_key_path = 'client_public_key'
        self.ui.lab_name.setText('Server')
        self.ui.lab_name.setFont(QFont("Roman times", 16, QFont.Bold))

        # 监听127.0.0.1:6666端口
        self.server = QTcpServer(self)
        if not self.server.listen(QHostAddress.LocalHost, 6666):
            self.ui.list_history.append(self.server.errorString())

        self.server.newConnection.connect(self.new_socket_slot)

        # 事件监听初始化
        self.signal_init()

    def signal_init(self):
        self.ui.btn_look_key.clicked.connect(self.get_private_key)
        self.ui.btn_send.clicked.connect(self.write_data_slot)
        self.ui.btn_decode.clicked.connect(self.decode_data_slot)

    def new_socket_slot(self):
        sock = self.server.nextPendingConnection()

        # TODO 证书认证
        CA_FILE = "ca/ca.crt"
        KEY_FILE = "server/server.key"
        CERT_FILE = "server/server.crt"
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        # socket_sock = socket.socket()
        # sock = context.wrap_socket(socket_sock,server_side=True)

        self.sock = sock
        peer_address = sock.peerAddress().toString()
        peer_port = sock.peerPort()
        news = '证书认证通过Connected with address {}, port {}'.format(peer_address, str(peer_port))
        self.ui.list_history.append(news)

        sock.readyRead.connect(lambda: self.read_data_slot())
        #sock.disconnected.connect(lambda: self.disconnected_slot)

    def read_data_slot(self):
        sock = self.sock
        while sock.bytesAvailable():
            datagram = sock.read(sock.bytesAvailable())
            self.message = datagram
            message = datagram.hex()
            self.ui.list_history.append('【密文】'+'[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))+'Client: {}'.format(message))


    def decode_data_slot(self):
        if self.message:
            message = decrypt(self.message,self.private_key_path).decode()
            self.ui.list_history.append(
                '【解密后】'+'[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + 'Client: {}'.format(message))


    def get_private_key(self):
        private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(None, "选择服务器私钥文件", '.',
                                                                   'All Files (*);;Text Files (*.txt)')
        # (fileName, selectedFilter) QtWidgets.QFileDialog.getOpenFileName
        if private_key_path:
            self.private_key_path = private_key_path
            self.ui.btn_look_key.setText(basename(private_key_path))

    def write_data_slot(self):
        edit = self.ui.text_msg
        answer = edit.toPlainText()
        self.ui.list_history.append('[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + 'Server: {}'.format(answer))

        #加密
        new_datagram = answer.encode('utf-8')
        new_datagram = encrypt(new_datagram,self.public_key_path)
        self.sock.write(new_datagram)
        edit.clear()

    def connected_slot(self):
        #TODO 证书验证
        message = 'Connected! Ready to chat!'
        self.ui.list_history.append(message)

    def close_slot(self):
        self.sock.close()
        self.close()

    def closeEvent(self, event):
        self.sock.close()
        event.accept()


if __name__ == '__main__':
    app = QApplication([])
    stats = Server()
    stats.ui.show()
    app.exec_()

