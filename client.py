from PyQt5.QtWidgets import QApplication ,QWidget
from PyQt5.QtNetwork import QTcpSocket, QHostAddress
from PyQt5 import uic, QtWidgets
from PyQt5.QtGui import QFont
from os.path import basename
import time
from utils import encrypt,decrypt
import ssl
import socket

class Client(QWidget):

    def __init__(self):
        super(Client, self).__init__()
        self.ui = uic.loadUi('ui/MainWindow.ui')
        self.ui.setWindowTitle('SSS')
        self.private_key_path = 'client_private_key'
        self.public_key_path = 'client_public_key'
        self.ui.lab_name.setText('Client')
        self.ui.lab_name.setFont(QFont("Roman times", 16, QFont.Bold))
        # 与127.0.0.1:6666建立tcp链接，
        self.sock = QTcpSocket(self)
        self.sock.connectToHost(QHostAddress.LocalHost, 6666)

        # 事件监听初始化
        self.signal_init()

    def signal_init(self):
        self.ui.btn_look_key.clicked.connect(self.get_public_key)
        self.ui.btn_send.clicked.connect(self.write_data_slot)
        self.ui.btn_decode.clicked.connect(self.decode_data_slot)
        self.sock.connected.connect(self.connected_slot)
        self.sock.readyRead.connect(self.read_data_slot)

    def get_public_key(self):
        private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(None, "选择服务器私钥文件", '.',
                                                                   'All Files (*);;Text Files (*.txt)')
        # (fileName, selectedFilter) QtWidgets.QFileDialog.getOpenFileName
        if private_key_path:
            self.private_key_path = private_key_path
            self.ui.btn_look_key.setText(basename(private_key_path))

    def write_data_slot(self):
        edit = self.ui.text_msg
        message = edit.toPlainText()
        self.ui.list_history.append('[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))+'Client: {}'.format(message))
        datagram = message.encode('utf-8')
        #用公钥加密
        datagram = encrypt(datagram,self.public_key_path)
        self.sock.write(datagram)
        edit.clear()

    def connected_slot(self):
        #TODO 证书验证
        CA_FILE = "ca/ca.crt"
        KEY_FILE = "client/client.key"
        CERT_FILE = "client/client.crt"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        # socket_sock = socket.socket()
        # sock = context.wrap_socket(socket,server_side=True)

        message = 'Connected! Ready to chat!证书认证通过'
        self.ui.list_history.append(message)

    def read_data_slot(self):
        while self.sock.bytesAvailable():
            datagram = self.sock.read(self.sock.bytesAvailable())
            self.message = datagram
            #显示加密前的消息
            message = datagram.hex()
            self.ui.list_history.append('【密文】'+'[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))+'Server: {}'.format(message))

    def decode_data_slot(self):
        if self.message:
            message = decrypt(self.message,self.private_key_path).decode()
            self.ui.list_history.append(
                 '【解密后】'+'[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + 'Server: {}'.format(message))

    def close_slot(self):
        self.sock.close()
        self.close()

    def closeEvent(self, event):
        self.sock.close()
        event.accept()


if __name__ == '__main__':
    app = QApplication([])
    stats = Client()
    stats.ui.show()
    app.exec_()

