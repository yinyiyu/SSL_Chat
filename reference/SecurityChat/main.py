# -*- coding: utf-8 -*-
# Python3-OpenSSL
# pip3 install cryptography

import wx
import socket
import threading
import sys
import select
import queue as Queue
# 导入cryptography库的相关模块和函数
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import padding

# data_file_name = r'msg.bin'
data_file_name = r'msg.txt'
encrypted_file_name = r'msg.bin.encrypted'
decrypted_file_name = r'msg.bin.decrypted'

private_key_file_name = r'Key.pem'
public_key_file_name = r'Key_pub.pem'


class chatdlg(wx.Dialog):
    def __init__(self):
        wx.Dialog.__init__(self, None, -1, u'基于 OpenSSL 聊天工具的设计与实现',
                           size=(610, 500))

        self.DisplayText = wx.TextCtrl(self, -1, '',
                                       size=(600, 350), style=wx.TE_MULTILINE)

        self.InputText = wx.TextCtrl(self, -1, "Hi,How are you! ",
                                     pos=(5, 370), size=(480, -1))

        self.sendButton = wx.Button(self, -1, "Send", pos=(500, 370))
        self.Bind(wx.EVT_BUTTON, self.OnSendClick, self.sendButton)
        self.sendButton.SetDefault()

        wx.StaticText(self, -1, "IP", (5, 415))
        self.IPText = wx.TextCtrl(self, -1, "127.0.0.1",
                                  pos=(30, 415), size=(150, -1))
        wx.StaticText(self, -1, "Port", (200, 415))
        self.PortText = wx.TextCtrl(self, -1, "8001",
                                    pos=(230, 415), size=(50, -1))

        self.cButton = wx.Button(self, -1, "Connect as a client", pos=(300, 415))
        self.Bind(wx.EVT_BUTTON, self.OnClientClick, self.cButton)
        self.sButton = wx.Button(self, -1, "Connect as a Server", pos=(450, 415))
        self.Bind(wx.EVT_BUTTON, self.OnSeverClick, self.sButton)

    def OnSendClick(self, event):
        # self.sendButton.SetLabel("Clicked")
        self.send_data = self.InputText.GetValue()

        try:
            # print(self.send_data)

            fo = open(data_file_name, 'w')
            fo.write(self.send_data)
            fo.close()
            # 先对数据加密
            self.datamsg = encrypt(data_file_name, encrypted_file_name, public_key_file_name)

            self.client.send(self.datamsg)  # self.datamsg 是客户端要发送的密文

            # self.client.send(self.send_data.encode('utf-8'))   ##encoding="utf-8"

            self.DisplayText.AppendText('\nYour said:  [')
            # self.DisplayText.AppendText(self.send_data.encode())   #encoding="utf-8"
            self.DisplayText.AppendText(self.send_data)
            self.DisplayText.AppendText(']\n')
        except  socket.error:
            self.DisplayText.AppendText('Pls connect to chat server @%d firstly\n' % self.port)

    def SocketProc_server(self):
        self.sButton.SetLabel(self.PortText.GetValue())

        # Sockets to which we expect to write
        outputs = []

        # Outgoing message queues (socket:Queue)
        message_queues = {}

        # 创建socket并绑定
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = int(self.PortText.GetValue())
        self.host = ''

        print('Waiting for connection @%s:%d\n' % (self.host, self.port))

        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

        self.DisplayText.AppendText('Waiting for connection @%s:%d\n' % (self.host, self.port))

        # Sockets from which we expect to read
        inputs = [self.server]

        while inputs:
            # Wait for at least one of the sockets to be ready for processing
            print('\n>>sys.stderr, waiting for the next event')
            readable, writable, exceptional = select.select(inputs, outputs, inputs)

            fo = open(encrypted_file_name, 'w')
            fo.write('')
            fo.close()

            # Handle inputs
            for s in readable:
                if s is self.server:
                    # A "readable" server socket is ready to accept a connection
                    connection, client_address = s.accept()
                    print(client_address)

                    self.DisplayText.AppendText('new connection from %s, %s \n' % (
                    client_address[0], client_address[1]))  # $!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    connection.setblocking(False)
                    inputs.append(connection)

                    # Give the connection a queue for data we want to send
                    message_queues[connection] = Queue.Queue()
                else:

                    data = s.recv(1024)

                    fo = open(encrypted_file_name, 'ab')
                    fo.write(data)
                    fo.close()
                    datamsg = decrypt(encrypted_file_name, decrypted_file_name, private_key_file_name)

                    if data:
                        # A readable client socket has data
                        print('received [%s] from %s' % (datamsg, s.getpeername()))

                        self.DisplayText.AppendText('received [%s] from %s\n' % (datamsg, s.getpeername()))

                        for c in inputs:
                            if c is self.server:
                                print('\nfrom server')
                            elif c is not s:
                                print('send_data [%s] to %s' % (datamsg, s.getpeername()))  # .decode()
                                message_queues[c].put('[ %s ] from %s ' % (datamsg, str(s.getpeername())))
                                if c not in outputs:
                                    outputs.append(c)
                    else:
                        # Interpret empty result as closed connection
                        print('closing %,%s after reading no data' % (client_address[0], client_address[1]))

                        self.DisplayText.AppendText(
                            'closing %s,%s after reading no data\n\n' % (client_address[0], client_address[1]))
                        # Stop listening for input on the connection
                        if s in outputs:
                            outputs.remove(s)
                        inputs.remove(s)
                        s.close()

                        # Remove message queue
                        del message_queues[s]

            # Handle outputs
            for s in writable:
                try:
                    next_msg = message_queues[s].get_nowait()
                except Queue.Empty:
                    print('output queue for %s, %s is empty' % (s.getpeername()[0], s.getpeername()[1]))
                    outputs.remove(s)
                else:
                    print('sending "%s" to %s' % (next_msg, s.getpeername()))  # datamsg 是解码后的，用于显示在服务器端界面
                    print(datamsg)  # datamsg 是解码后的，用于显示在服务器端界面

                    s.send(data)  # data 是解码前的

            # Handle "exceptional conditions"
            for s in exceptional:
                print('handling exceptional condition for %s ' % s.getpeername())
                self.DisplayText.AppendText('handling exceptional condition for', s.getpeername())
                # Stop listening for input on the connection
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
                s.close()

                # Remove message queue
                del message_queues[s]

    def SocketProc_client(self):
        self.cButton.SetLabel(self.PortText.GetValue())

        # Sockets to which we expect to write
        outputs = []

        # Outgoing message queues (socket:Queue)
        message_queues = {}

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = str(self.IPText.GetValue())
        self.port = int(self.PortText.GetValue())
        print('Connecting to chat server@%s:%d\n' % (self.host, self.port))
        try:
            self.client.connect((self.host, self.port))
            print('connected to chat server @%s:%d\n' % (self.host, self.port))
            self.DisplayText.AppendText('Connected to chat server@%s:%d\n' % (self.host, self.port))
        except socket.error:
            print('Could not connect to chat server @%s:%d\n' % (self.host, self.port))
            self.DisplayText.AppendText('Could not connect to chat server @%s:%d\n' % (self.host, self.port))
            return

        inputs = [self.client]
        message_queues[self.client] = Queue.Queue()

        while inputs:
            # Wait for at least one of the sockets to be ready for processing
            print('\nwaiting for the next event')
            readable, writable, exceptional = select.select(inputs, outputs, inputs)

            fo = open(encrypted_file_name, 'w')
            fo.write('')
            fo.close()

            # Handle inputs
            for s in readable:
                data = s.recv(1024)  # data是客户端刚接收到的密文

                fo = open(encrypted_file_name, 'ab')
                fo.write(data)  # 将密文写入文件
                fo.close()
                datamsg = decrypt(encrypted_file_name, decrypted_file_name, private_key_file_name)

                if data:

                    print('received "%s" from %s' % (
                    datamsg.decode('utf-8'), s.getpeername()))  # datamsg 是客户端接收到密文之后进行解密的信息

                    self.DisplayText.AppendText('received "%s"\n' % datamsg.decode('utf-8'))  # 显示明文
                else:
                    # Interpret empty result as closed connection
                    print('>>sys.stderr, closing %s after reading no data' % (self.host, self.port))
                    # self.DisplayText.AppendText('closing %s after reading no data\n\n' % client_address)#
                    # Stop listening for input on the connection
                    if s in outputs:
                        outputs.remove(s)
                    inputs.remove(s)
                    s.close()

                    # Remove message queue
                    del message_queues[s]

            # Handle outputs
            for s in writable:
                try:
                    next_msg = message_queues[s].get_nowait()
                except Queue.Empty:
                    # No messages waiting so stop checking for writability.
                    print('>>sys.stderr, output queue for % is empty' % s.getpeername())
                    outputs.remove(s)
                else:
                    print('>>sys.stderr, sending "%s" to %s' % (next_msg, s.getpeername()))

                    fo = open(data_file_name, 'w')
                    fo.write(next_msg)
                    fo.close()
                    # 先对数据加密
                    datamsg = encrypt(data_file_name, encrypted_file_name, public_key_file_name)
                    # 打印加密结果
                    print("encrypted data:")
                    # dump_hex(data)
                    print(datamsg)
                    '''
                    # 对数据进行解密
                    datatest = decrypt(encrypted_file_name, decrypted_file_name, private_key_file_name)
                    # 打印解密结果
                    print("decrypted data:")
                    print(datatest)
                    print('!!!!!!!!!!!!!!!!!!!!!!')
                    print('!!!!!!!!!!!!!!!!!!!!!!')
                    print('!!!!!!!!!!!!!!!!!!!!!!')
                    '''

                    s.send(datamsg)
            # Handle "exceptional conditions"
            for s in exceptional:
                print('>>sys.stderr, handling exceptional condition for %s ' % s.getpeername())
                self.DisplayText.AppendText('handling exceptional condition for % s' % s.getpeername())
                # Stop listening for input on the connection
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
                s.close()

                # Remove message queue
                del message_queues[s]

    def SocketProc_process(self):
        pass
        # recv all recv_data
        # broadcast msg

    def OnSeverClick(self, event):
        self.socketmode = 1
        # thread.start_new_thread(self.SocketProc_server,())
        trd = threading.Thread(target=self.SocketProc_server)
        trd.setDaemon(True)
        trd.start()

    def OnClientClick(self, event):
        self.socketmode = 0
        # self.cButton.SetLabel("connected")
        # thread.start_new_thread(self.SocketProc_client,())

        # threading.Thread
        trd = threading.Thread(target=self.SocketProc_client)
        trd.setDaemon(True)
        trd.start()


# 定义辅助函数，用于打印16进制数据
def dump_hex(buffer, sep=' ', indent=0, line_size=16):
    """
    辅助函数，将bytes数组以如下格式打印输出：
    0000: 40 71 37 d0 80 32 7f 04 d9 6d fb fc f7 6a 7d d4
    0010: 48 ad 75 79 7a 0d 6c 55 01 ed 45 d5 1e 75 33 a6
    :param buffer: 待打印数据
    :param sep: 各16进制数据之间的分隔符，默认用空格' '分隔
    :param indent: 打印输出前是否需要缩进，默认不缩进
    :param line_size: 每行输出16进制的数量，默认1行输出16个
    :return: 无返回值
    """
    # 计算缩进空格数
    leading = '%s' % ' ' * indent
    # 循环打印每行16进制数据
    for x in range(0, len(buffer), line_size):
        # 打印缩进字符和当前行数据的起始地址
        print('%s%04X: ' % (leading, x))
        # 将当前行数据制作成列表list，并打印
        line = ['%02x' % i for i in buffer[x:x + line_size]]
        # print(*line, sep=sep, end='\n')


# 加密函数
def encrypt(src_file_name, dst_file_name, public_key_file_name):
    """
    对原始数据文件使用指定的公钥进行加密，并将加密输出到目标文件中
    :param src_file_name: 原始数据文件
    :param dst_file_name: 加密输出文件
    :param public_key_file_name: 用于加密的公钥
    :return: 加密结果的bytes数组
    """
    # 读取原始数据
    data_file = open(src_file_name, 'rb')
    data = data_file.read()
    data_file.close()

    # 读取公钥数据
    key_file = open(public_key_file_name, 'rb')
    key_data = key_file.read()
    key_file.close()

    # 从公钥数据中加载公钥
    public_key = serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )

    # 使用公钥对原始数据进行加密，使用PKCS#1 v1.5的填充方式
    out_data = public_key.encrypt(
        data,
        padding.PKCS1v15()
    )

    # 将加密结果输出到目标文件中
    # write encrypted data
    out_data_file = open(dst_file_name, 'wb')
    out_data_file.write(out_data)
    out_data_file.close()

    # 返回加密结果
    return out_data


# 解密函数
def decrypt(src_file_name, dst_file_name, private_key_file_name):
    """
    对原始数据文件使用指定的私钥进行解密，并将结果输出到目标文件中
    :param src_file_name: 原始数据文件
    :param dst_file_name: 解密输出文件
    :param private_key_file_name: 用于解密的私钥
    :return: 解密结果的bytes数组
    """
    # 读取原始数据
    data_file = open(src_file_name, 'rb')
    data = data_file.read()
    data_file.close()

    # 读取私钥数据
    key_file = open(private_key_file_name, 'rb')
    key_data = key_file.read()
    key_file.close()

    # 从私钥数据中加载私钥
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
        backend=default_backend()
    )

    # 使用私钥对数据进行解密，使用PKCS#1 v1.5的填充方式
    out_data = private_key.decrypt(
        data,
        padding.PKCS1v15()
    )

    # 将解密结果输出到目标文件中
    out_data_file = open(dst_file_name, 'wb')
    out_data_file.write(out_data)
    out_data_file.close()

    # 返回解密结果
    return out_data


if __name__ == '__main__':
    app = wx.App()
    app.MainLoop()
    dialog = chatdlg()
    result = dialog.ShowModal()
    if result == wx.ID_OK:
        print("OK")
    else:
        print("Cancel")
    dialog.Destroy()
