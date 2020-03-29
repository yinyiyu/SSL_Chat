import rsa
import time

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


# 加密函数
def encrypt(src_msg, dst_file_name, public_key_file_name):
    """
    对原始数据文件使用指定的公钥进行加密，并将加密输出到目标文件中
    :param src_msg: 原始数据
    :param dst_file_name: 加密输出文件
    :param public_key_file_name: 用于加密的公钥
    :return: 加密结果的bytes数组
    """
    default_length = 117
    # 读取原始数据
    timeform = '[{}]:'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    src_msg = timeform + src_msg
    data = src_msg.encode('utf-8')

    # 读取公钥数据
    key_file = open(public_key_file_name, 'rb')
    public_key = rsa.PublicKey.load_pkcs1(key_file.read())


    # 使用公钥对原始数据进行加密
    if len(data) >= default_length:
        out_data = rsa_long_encrypt(data,public_key)

    else:
        out_data = rsa.encrypt(data,public_key)

    # 将加密结果输出到目标文件中
    # write encrypted data
    out_data_file = open(dst_file_name, 'w')

    out_data = out_data.hex()
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
    default_length = 128
    # 读取原始数据
    data_file = open(src_file_name, 'r')
    data = data_file.read()
    data_file.close()

    # 读取私钥数据
    key_file = open(private_key_file_name, 'rb')
    private_key = rsa.PrivateKey.load_pkcs1(key_file.read())


    # 使用私钥对数据进行解密
    data = bytes.fromhex(data)
    if len(data) >= default_length:
        out_data = rsa_long_decrypt(data,private_key)
    else:
        out_data = rsa.decrypt(data,private_key)

    # 将解密结果输出到目标文件中
    out_data_file = open(dst_file_name, 'a+')
    out_data = out_data.decode('utf-8')
    out_data_file.write(out_data)
    out_data_file.close()

    # 返回解密结果
    return out_data


def rsa_long_encrypt(msg,pub_key_str):
    # 需要分段
    default_length = 117
    offset = 0
    res = bytes('','utf-8')
    length = len(msg)
    while length - offset > 0:
        if length - offset > default_length:
            res+=(rsa.encrypt(msg[offset:offset + default_length],pub_key_str))
        else:
            res+=(rsa.encrypt(msg[offset:],pub_key_str))
        offset += default_length

    return res

def rsa_long_decrypt(msg,priv_key_str):
    #需要分段
    default_length = 128
    offset = 0
    res = bytes('','utf-8')
    length = len(msg)
    while length - offset > 0:
        if length - offset > default_length:
            res+=(rsa.decrypt(msg[offset:offset+default_length],priv_key_str))
        else:
            res+=(rsa.decrypt(msg[offset:],priv_key_str))
        offset += default_length
    return res



if __name__ == '__main__':
    str_client = 'this is client\n'
    str_server = 'this is server\n'
    client_src_file_name = 'msg/client_msg.txt'
    server_src_file_name = 'msg/server_msg.txt'

    # with open(client_src_file_name,'a+') as f:
    #     f.write(str_client)
    # with open(server_src_file_name,'a+') as f:
    #     f.write(str_server)

    client_encode_dst_file = 'msg/client_encrypt.txt'
    server_encpde_dst_file = 'msg/server_encrypt.txt'

    client_decode_dst_file = 'msg/client_decode_msg.txt'
    server_decode_dst_file = 'msg/server_decode_msg.txt'

    client_public_key = 'client/client_public_key'
    client_private_key = 'client/client_private_key'

    server_public_key = 'server/server_public_key'
    server_private_key = 'server/server_private_key'


    msg = '测试6langlanglanglnsjdjajsdjfjajsdjfjajsdjfjasdklfjajsdkfjlkjalsdjfajsdjfjalsjdfjasdjfjasdjfkl\n'

    # timeform = '[{}]:'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    # msg = timeform+msg
    with open('msg/msg.txt','a+') as f:
        f.write(msg)

    print('测试加密后的消息'+encrypt(msg,client_encode_dst_file,server_public_key))
    print('测试解密后的消息'+decrypt(client_encode_dst_file,client_decode_dst_file,server_private_key))
    #print('客户端加密后的消息'+encrypt(client_src_file_name,client_encode_dst_file,server_public_key))
    # print('\n客户端解密后的消息'+decrypt(client_encode_dst_file,client_decode_dst_file,server_private_key))
    # print('\n服务端加密后的消息'+encrypt(server_src_file_name,server_encpde_dst_file,client_public_key))
    # print('\n服务端解密后的消息'+decrypt(server_encpde_dst_file,server_decode_dst_file,client_private_key))
