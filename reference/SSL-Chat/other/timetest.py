#测试时间的格式化输出
import time
now = time.localtime()
print('[{}]'.format(time.strftime("%Y-%m-%d %H:%M:%S", now)))
print('[%s]'%time.strftime("%Y-%m-%d %H:%M:%S", now))



from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_v1_5 #RSA加密协议


#单次加密串的长度最大为 (key_size/8)-11

'''
加密的 plaintext 最大长度是 证书key位数/8 - 11, 例如1024 bit的证书，被加密的串最长 1024/8 - 11=117, 
解决办法是 分块 加密，然后分块解密就行了，
因为 证书key固定的情况下，加密出来的串长度是固定的。
'''
def rsa_long_encrypt(pub_key_str, msg):
    msg = msg.encode('utf-8')
    length = len(msg)
    default_length = 117
    #公钥加密
    pubobj = PKCS1_v1_5.new(rsa.importKey(pub_key_str))
    #长度不用分段
    if length < default_length:
        return "".join(pubobj.encrypt(msg))
    #需要分段
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(pubobj.encrypt(msg[offset:offset+default_length]))
        else:
            res.append(pubobj.encrypt(msg[offset:]))
        offset += default_length
    return "".join(res)


def rsa_long_decrypt(priv_key_str, msg):
    #msg = msg.encode('utf-8')
    length = len(msg)
    default_length = 256
    #私钥解密
    priobj = PKCS1_v1_5.new(rsa.importKey(priv_key_str))
    #长度不用分段
    if length < default_length:
        return "".join(priobj.decrypt(msg,'xyz'))
    #需要分段
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(priobj.decrypt(msg[offset:offset+default_length],'xyz'))
        else:
            res.append(priobj.decrypt(msg[offset:],'xyz'))
        offset += default_length
    return "".join(res)



test = []
for i in range(10):
    test.append(str(i).encode('utf-8'))
print(test)
print(''.join(test))
