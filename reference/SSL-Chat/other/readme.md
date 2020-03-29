这是一个课程的课后开发作业，实现一个加密的认证聊天室
参考博客
https://blog.csdn.net/vip97yigang/article/details/84721027
https://blog.csdn.net/lzz781699880/article/details/92787654

ca目录：保存ca的私钥ca.key和证书ca.crt
certDER目录:将证书保存为二进制文件 ca.der client.der server.der
client目录: client.crt client.key
server目录:server.crt server.key
encrypt出现下面错误：
ValueError: Data too long for key size. Encrypt less data or use a larger key size.
rsa加密解密
1024位的证书，加密时最大支持117个字节，解密时为128；
2048位的证书，加密时最大支持245个字节，解密时为256。
加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：1024/8 - 11 = 117）
其中，11位字节为保留字节。

bytes和hex字符串之间的相互转换。
hex和bytes之间的转换
python2
    >>> a = 'aabbccddeeff'
    >>> a_bytes = a.decode('hex')
    >>> print(a_bytes)
    b'\xaa\xbb\xcc\xdd\xee\xff'
    >>> aa = a_bytes.encode('hex')
    >>> print(aa)
    aabbccddeeff
    >>>

python3.5前
    >>> a = 'aabbccddeeff'
    >>> a_bytes = bytes.fromhex(a)
    >>> print(a_bytes)
    b'\xaa\xbb\xcc\xdd\xee\xff'
    >>> aa = ''.join(['%02x' % b for b in a_bytes])
    >>> print(aa)
    aabbccddeeff
    >>>
    
python3.5后
    >>> a = 'aabbccddeeff'
    >>> a_bytes = bytes.fromhex(a)
    >>> print(a_bytes)
    b'\xaa\xbb\xcc\xdd\xee\xff'
    >>> aa = a_bytes.hex()
    >>> print(aa)
    aabbccddeeff
    >>>