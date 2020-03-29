import rsa
import json

#使用1024byte进行证书生成，并从中提取公钥和私钥存储到对应文件中
public_key, private_key = rsa.newkeys(1024)
with open('server_private_key', 'w+') as f:
    f.write(private_key.save_pkcs1().decode())

with open('server_public_key', 'w+') as f:
    f.write(public_key.save_pkcs1().decode())

