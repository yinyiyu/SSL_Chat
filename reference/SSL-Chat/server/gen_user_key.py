import rsa
import json


#不能将private 写到public里面 不然会报b'的那个错误
public_key, private_key = rsa.newkeys(1024)
with open('server_private_key', 'w+') as f:
    f.write(private_key.save_pkcs1().decode())

with open('server_public_key', 'w+') as f:
    f.write(public_key.save_pkcs1().decode())

