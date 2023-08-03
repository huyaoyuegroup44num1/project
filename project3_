from gmssl import sm3, func   # SM3 哈希函数的长度扩展攻击
import random
import gmssl_sm3
import struct

def length_extend_attack(src_hash, append_msg):
    vec = []

    for i in range(0, len(src_hash), 8):
        vec.append(int(src_hash[i:i + 8], 16))

    fake_msg = bytearray(0)  # 使用bytearray对象替代字符串拼接

    fake_msg.extend(bytes([0x80]))  # 使用bytearray.extend()方法对消息进行填充
    fake_msg.extend(bytes([(len(fake_msg) + 56) % 64]))  # 使用bytearray.extend()方法对消息进行填充
    fake_msg.extend(bytes([0x00] * ((len(fake_msg) + 8) % 64)))  # 使用bytearray.extend()方法对消息进行填充
    fake_msg.extend(struct.pack('>q', (len(fake_msg) + len(append_msg)) * 8))  # 使用bytearray.extend()方法对消息进行填充
    fake_msg.extend(bytes(append_msg, encoding='utf-8'))  # 使用bytearray.extend()方法对消息进行填充

    fake_msg = func.bytes_to_list(fake_msg)

    return gmssl_sm3.sm3_hash(fake_msg, vec)

def main():
    message = str(random.randint(10 ** 200, 10 ** 201))
    message_hash = sm3.sm3_hash(func.bytes_to_list(bytes(message, encoding='utf-8')))
    append_m = "202100460144"

    fake_hash = length_extend_attack(message_hash, append_m)

    new_msg = bytearray(message.encode('utf-8'))
    new_msg.extend(bytes(append_m, encoding='utf-8'))

    new_hash = sm3.sm3_hash(func.bytes_to_list(new_msg))

    print("message:", message)
    print("message_hash:", message_hash)
    print("append_message:", append_m, '\n')

    print('new_hash', new_hash)
    print("fake_hash:", fake_hash, '\n')

    if fake_hash == new_hash:
        print('Attack Success')
    else:
        print('Failed')

if __name__ == '__main__':
    main()
