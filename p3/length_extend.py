import hashlib
import random
import struct
import time

def length_extend_attack(src_hash, append_msg):
    vec = []

    for i in range(0, len(src_hash), 8):
        vec.append(int(src_hash[i:i + 8], 16))

    fake_msg = bytearray()

    fake_msg.extend(b'\x80')
    fake_msg.extend(b'\x00' * ((len(fake_msg) + 55) % 64))
    fake_msg.extend(struct.pack('>Q', (len(fake_msg) + len(append_msg)) * 8))
    fake_msg.extend(append_msg.encode('utf-8'))

    fake_hash = hashlib.new('sm3')
    fake_hash.update(fake_msg)
    fake_hash = fake_hash.digest()

    return hashlib.sha256(fake_hash + struct.pack('<II', vec[0], vec[1])).hexdigest()

def main():
    message = str(random.randint(10 ** 200, 10 ** 201))
    message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
    append_m = "202100460144"

    start_time = time.time()
    
    fake_hash = length_extend_attack(message_hash, append_m)

    new_msg = message.encode('utf-8') + append_m.encode('utf-8')
    new_hash = hashlib.sha256(new_msg).hexdigest()

    end_time = time.time()

    print("message:", message)
    print("message_hash:", message_hash)
    print("append_message:", append_m, '\n')

    print('new_hash', new_hash)
    print("fake_hash:", fake_hash, '\n')

    if fake_hash == new_hash:
        print('Attack Success')
    else:
        print('Failed')

    print("Execution Time:", end_time - start_time)

if __name__ == '__main__':
    main()
