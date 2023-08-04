from hashlib import sha256
import random

# 生成椭圆曲线上的点
def point_add(x1, y1, x2, y2, p):
    lamda = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
    x3 = (lamda ** 2 - x1 - x2) % p
    y3 = (lamda * (x1 - x3) - y1) % p
    return x3, y3

# 计算模反元素
def mod_inverse(a, m):
    if m == 0:
        return 1, 0, a
    x, y, gcd = ext_euclidean(m, a % m)
    return x % m

# 扩展欧几里得算法
def ext_euclidean(a, b):
    if b == 0:
        return 1, 0, a
    x, y, gcd = ext_euclidean(b, a % b)
    return y, x - a // b * y, gcd

# 计算消息的哈希值
def sm3_hash(msg):
    return sha256(msg).hexdigest()

# SM2加密
def sm2_encrypt(P, M):
    p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF
    a = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFC
    b = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
    Gx = 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
    Gy = 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0
    n = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_F7203BD1_97058653_6DDB3A34_B28FE6AC_9C04FD83

    d = random.randint(1, n - 1)  # 选择随机数d [1, n-1]
    Qx, Qy = point_multiply(Gx, Gy, d, a, p)  # 计算公钥Q

    k = random.randint(1, n - 1)  # 随机数k [1, n-1]
    C1x, C1y = point_multiply(Gx, Gy, k, a, p)  # 计算点C1

    hash_msg = sm3_hash(M.encode())  # 计算消息的哈希值
    t = int(hash_msg, 16) ^ k  # 求t
    C2 = t.to_bytes((t.bit_length() + 7) // 8, 'big')  # 计算C2

    C3 = sm3_hash((hex(C1x)[2:] + hash_msg + hex(C1y)[2:]).encode())  # 计算C3

    return hex(C1x), hex(C1y), C2.hex(), C3

# SM2解密
def sm2_decrypt(d, C1x, C1y, C2, C3):
    p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF
    a = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFC
    b = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
    n = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_F7203BD1_97058653_6DDB3A34_B28FE6AC_9C04FD83

    x2, y2 = point_multiply(int(C1x, 16), int(C1y, 16), d, a, p)  # 计算点(x2, y2)
    
    hash_msg = sm3_hash(int(C1x, 16).to_bytes((int(C1x, 16).bit_length() + 7) // 8, 'big') + bytes.fromhex(C2))  
    t = int(hash_msg, 16) ^ int(C2, 16)  # 求t

    M = t.to_bytes((t.bit_length() + 7) // 8, 'big').decode()  # 解密得到明文M

    C3_calculated = sm3_hash((C1x + hash_msg + C1y).encode())  # 计算C3

    if C3_calculated == C3:
        return M
    else:
        return None

# 示例使用
plaintext = "Hello, world!"
d = random.randint(1, n - 1)  # 选择随机数d [1, n-1]
C1x, C1y, C2, C3 = sm2_encrypt((Gx, Gy), plaintext)
decrypted_text = sm2_decrypt(d, C1x, C1y, C2, C3)

print("Plaintext:", plaintext)
print("Decrypted Text:", decrypted_text)
