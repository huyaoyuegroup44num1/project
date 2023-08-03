import random
import time
from gmssl import sm3, func

def SM3_rho_attack(n):
    random_number = random.randint(0, 2**(n+1)-1)
    cip = hex(random_number)[2:]
    cip_hash1 = sm3.sm3_hash(func.bytes_to_list(bytes(cip, encoding='utf-8')))
    cip_hash2 = sm3.sm3_hash(func.bytes_to_list(bytes(sm3.sm3_hash(func.bytes_to_list(bytes(cip, encoding='utf-8'))), encoding='utf-8')))
    cnt = 1
    while cip_hash1[:int(n/4)] != cip_hash2[:int(n/4)]:
        cnt += 1
        cip_hash1 = sm3.sm3_hash(func.bytes_to_list(bytes(cip_hash1, encoding='utf-8')))
        cip_hash2 = sm3.sm3_hash(func.bytes_to_list(bytes(sm3.sm3_hash(func.bytes_to_list(bytes(cip_hash2, encoding='utf-8'))), encoding='utf-8')))
    
    for j in range(1, cnt+1):
        cip_hash1 = sm3.sm3_hash(func.bytes_to_list(bytes(cip_hash1, encoding='utf-8')))
        cip_hash2 = sm3.sm3_hash(func.bytes_to_list(bytes(cip_hash2, encoding='utf-8')))
        if cip_hash1[:int(n/4)] == cip_hash2[:int(n/4)]:
            collision = sm3.sm3_hash(func.bytes_to_list(bytes(cip_hash1, encoding='utf-8')))
            return [cip_hash1, cip_hash2, collision]
    
    # 如果未找到碰撞，返回默认值
    return None

if __name__ == '__main__':
    n = int(input("攻击多少bit：\n"))
    start = time.time()
    res = SM3_rho_attack(n)
    end = time.time()

    if res is not None:
        print("message1:", res[0])
        print("message2:", res[1])
        print("碰撞:", res[2])
    else:
        print("未找到碰撞")

    print(end-start,"seconds\n")
