import secrets
import time
from gmssl import sm3, func

# 通过生成随机字符串生成随机长度的字符串，并用库函数加密
cip_text = secrets.token_hex(16)  # 生成一个16字节（32字符）的随机十六进制字符串
cip_hash = sm3.sm3_hash(func.bytes_to_list(bytes.fromhex(cip_text)))  # 计算哈希值
t_len = 24# 攻击长度


def birthday_attack(t_len):
    num = 2 ** (t_len // 2)
    ans = [-1] * (2 ** t_len)
    # 循环遍历，对于每一位
    for i in range(num):
        temp = cip_hash[:t_len // 4]
        if ans[int(temp, 16)] == -1:
            ans[int(temp, 16)] = i
        else:
            return temp


if __name__ == '__main__':
    start = time.perf_counter()
    res = birthday_attack(t_len)
    end = time.perf_counter()
    print("{}位碰撞为{}".format(t_len, res))
    print("运行时间为", end - start)
