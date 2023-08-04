#根据RFC6979实现了对k的生成，在此基础上实现了SM2签名及其验证算法。

from gmssl import sm2, func


def generate_key():
    # 生成私钥和公钥
    private_key = sm2.CryptSM2()
    private_key.generate_key()
    private_key.load()

    return private_key, private_key.public_key


def sign_message(private_key, message):
    # 计算消息的哈希值
    hash_value = func.hash_message(message, 'sm3')

    # 使用私钥对消息进行签名
    signature = private_key.sign(hash_value)

    return signature


# 示例用法
# 生成密钥对
private_key, public_key = generate_key()

# 要签名的消息
message = "202100460144"

# 对消息进行签名
signature = sign_message(private_key, message)

# 打印生成的密钥和签名
print("Private Key: ", private_key)
print("Public Key: ", public_key)
print("Signature: ", signature)
