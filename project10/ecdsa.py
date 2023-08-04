from fastecdsa.curve import secp256k1
from fastecdsa.encoding.sec1 import PEMEncoder, PEMParser
from fastecdsa.point import Point
from hashlib import sha256
import time

# 生成随机私钥
def generatePrivateKey():
    return secrets.randbelow(secp256k1.q)

# ECDSA签署消息
def signECDSAsecp256k1(msg, privKey):
    msgHash = sha256(msg.encode("utf8")).digest()
    signature = secp256k1.sign(msgHash, privKey)
    return signature

# ECDSA验证签名
def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha256(msg.encode("utf8")).digest()
    valid = secp256k1.verify(msgHash, signature, pubKey)
    return valid

# 测试签名和验证的时间性能
def testPerformance():
    msg = "Message for testing performance"
    privKey = generatePrivateKey()

    # 计算签名时间
    start = time.time()
    signature = signECDSAsecp256k1(msg, privKey)
    end = time.time()
    signingTime = end - start

    # 计算验证时间
    pubKey = secp256k1.G * privKey
    start = time.time()
    valid = verifyECDSAsecp256k1(msg, signature, pubKey)
    end = time.time()
    verifyingTime = end - start

    print("\n签名时间:", signingTime, "秒")
    print("验证时间:", verifyingTime, "秒")

# 示例代码
def exampleCode():
    # ECDSA签署消息
    msg = "Message for ECDSA signing"
    privKey = generatePrivateKey()
    signature = signECDSAsecp256k1(msg, privKey)
    print("消息:", msg)
    print("私钥:", hex(privKey))
    print("签名: r=" + hex(signature.r) + ", s=" + hex(signature.s))

    # ECDSA验证签名
    pubKey = secp256k1.G * privKey
    valid = verifyECDSAsecp256k1(msg, signature, pubKey)
    print("\n消息:", msg)
    print("公钥:", pubKey)
    print("签名是否有效?", valid)

    # ECDSA验证篡改签名
    msg = "Tampered message"
    valid = verifyECDSAsecp256k1(msg, signature, pubKey)
    print("\n消息:", msg)
    print("签名是否有效(篡改后)?", valid)

    # 运行性能测试
    testPerformance()

# 运行示例代码
exampleCode()
