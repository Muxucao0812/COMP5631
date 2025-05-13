import random
import hashlib
from typing import Tuple

# 简化示例参数（生产环境需使用大素数）
p = 23  # 大素数 p
q = 11  # q | (p - 1)
# 找到 g，使其在 Z_p* 中的阶为 q
h = 5
g = pow(h, (p - 1) // q, p)

# 生成密钥对
def generate_keypair() -> Tuple[int, int]:
    x = random.randint(1, q - 1)          # 私钥 x
    y = pow(g, x, p)                      # 公钥 y = g^x mod p
    return x, y

# 计算消息哈希值（取 SHA-1 后对 q 取模）
def hash_message(m: bytes) -> int:
    h_obj = hashlib.sha1(m).digest()
    return int.from_bytes(h_obj, 'big') % q

# 计算模逆
def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)

# 签名
def sign(m: bytes, x: int) -> Tuple[int, int]:
    H = hash_message(m)
    while True:
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        if r == 0:
            continue
        s = (modinv(k, q) * (H + x * r)) % q
        if s == 0:
            continue
        return r, s

# 验证
def verify(m: bytes, signature: Tuple[int, int], y: int) -> bool:
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    H = hash_message(m)
    w = modinv(s, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r

# 演示
if __name__ == "__main__":
    message = b"Hello, DSA!"
    x, y = generate_keypair()
    sig = sign(message, x)
    valid = verify(message, sig, y)
    print(f"公钥 y: {y}")
    print(f"消息: {message!r}")
    print(f"签名 (r, s): {sig}")
    print("验签结果:", "通过" if valid else "失败")
