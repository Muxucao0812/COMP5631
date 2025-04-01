import sympy
import os
import math

def encrypt(data, e, n):
    """
    加密数据，支持文本或字节数据
    """
    if isinstance(data, str):
        # 如果输入是字符串，转换为字节数组
        data = [ord(char) for char in data]
    elif isinstance(data, bytes):
        # 如果输入是字节，转换为整数列表
        data = list(data)
    
    # 加密每个值
    ciphertext = [pow(char, e, n) for char in data]
    return ciphertext

def decrypt(ciphertext, d, n):
    """
    解密数据，返回原始形式（文本或字节）
    """
    # 解密每个值
    decrypted = [pow(char, d, n) for char in ciphertext]
    return decrypted

def text_encrypt(plaintext, e, n):
    """
    加密文本并返回密文
    """
    encrypted = encrypt(plaintext, e, n)
    return encrypted

def text_decrypt(ciphertext, d, n):
    """
    解密文本并返回明文
    """
    decrypted = decrypt(ciphertext, d, n)
    # 转换回字符串
    return ''.join([chr(char) for char in decrypted])

def file_to_bytes(file_path):
    """
    将文件读取为字节数组
    """
    with open(file_path, 'rb') as file:
        return file.read()

def bytes_to_file(data, file_path):
    """
    将字节数组写入文件
    """
    with open(file_path, 'wb') as file:
        file.write(bytes(data))

def encrypt_file(input_file, output_file, e, n):
    """
    加密文件
    """
    # 读取文件为字节
    file_bytes = file_to_bytes(input_file)
    
    # 将字节分块处理，避免超出RSA加密限制
    block_size = 1  # 每次处理一个字节，可以根据n的大小调整
    
    # 分块加密
    encrypted_data = []
    for i in range(0, len(file_bytes), block_size):
        block = file_bytes[i:i+block_size]
        encrypted_block = encrypt(block, e, n)
        encrypted_data.extend(encrypted_block)
    
    # 将加密结果保存为文件
    with open(output_file, 'w') as f:
        f.write(','.join(map(str, encrypted_data)))
    
    return encrypted_data

def decrypt_file(input_file, output_file, d, n):
    """
    解密文件
    """
    # 读取加密的数据
    with open(input_file, 'r') as f:
        encrypted_data = [int(x) for x in f.read().split(',')]
    
    # 解密数据
    decrypted_data = decrypt(encrypted_data, d, n)
    
    # 将解密后的数据写入文件
    bytes_to_file(decrypted_data, output_file)
    
    return decrypted_data

def generate_keypair(p, q):
    # Calculate n
    n = p * q
    # Calculate the totient
    phi = (p - 1) * (q - 1)
    # Find e such that e and phi are coprime
    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1
    # Find d such that d is the modular inverse of e
    d = modinv(e, phi)
    # Return the public and private keys
    return (e, n), (d, n)

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def main():
    p = sympy.nextprime(2**31)
    q = sympy.nextprime(p)
    
    public, private = generate_keypair(p, q)
    e, n = public
    d, n = private
    
    # 测试文本加密解密
    plaintext = '早上好家人们'
    ciphertext = text_encrypt(plaintext, e, n)
    decrypted = text_decrypt(ciphertext, d, n)
    
    print('Public key:', public)
    print('Private key:', private)
    print('Plaintext:', plaintext)
    print('Ciphertext:', ciphertext)
    print('Decrypted:', decrypted)
    if plaintext == decrypted:
        print('文本解密成功')
    else:
        print('文本解密失败')
    
    # 测试图片加密解密
    try:
        input_image = "fig.jpg"  # 请确保此图片存在
        encrypted_image = "encrypted_image.txt"
        decrypted_image = "decrypted_image.jpg"
        
        # 加密图片
        print(f"\n加密图片 {input_image}...")
        encrypt_file(input_image, encrypted_image, e, n)
        print(f"加密完成，已保存到 {encrypted_image}")
        
        # 解密图片
        print(f"\n解密图片到 {decrypted_image}...")
        decrypt_file(encrypted_image, decrypted_image, d, n)
        print(f"解密完成，已保存到 {decrypted_image}")
        
        print("\n请比较原始图片和解密后的图片是否相同")
    except FileNotFoundError:
        print("\n未找到测试图片文件，请确保文件路径正确")
    except Exception as e:
        print(f"\n图片处理过程中发生错误: {e}")
        
if __name__ == '__main__':
    main()
