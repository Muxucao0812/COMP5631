from collections import Counter

# 标准英语字母频率
english_freq = {
    'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 12.7,
    'F': 2.2, 'G': 2.0, 'H': 6.1, 'I': 6.7, 'J': 0.2,
    'K': 0.8, 'L': 4.0, 'M': 2.4, 'N': 6.7, 'O': 7.5,
    'P': 1.9, 'Q': 0.1, 'R': 6.0, 'S': 6.3, 'T': 9.1,
    'U': 2.8, 'V': 1.0, 'W': 2.4, 'X': 0.2, 'Y': 2.0,
    'Z': 0.1
}

def calculate_frequency(ciphertext):
    # 计算密文中每个字母的频率
    ciphertext = ciphertext.upper().replace(" ", "")
    total_letters = len(ciphertext)
    freq = Counter(ciphertext)
    for letter in freq:
        freq[letter] = (freq[letter] / total_letters) * 100
    return freq

def map_letters(cipher_freq, english_freq):
    # 将密文字母映射到标准英语字母频率
    cipher_sorted = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
    english_sorted = sorted(english_freq.items(), key=lambda x: x[1], reverse=True)
    
    mapping = {}
    for i in range(min(len(cipher_sorted), len(english_sorted))):
        mapping[cipher_sorted[i][0]] = english_sorted[i][0]
    return mapping

def decrypt(ciphertext, mapping):
    # 根据映射解密文本
    plaintext = ""
    for char in ciphertext.upper():
        if char in mapping:
            plaintext += mapping[char]
        else:
            plaintext += char
    return plaintext

# 示例密文
cipher_pth = "ciphertext.txt"
with open(cipher_pth, "r") as f:
    ciphertext = f.read()
print("Ciphertext:", ciphertext)

# 计算频率
cipher_freq = calculate_frequency(ciphertext)
print("Ciphertext Frequency:", cipher_freq)

# 映射字母
mapping = map_letters(cipher_freq, english_freq)
print("Mapping:", mapping)

# 解密
plaintext = decrypt(ciphertext, mapping)
print("Decrypted Text:", plaintext)

# 保存解密文本
with open("plaintext.txt", "w") as f:
    f.write(plaintext)

