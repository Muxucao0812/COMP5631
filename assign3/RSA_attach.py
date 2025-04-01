#!/usr/bin/env python3
# RSA_attach.py - RSA加密攻击和分析工具

import math
import sympy
import gmpy2
import random
import time
from Crypto.Util.number import getPrime

def factorize_n(n):
    """尝试将模数N分解为质因数"""
    factors = sympy.factorint(n)
    return factors

def fermat_factorization(n, max_iterations=10000):
    """使用Fermat方法分解n (当p和q接近时效果好)"""
    a = math.isqrt(n)
    if a * a == n:
        return [a, a]
    
    for i in range(max_iterations):
        a += 1
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return [a - b, a + b]
    
    return None

def extended_gcd(a, b):
    """扩展欧几里得算法，返回(s, t, gcd)使得s*a + t*b = gcd(a,b)"""
    if a == 0:
        return 0, 1, b
    
    s, t, g = extended_gcd(b % a, a)
    return t - (b // a) * s, s, g

def common_modulus_attack(c1, c2, e1, e2, n):
    """共模攻击 - 当使用相同模数但不同指数加密相同消息时"""
    s1, s2, g = extended_gcd(e1, e2)
    
    if g != 1:
        raise ValueError("指数e1和e2必须互质")
    
    # 处理负指数情况
    if s1 < 0:
        s1 = -s1
        c1 = pow(c1, -1, n)
    
    if s2 < 0:
        s2 = -s2
        c2 = pow(c2, -1, n)
    
    # 计算明文
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m

def low_exponent_attack(c, e, n):
    """低指数攻击 - 当e较小且没有使用padding时"""
    m = gmpy2.iroot(c, e)
    if m[1]:  # 如果是完美的e次根
        return int(m[0])
    return None

def continued_fraction_expansion(num, denom):
    """计算分数num/denom的连分数展开"""
    expansion = []
    while denom:
        q = num // denom
        expansion.append(q)
        num, denom = denom, num - q * denom
    return expansion

def convergents_from_expansion(expansion):
    """从连分数展开计算渐进分数序列"""
    n = len(expansion)
    numerators = [0] * n
    denominators = [0] * n
    
    for i in range(n):
        if i == 0:
            numerators[i] = expansion[i]
            denominators[i] = 1
        elif i == 1:
            numerators[i] = expansion[i] * expansion[i-1] + 1
            denominators[i] = expansion[i]
        else:
            numerators[i] = expansion[i] * numerators[i-1] + numerators[i-2]
            denominators[i] = expansion[i] * denominators[i-1] + denominators[i-2]
    
    return list(zip(numerators, denominators))

def wiener_attack(e, n):
    """Wiener攻击 - 当私钥d很小时有效"""
    expansion = continued_fraction_expansion(e, n)
    convergents = convergents_from_expansion(expansion)
    
    for k, d in convergents:
        if k == 0:
            continue
            
        if e * d % k == 1:
            phi = (e * d - 1) // k
            b = n - phi + 1
            discriminant = b * b - 4 * n
            if discriminant >= 0:
                sqrt_disc = gmpy2.isqrt(discriminant)
                if sqrt_disc * sqrt_disc == discriminant:
                    p = (b + sqrt_disc) // 2
                    q = (b - sqrt_disc) // 2
                    if p * q == n:
                        return d, p, q
    
    return None, None, None

def hastad_broadcast_attack(ciphertexts, moduli, exponent):
    """Hastad广播攻击 - 当相同消息被多次使用小指数加密时"""
    if len(ciphertexts) < exponent:
        print("需要至少e个密文才能执行此攻击")
        return None
    
    c = ciphertexts[:exponent]
    n = moduli[:exponent]
    
    # 中国剩余定理实现
    N = 1
    for modulus in n:
        N *= modulus
    
    result = 0
    for i in range(exponent):
        Ni = N // n[i]
        si = pow(Ni, -1, n[i])
        result = (result + c[i] * si * Ni) % N
    
    # 计算e次根
    m = gmpy2.iroot(result, exponent)
    if m[1]:
        return int(m[0])
    
    return None

# RSA参数生成函数
def generate_prime_of_bits(bit_length):
    """生成指定位数的质数"""
    return getPrime(bit_length)

def generate_standard_rsa(bit_length):
    """生成标准RSA参数"""
    p_bits = bit_length // 2
    q_bits = bit_length - p_bits
    
    p = generate_prime_of_bits(p_bits)
    q = generate_prime_of_bits(q_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  # 标准RSA通常使用65537
    while math.gcd(e, phi) != 1:
        e += 2
    
    d = pow(e, -1, phi)
    
    return {
        'p': p,
        'q': q,
        'n': n,
        'phi': phi,
        'e': e,
        'd': d,
        'type': '标准RSA参数'
    }

def generate_close_factors_rsa(bit_length):
    """生成p和q接近的RSA参数 (适合Fermat分解)"""
    p_bits = bit_length // 2
    
    # 生成基础p
    p_base = generate_prime_of_bits(p_bits)
    
    # 生成接近p的q (差值很小)
    delta = random.randint(2, 1000)
    q_candidate = p_base + delta
    q = sympy.nextprime(q_candidate)
    
    n = p_base * q
    phi = (p_base - 1) * (q - 1)
    
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    
    d = pow(e, -1, phi)
    
    return {
        'p': p_base,
        'q': q,
        'n': n,
        'phi': phi,
        'e': e,
        'd': d,
        'type': '弱RSA参数 (p和q接近)'
    }

def generate_small_exponent_rsa(bit_length):
    """生成小公钥指数的RSA参数 (适合低指数攻击)"""
    p_bits = bit_length // 2
    q_bits = bit_length - p_bits
    
    p = generate_prime_of_bits(p_bits)
    q = generate_prime_of_bits(q_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # 使用小的公钥指数
    e = 3
    while math.gcd(e, phi) != 1:
        e += 2
    
    d = pow(e, -1, phi)
    
    return {
        'p': p,
        'q': q,
        'n': n,
        'phi': phi,
        'e': e,
        'd': d,
        'type': '弱RSA参数 (小公钥指数)'
    }

def generate_small_private_key_rsa(bit_length):
    """生成小私钥指数的RSA参数 (适合Wiener攻击)"""
    p_bits = bit_length // 2
    q_bits = bit_length - p_bits
    
    p = generate_prime_of_bits(p_bits)
    q = generate_prime_of_bits(q_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # 选择一个小的d，最大为n的1/4次方
    d = random.randint(2, int(n ** 0.25))
    
    # 确保d与phi互质
    while math.gcd(d, phi) != 1:
        d += 1
    
    # 计算e
    e = pow(d, -1, phi)
    
    return {
        'p': p,
        'q': q,
        'n': n,
        'phi': phi,
        'e': e,
        'd': d,
        'type': '弱RSA参数 (小私钥指数)'
    }

def generate_and_attack_rsa():
    """生成RSA参数并测试各种攻击方法"""
    print("\n选择RSA参数类型:")
    print("1. 标准RSA参数")
    print("2. 弱RSA参数 (p和q接近)")
    print("3. 弱RSA参数 (小公钥指数e)")
    print("4. 弱RSA参数 (小私钥指数d)")
    
    choice = input("选择参数类型 (1-4): ")
    bit_length = int(input("输入密钥总位数: "))
    
    # 生成参数
    if choice == '1':
        params = generate_standard_rsa(bit_length)
    elif choice == '2':
        params = generate_close_factors_rsa(bit_length)
    elif choice == '3':
        params = generate_small_exponent_rsa(bit_length)
    elif choice == '4':
        params = generate_small_private_key_rsa(bit_length)
    else:
        print("无效选择，使用标准参数")
        params = generate_standard_rsa(bit_length)
    
    # 显示生成的参数
    print("\nRSA参数生成成功 - " + params['type'])
    print("-" * 50)
    print(f"p = {params['p']} ({params['p'].bit_length()}位)")
    print(f"q = {params['q']} ({params['q'].bit_length()}位)")
    print(f"n = p * q = {params['n']} ({params['n'].bit_length()}位)")
    print(f"φ(n) = (p-1)(q-1) = {params['phi']}")
    print(f"公钥指数 e = {params['e']}")
    print(f"私钥指数 d = {params['d']}")
    print("\n公钥: (e, n) = ({}, {})".format(params['e'], params['n']))
    print("私钥: (d, n) = ({}, {})".format(params['d'], params['n']))
    
    # 创建测试消息
    m = random.randint(2, params['n'] - 1)
    print(f"\n生成随机测试消息: {m}")
    
    # 加密消息
    c = pow(m, params['e'], params['n'])
    print(f"加密后的密文: {c}")
    
    # 测试各种攻击
    print("\n开始测试各种攻击方法...\n")
    
    # 1. 直接因数分解
    print("1. 尝试直接因数分解...")
    start_time = time.time()
    try:
        if params['n'].bit_length() <= 64:  # 仅对小模数尝试
            factors = factorize_n(params['n'])
            end_time = time.time()
            print(f"分解成功: {factors}")
        else:
            print("模数太大，跳过直接因数分解")
            end_time = time.time()
    except Exception as e:
        end_time = time.time()
        print(f"分解失败: {e}")
    print(f"用时: {end_time - start_time:.4f}秒\n")
    
    # 2. Fermat分解
    print("2. 尝试Fermat分解...")
    start_time = time.time()
    max_iter = 1000 if params['n'].bit_length() > 40 else 10000
    factors = fermat_factorization(params['n'], max_iterations=max_iter)
    end_time = time.time()
    
    if factors:
        print(f"分解成功: p = {factors[0]}, q = {factors[1]}")
        recovered_d = pow(params['e'], -1, (factors[0]-1)*(factors[1]-1))
        recovered_m = pow(c, recovered_d, params['n'])
        print(f"恢复的明文: {recovered_m}")
        print(f"原始明文: {m}")
        print(f"明文恢复是否成功: {recovered_m == m}")
    else:
        print("分解失败，p和q可能相差较大")
    print(f"用时: {end_time - start_time:.4f}秒\n")
    
    # 3. 低指数攻击
    print("3. 尝试低指数攻击...")
    start_time = time.time()
    recovered_m = low_exponent_attack(c, params['e'], params['n'])
    end_time = time.time()
    
    if recovered_m:
        print(f"攻击成功，恢复明文: {recovered_m}")
        print(f"原始明文: {m}")
        print(f"明文恢复是否成功: {recovered_m == m}")
    else:
        print("攻击失败，e可能太大或密文不适合此攻击")
    print(f"用时: {end_time - start_time:.4f}秒\n")
    
    # 4. Wiener攻击
    print("4. 尝试Wiener攻击...")
    start_time = time.time()
    recovered_d, recovered_p, recovered_q = wiener_attack(params['e'], params['n'])
    end_time = time.time()
    
    if recovered_d:
        print(f"攻击成功，恢复私钥d: {recovered_d}")
        print(f"原始私钥d: {params['d']}")
        print(f"私钥恢复是否成功: {recovered_d == params['d']}")
        
        # 使用恢复的私钥解密
        recovered_m = pow(c, recovered_d, params['n'])
        print(f"使用恢复的私钥解密: {recovered_m}")
        print(f"原始明文: {m}")
        print(f"明文恢复是否成功: {recovered_m == m}")
    else:
        print("攻击失败，d可能不够小或者不满足Wiener攻击条件")
    print(f"用时: {end_time - start_time:.4f}秒\n")
    
    # 测试共模攻击
    if params['e'] < 100:  # 仅对小指数测试
        print("5. 测试共模攻击...")
        # 生成不同的指数但相同的模数
        e2 = params['e'] + 2
        while math.gcd(e2, params['phi']) != 1:
            e2 += 1
        
        # 使用不同指数加密相同消息
        c2 = pow(m, e2, params['n'])
        
        start_time = time.time()
        try:
            recovered_m = common_modulus_attack(c, c2, params['e'], e2, params['n'])
            end_time = time.time()
            
            print(f"攻击成功，恢复明文: {recovered_m}")
            print(f"原始明文: {m}")
            print(f"明文恢复是否成功: {recovered_m == m}")
        except Exception as e:
            end_time = time.time()
            print(f"攻击失败: {e}")
        print(f"用时: {end_time - start_time:.4f}秒\n")
    
    # 总结
    print("\n攻击测试总结")
    print("=" * 50)
    print(f"RSA参数类型: {params['type']}")
    print(f"模数位数: {params['n'].bit_length()}位")
    print(f"公钥指数 e: {params['e']}")
    print(f"私钥指数 d: {params['d']}")
    
    if choice == '1':
        print("\n评估: 标准RSA参数应该能抵抗所有常见攻击")
    elif choice == '2':
        print("\n评估: p和q接近的RSA应该容易被Fermat分解方法攻破")
    elif choice == '3':
        print("\n评估: 小公钥指数的RSA容易被低指数攻击或共模攻击破解")
    elif choice == '4':
        print("\n评估: 小私钥指数的RSA容易被Wiener攻击破解")

def main():
    print("RSA加密分析与攻击工具")
    print("=" * 40)
    print("1. 生成RSA参数并尝试不同攻击方法")
    print("2. 分解模数N")
    print("3. Fermat分解法")
    print("4. 低指数攻击")
    print("5. 共模攻击")
    print("6. Wiener攻击")
    print("7. Hastad广播攻击")
    
    choice = input("\n选择操作 (1-7): ")
    
    if choice == '1':
        generate_and_attack_rsa()
    
    elif choice == '2':
        n = int(input("输入模数N: "))
        print("尝试分解中...")
        factors = factorize_n(n)
        print(f"N的因子: {factors}")
    
    elif choice == '3':
        n = int(input("输入模数N: "))
        print("使用Fermat方法尝试分解...")
        factors = fermat_factorization(n)
        if factors:
            print(f"N的因子: p = {factors[0]}, q = {factors[1]}")
        else:
            print("分解失败，p和q可能相差较大")
    
    elif choice == '4':
        c = int(input("输入密文c: "))
        e = int(input("输入公钥指数e: "))
        n = int(input("输入模数N: "))
        print("尝试低指数攻击...")
        m = low_exponent_attack(c, e, n)
        if m:
            print(f"恢复的明文: {m}")
            print(f"十六进制表示: {hex(m)}")
        else:
            print("攻击失败，e可能太大或使用了填充")
    
    elif choice == '5':
        c1 = int(input("输入第一个密文c1: "))
        c2 = int(input("输入第二个密文c2: "))
        e1 = int(input("输入第一个指数e1: "))
        e2 = int(input("输入第二个指数e2: "))
        n = int(input("输入共同模数N: "))
        print("尝试共模攻击...")
        try:
            m = common_modulus_attack(c1, c2, e1, e2, n)
            print(f"恢复的明文: {m}")
            print(f"十六进制表示: {hex(m)}")
        except Exception as e:
            print(f"攻击失败: {e}")
    
    elif choice == '6':
        e = int(input("输入公钥指数e: "))
        n = int(input("输入模数N: "))
        print("尝试Wiener攻击...")
        d, p, q = wiener_attack(e, n)
        if d:
            print(f"恢复的私钥d: {d}")
            print(f"N的质因子: p = {p}, q = {q}")
        else:
            print("攻击失败，d可能不够小")
    
    elif choice == '7':
        num_ciphertexts = int(input("输入密文数量: "))
        e = int(input("输入所有加密使用的公钥指数e: "))
        
        ciphertexts = []
        moduli = []
        
        for i in range(num_ciphertexts):
            c = int(input(f"输入密文c{i+1}: "))
            n = int(input(f"输入模数N{i+1}: "))
            ciphertexts.append(c)
            moduli.append(n)
        
        m = hastad_broadcast_attack(ciphertexts, moduli, e)
        if m:
            print(f"恢复的明文: {m}")
            print(f"十六进制表示: {hex(m)}")
        else:
            print("攻击失败")

if __name__ == "__main__":
    main()
