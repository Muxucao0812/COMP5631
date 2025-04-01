"""
This script compares the performance of three different methods for calculating modular exponentiation:
1. fast_exp: A classic implementation of the fast exponentiation algorithm, which uses binary decomposition to optimize the number of multiplications.
2. faster_exp: A more concise implementation of the fast exponentiation algorithm.
3. pow: The built-in Python function for modular exponentiation.
"""

import time



def fast_exp(alpha, i, p):
    """
    计算 alpha^i mod p，使用二进制分解优化乘法次数。
    
    参数:
        alpha: 底数
        i: 指数（正整数）
        p: 模数（素数）
    
    返回:
        alpha^i mod p
    """
    result = 1
    base = alpha % p
    
    # 当i为0时，直接返回1
    if i == 0:
        return 1
    
    # 使用经典快速幂算法 - 按位处理指数
    while i > 0:
        # 如果当前位是1，将当前累积的base计入结果
        if i & 1:
            result = (result * base) % p
        
        # 将base平方，准备处理下一位
        base = (base * base) % p
        
        # 右移一位，处理下一个二进制位
        i >>= 1
    
    return result


def faster_exp(alpha, i, p):
    """
    另一种实现快速幂的方法，更加简洁。
    """
    result = 1
    alpha = alpha % p
    
    while i > 0:
        if i % 2 == 1:
            result = (result * alpha) % p
        alpha = (alpha * alpha) % p
        i //= 2
        
    return result


def benchmark(base, exponent, modulus, iterations=100000):
    """性能基准测试"""
    # 测试fast_exp
    start_time = time.time()
    for _ in range(iterations):
        result1 = fast_exp(base, exponent, modulus)
    end_time = time.time()
    fast_exp_time = end_time - start_time
    
    # 测试faster_exp
    start_time = time.time()
    for _ in range(iterations):
        result2 = faster_exp(base, exponent, modulus)
    end_time = time.time()
    faster_exp_time = end_time - start_time
    
    # 测试内置pow
    start_time = time.time()
    for _ in range(iterations):
        result3 = pow(base, exponent, modulus)
    end_time = time.time()
    pow_time = end_time - start_time
    
    # 测试原始幂运算
    start_time = time.time()
    for _ in range(iterations):
        result4 = (base ** exponent) % modulus
    end_time = time.time()
    native_time = end_time - start_time
    
    # 验证结果正确性
    assert result1 == result2 == result3 == result4, "结果不一致"
    
    return {
        "fast_exp": fast_exp_time,
        "faster_exp": faster_exp_time,
        "pow": pow_time,
        "native": native_time
    }


if __name__ == "__main__":
    # 基本测试
    alpha = 3141
    i = 350000  # 35的二进制是100011
    p = 17
    
    print(f"计算 {alpha}^{i} mod {p}")
    result1 = fast_exp(alpha, i, p)
    result2 = faster_exp(alpha, i, p)
    result3 = pow(alpha, i, p)
    result4 = alpha ** i % p
    
    print(f"fast_exp 结果: {result1}")
    print(f"faster_exp 结果: {result2}")
    print(f"内置pow 结果: {result3}")
    print(f"直接计算 结果: {result4}")
    
    # 性能测试 - 小数
    print("\n小数性能测试")
    results = benchmark(3, 35, 17, iterations=10)
    print(f"fast_exp: {results['fast_exp']:.6f}秒")
    print(f"faster_exp: {results['faster_exp']:.6f}秒")
    print(f"内置pow: {results['pow']:.6f}秒")
    print(f"直接计算: {results['native']:.6f}秒")
    
    # 性能测试 - 大数
    print("\n大数性能测试")
    results = benchmark(1289, 987654321, 2147483647, iterations=10)
    print(f"fast_exp: {results['fast_exp']:.6f}秒")
    print(f"faster_exp: {results['faster_exp']:.6f}秒")
    print(f"内置pow: {results['pow']:.6f}秒")
    print(f"直接计算: {results['native']:.6f}秒")