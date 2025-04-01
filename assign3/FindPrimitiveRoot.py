from math import gcd

def prime_factors(n):
    """返回 n 的所有质因数集合"""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors

def is_primitive_root(g, p):
    """判断 g 是否是模 p 的原根"""
    phi = p - 1
    factors = prime_factors(phi)
    for q in factors:
        power = phi // q
        if pow(g, power, p) == 1:
            return False
    return True

def find_primitive_root(p):
    """找出模 p 的一个原根"""
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return None

if __name__ == "__main__":
    p = 13
    g = find_primitive_root(p)
    print(f"模 {p} 的一个原根是：{g}")

