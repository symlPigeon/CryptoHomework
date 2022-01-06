from utils import load_data
from Crypto.Util.number import long_to_bytes, inverse


def exgcd(a, b):
    x1, x2, x3, y1, y2, y3 = 1, 0, a, 0, 1, b
    while y3 != 0:
        q = x3 // y3
        x1, x2, x3, y1, y2, y3 = y1, y2, y3, x1 - q * y1, x2 - q * y2, x3 - q * y3
    return x1, x2


def same_module_attack(e1, e2, c1, c2, N):
    x, y = exgcd(e1, e2)
    return (pow(c1, x, N) * pow(c2, y, N)) % N


N1, e1, c1 = load_data('frames/Frame0')
N2, e2, c2 = load_data('frames/Frame4')
print("N =", hex(N1))
print("e1 =", hex(e1))
print("e2 =", hex(e2))
print("c1 =", hex(c1))
print("c2 =", hex(c2))
m = same_module_attack(e1, e2, c1, c2, N1)
print("m =", hex(m))
print(long_to_bytes(m)[-8:])