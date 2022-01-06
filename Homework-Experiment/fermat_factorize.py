from math import ceil
from utils import load_data, calc_d, rsa_decrypt
from Crypto.Util.number import long_to_bytes
import gmpy2


def fermat_factorize(n: int):
    u = 2 * ceil(gmpy2.iroot(n, 2)[0])
    v = 0
    r = pow(u, 2) - pow(v, 2) - 4 * n
    while r != 0:
        if r >= 0:
            r -= 4 * v + 4
            v += 2
        else:
            r += 4 * u + 4
            u += 2
    p = (u + v) // 2
    q = (u - v) // 2
    return p, q


N, e, c = load_data('frames/Frame10')
print('N =', hex(N))
print('e =', hex(e))
print('c =', hex(c))
p, q = fermat_factorize(N)
print("p =", hex(p))
print("q =", hex(q))
if not p or not q:
    print('No factors found')
    exit(0)
d = calc_d(p, q, e, N)
print('d =', hex(d))
m = rsa_decrypt(c, N, d)
print('m =', hex(m))
print(long_to_bytes(m)[-8:])
