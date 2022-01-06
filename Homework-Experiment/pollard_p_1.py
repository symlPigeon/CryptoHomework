from utils import rsa_decrypt, calc_d, load_data
from Crypto.Util.number import GCD, long_to_bytes
import random


def pollard_p_1(n: int):
    a = 2
    k = 1
    while k <= 200000:
        a = pow(a, k, n)
        p = GCD(a - 1, n)
        if 1 < p < n:
            q = n // p
            return p, q
        k += 1
    return None, None

def solve(frame_no):
    print("\n####### Frame {} #######".format(frame_no))
    N, e, c = load_data(f"frames/Frame{ frame_no }")
    p, q = pollard_p_1(N)
    print('N =', hex(N))
    print('e =', hex(e))
    print('c =', hex(c))
    if not p or not q:
        return
    print("p =", hex(p))
    print("q =", hex(q))
    d = calc_d(p, q, e, N)
    print("d =", d)
    m = rsa_decrypt(c, N, d)
    print("m =", m)
    print(long_to_bytes(m)[-8:])

solve(2)
solve(6)
solve(19)