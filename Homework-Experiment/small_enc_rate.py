from utils import rsa_decrypt, calc_d, load_data
from Crypto.Util.number import GCD, long_to_bytes, inverse
from gmpy2 import iroot


frame_no_list = [3, 8, 12, 16, 20]
N = []
c = []
for i in frame_no_list:
    N_, _, c_ = load_data(f"frames/Frame{ i }")
    N.append(N_)
    c.append(c_)
M = 1
for i in N:
    M *= i
M_ = []
for i in N:
    M_.append(M // i)
t = []
for i in range(len(N)):
    t.append(inverse(M_[i], N[i]))
x = 0
for i in range(len(N)):
    x += t[i] * c[i] * M_[i]
m, _ = iroot(x % M, 5)
print("m =", hex(m))
print(long_to_bytes(m)[-8:])