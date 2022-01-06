from Crypto.Util.number import GCD, inverse, long_to_bytes
from utils import calc_d, load_data, rsa_decrypt


N = []
e = []
c = []
for i in range(21):
    N_, e_, c_ = load_data('frames/Frame{}'.format(i))
    N.append(N_)
    e.append(e_)
    c.append(c_)
for i in range(20):
    for j in range(i + 1, 21):
        p = GCD(N[i], N[j])
        if p != 1:
            q1 = N[i] // p
            q2 = N[j] // p
            d1 = calc_d(p, q1, e[i], N[i])
            d2 = calc_d(p, q2, e[j], N[j])
            m1 = rsa_decrypt(c[i], N[i], d1)
            m2 = rsa_decrypt(c[j], N[j], d2)
            print(f"N{ i } = { hex(N[i]) }")
            print(f"N{ j } = { hex(N[j]) }")
            print(f"e{ i } = { hex(e[i]) }")
            print(f"e{ j } = { hex(e[j]) }")
            print(f"p = { hex(p) }")
            print(f"q{ i } = { hex(q1) }")
            print(f"q{ j } = { hex(q2) }")
            print(f"m{ i } = { hex(m1) }")
            print(f"m{ j } = { hex(m2) }")
            print(f"plain text { i } = { long_to_bytes(m1)[-8:] }")
            print(f"plain text { j } = { long_to_bytes(m2)[-8:] }")