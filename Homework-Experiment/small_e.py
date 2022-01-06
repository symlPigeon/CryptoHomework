from utils import load_data
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes


i = input()
N, e, c = load_data(f'frames/Frame{ i }')
k = 0
while True:
    m, state = iroot(c + k * N, e)
    if state:
        print(long_to_bytes(m)[-8:])
        break