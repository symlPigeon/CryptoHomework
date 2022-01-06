from typing import Tuple
from Crypto.Util.number import inverse

def load_data(frame_file_name: str) -> Tuple[int, int, int]:
    '''
    Load data (N, e, c) from frame file.
    '''
    f = open(frame_file_name, 'r')
    hex_str = f.read()
    f.close()
    N = int(hex_str[0:1024//4], 16)
    e = int(hex_str[1024//4:2048//4], 16)
    c = int(hex_str[2048//4:], 16)
    return N, e, c


def rsa_decrypt(c: int, N: int, d: int) -> int:
    return pow(c, d, N)


def rsa_encrypt(m: int, N: int, e: int) -> int:
    return pow(m, e, N)


def calc_d(p: int, q: int, e: int, N: int) -> int:
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return d