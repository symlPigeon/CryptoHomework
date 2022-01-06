import random
from typing import Union, Tuple

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, getRandomInteger
import base64


addition_m = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd" \
             "24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbi" \
             "BzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW9" \
             "1IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".encode())
global_key = long_to_bytes(getRandomInteger(128))
random_text = long_to_bytes(getRandomInteger(random.randint(256, 1024)))


def add_key_to_128bit(key: bytes) -> bytes:
    assert len(key) <= 16, "key is too long!"
    while len(key) < 16:
        key += b"\0"
    return key


def list_to_bytes(l):
    b = b""
    for i in l:
        b += chr(i).encode()
    return b


def bytes_to_list(b):
    l = []
    for i in b:
        l.append(i)
    return l


def add_iv_to_64bit(iv: bytes) -> bytes:
    assert len(iv) <= 16, "iv is too long!"
    while len(iv) < 16:
        iv += b"\0"
    return iv


def AES_encrypt_ECB(plain_text: bytes, key: bytes, b64enc: bool = False) -> Union[str, bytes]:
    '''

    :param plain_text:
    :param key:
    :param b64enc:
    :return:
    '''
    block_size = AES.block_size
    # PKCS7 padding
    if len(plain_text) % block_size != 0:
        padding = chr(block_size - len(plain_text) % block_size).encode()
        plain_text += padding * (block_size - len(plain_text) % block_size)
    key = add_key_to_128bit(key)
    cipher = AES.new(key, mode=AES.MODE_ECB)
    ct = cipher.encrypt(plain_text)
    if b64enc:
        return base64.b64encode(ct).decode()
    else:
        return ct


def AES_decrypt_ECB(cipher_text: bytes, key: bytes) -> Union[bytes, str]:
    key = add_key_to_128bit(key)
    cipher = AES.new(key, mode=AES.MODE_ECB)
    plaintext = cipher.decrypt(cipher_text)
    if plaintext[-1] < 20:
        plaintext = plaintext[:len(plaintext) - plaintext[-1]]
    return plaintext


def bytes_xor(a: bytes, b: bytes) -> bytes:
    result = b""
    for b1, b2 in zip(a, b):
        result += bytes([b1 ^ b2])
    return result


def target_ECB_hard(plain_text: bytes) -> bytes:
    """
    available to attacker
    """
    key = global_key
    plain_text = random_text + plain_text + addition_m
    return AES_encrypt_ECB(plain_text, key)


def detect_random_text_len(block_size: int) -> int:
    c1 = target_ECB_hard(b"")
    c2 = target_ECB_hard(b"A")
    index = 0
    for i in range(len(c1) // block_size):
        c1_t = c1[block_size * i : block_size * i + block_size]
        c2_t = c2[block_size * i: block_size * i + block_size]
        if c1_t != c2_t:
            index = i
            break
    size = 1
    while size < 16:
        c1 = target_ECB_hard(b"A" * size)
        c2 = target_ECB_hard(b"A" * (size - 1))
        c1_t = c1[block_size * index: block_size * index + block_size]
        c2_t = c2[block_size * index: block_size * index + block_size]
        if c1_t == c2_t:
            break
        size += 1
    return index * 16 + (16 - size + 1)



def detect_len() -> Tuple[int, int, int]:
    ulen = len(target_ECB_hard(b""))
    p1 = p2 = ''
    l1 = l2 = ulen
    while l1 == l2:
        p1 += 'A'
        l2 = len(target_ECB_hard(p1.encode()))
    l1 = l2
    while l1 == l2:
        p2 += 'A'
        l2 = len(target_ECB_hard((p1 + p2).encode()))
    # 返回：unknown-string长度，填充长度，加密块大小
    return (ulen - (len(p1) - 1), len(p1) - 1, len(p2))



def byte_at_a_time_ECB_decrypt() -> str:
    m_len, _, block_size = detect_len()
    random_len= detect_random_text_len(block_size)
    random_index = random_len // block_size
    padding_size =block_size - random_len % block_size
    recovered_list = [0 for i in range(padding_size - 1 + block_size)]
    try:
        for i in range(m_len):
            d = {}
            for j in range(256):
                m = recovered_list[i: i + block_size - 1 + padding_size]
                m.append(j)
                m = list_to_bytes(m)
                c = target_ECB_hard(m)[(random_index + 1) * block_size: (random_index + 2) * block_size]
                d[c] = m
            m = [0 for j in range(block_size - i % block_size - 1 + padding_size)]
            c = target_ECB_hard(list_to_bytes(m))[block_size * (i // block_size + random_index + 1): block_size * (i // block_size + 2 + random_index)]
            recovered_list.append(d[c][-1])
    except:
        pass
    ans = list_to_bytes(recovered_list[padding_size - 1 + block_size:])
    if ans[-1] < 20:
        plaintext = ans[:len(ans) - ans[-1]]
    return ans.decode()



print(byte_at_a_time_ECB_decrypt())

