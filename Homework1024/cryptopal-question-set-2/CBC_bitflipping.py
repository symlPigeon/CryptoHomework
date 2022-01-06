from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, getRandomInteger


key = long_to_bytes(getRandomInteger(128))
iv = long_to_bytes(getRandomInteger(64))
pre = b"comment1=cooking%20MCs;userdata="
suf = b";comment2=%20like%20a%20pound%20of%20bacon"


def pkcs7(plain_text: bytes) -> bytes:
    block_size = AES.block_size
    # PKCS7 padding
    if len(plain_text) % block_size != 0:
        padding = chr(block_size - len(plain_text) % block_size).encode()
        plain_text += padding * (block_size - len(plain_text) % block_size)
    return plain_text


def add_iv_to_64bit(iv: bytes) -> bytes:
    assert len(iv) <= 16, "iv is too long!"
    while len(iv) < 16:
        iv += b"\0"
    return iv


def add_key_to_128bit(key: bytes) -> bytes:
    assert len(key) <= 16, "key is too long!"
    while len(key) < 16:
        key += b"\0"
    return key


def bytes_xor(a: bytes, b: bytes) -> bytes:
    result = b""
    for b1, b2 in zip(a, b):
        result += bytes([b1 ^ b2])
    return result


def AES_encrypt_CBC(plain_text: bytes, key: bytes, iv: bytes) -> bytes:
    plain_text = pkcs7(plain_text)
    key = add_key_to_128bit(key)
    iv = add_iv_to_64bit(iv)
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(plain_text)
    return ct


def AES_decrypt_CBC(cipher_text: bytes, key: bytes, iv: bytes) -> bytes:
    key = add_key_to_128bit(key)
    iv = add_iv_to_64bit(iv)
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(cipher_text)
    # removing padding
    if plaintext[-1] < 20:
        plaintext = plaintext[:len(plaintext) - plaintext[-1]]
    return plaintext


def encrypt(plain_text: bytes) -> bytes:
    plain_text = plain_text.replace(b";", b"%3B").replace(b"=", b"%3D")
    plain_text = pre + plain_text + suf
    return AES_encrypt_CBC(plain_text, key, iv)


def is_admin(plain_text: bytes) -> bool:
    l = plain_text.split(b";")
    for i in l:
        if i == b"admin=true":
            return True
    return False


def decrypt(ct: bytes) -> bool:
    plain_text = AES_decrypt_CBC(ct, key, iv)
    return is_admin(plain_text)


padding = b"A" * 16
data = encrypt(padding)
print("user input: ", padding.decode())
print("AES CBC encrypt: ", data)
AES_prefix = data[0 : len(pre)]
AES_payload = data[len(pre) : len(pre) + len(padding)]
AES_suffix = data[len(pre) + len(padding):]
AES_payload = bytes_xor(bytes_xor(AES_payload, b';comment2=%20lik'), b';admin=true;xxx=')
print("AES_PAYLOAD:", AES_payload)
if decrypt(AES_prefix + AES_payload + AES_suffix):
    print("IS ADMIN")
else:
    print("NOT ADMIN")