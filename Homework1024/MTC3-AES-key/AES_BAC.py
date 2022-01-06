import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import base64

mrz = "12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4"
# https://en.wikipedia.org/wiki/Machine-readable_passport
# passport number checksum 138%10 = 8, OK
pass_no = "12345678<"
check_digit1_9 = "8"
# birth no checksum 22%10 = 2, OK
birth = "111018"
check_digit14_19 = "2"
sex = "<" # unspecified
expiration_data = "111116"
# calc check digit on date domain
# date   : 1 1 1 1 1 6
# weight : 7 3 1 7 3 1
# mul    : 7+3+1+7+3+6 = 27 % 10 = 7
check_digit22_27 = "7" # unknown
check_digit_all = "4"

MRZ_inf = pass_no + check_digit1_9 + birth + check_digit14_19 + expiration_data + check_digit22_27
print("MRZ info: ", MRZ_inf)

key_seed = hashlib.sha1(MRZ_inf.encode()).hexdigest()[0:32]
d = key_seed + "00000001"
H_SHA1 = hashlib.sha1(long_to_bytes(int(d,16))).hexdigest()
ka = long_to_bytes(int(H_SHA1[0:32], 16))
Ka = ""

for i in range(16):
    a = bin(ka[i])[2:]
    while len(a) < 8:
        a = '0' + a
    if a[0:7].count("1") % 2 == 1:
        Ka += a[0:7] + "0"
    else:
        Ka += a[0:7] + "1"

print("Secret Key:", hex(int(Ka, 2))[2:])
AES_key = long_to_bytes(int(Ka, 2))

iv = b"\0" * 16
cipher = base64.b64decode(b"9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI")
aes = AES.new(AES_key, mode=AES.MODE_CBC, iv=iv)
message = aes.decrypt(cipher)
while message[-1] < 20:
    message = message[:-1]
print("message:", message.decode())