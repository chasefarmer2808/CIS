import hashlib # for SHA1 hashing of keys
import hmac # for generating a hashed MAC

from Crypto.Cipher import AES
from Crypto import Random


def pad(msg, block_size):
    num_bytes = len(msg)

    if (num_bytes%block_size == 0):
        return msg

    pad_bytes = block_size - (len(msg) % block_size)

    msg += '\x08'
    msg = msg + chr(0)*(pad_bytes - 1)

    return msg

def unpad(msg):
    if (msg[-1] is not '\x00'):
        return msg

    pointer = len(msg) - 1

    while (msg[pointer] != '\x08'):
        pointer -= 1

    return msg[0:pointer]

def extract_iv(ciphertext):
    return ciphertext[0:16]

def extract_hmac(ciphertext):
    return ciphertext[16:36]

def extract_ciphertext(ciphertext):
    return ciphertext[36:]

key1 = 'test1'
key2 = 'test2'
msg = 'hello'
msg = pad(msg, AES.block_size)
#print("".join(hex(ord(s)) for s in msg))
#msg = unpad(msg)
#print("".join(hex(ord(s)) for s in msg))

hash1 = hashlib.sha1(key1).digest()
hash2 = hashlib.sha1(key2).digest()
key1 = hash1[0:16]
key2 = hash2[0:16]

my_hmac = hmac.new(key2, msg, hashlib.sha1).digest()
iv = Random.new().read(AES.block_size)

cipher = AES.new(key1, AES.MODE_CBC, iv)
ciphertext = iv +  my_hmac + cipher.encrypt(msg.encode())

sent_iv = extract_iv(ciphertext)
sent_hmac = extract_hmac(ciphertext)
print(sent_iv == iv)
print(hmac.compare_digest(sent_hmac, my_hmac))

decrypt = AES.new(key1, AES.MODE_CBC, sent_iv)
plaintext = extract_ciphertext(ciphertext)
print(plaintext)
print(len(plaintext))

plaintext = decrypt.decrypt(plaintext)
plaintext = unpad(plaintext)
print(plaintext)
