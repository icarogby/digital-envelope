from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

plainText = bytes([0, 1, 2, 3, 4, 5, 6, 7])

vetor = get_random_bytes(16)

for i in vetor:
    print(i)

print('\n\n')
symmetricKeySize = 16

symmetricKey = get_random_bytes(symmetricKeySize) # 128, 192 or 256 bits key

cipher = AES.new(symmetricKey, AES.MODE_CBC, vetor)

cipherText = cipher.encrypt(pad(plainText, AES.block_size))

for i in plainText:
    print(i)

print('\n\n')

for i in pad(plainText, AES.block_size):
    print(i)

print('\n\n')

for i in cipherText:
    print(i)

cipher2 = AES.new(symmetricKey, AES.MODE_CBC, vetor)

plainText2 = cipher2.decrypt(cipherText)

print('\n\n')

for i in plainText2:
    print(i)

# plainText3 = unpad(cipher2.decrypt(cipherText), AES.block_size)

#print(plainText2)
