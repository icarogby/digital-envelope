from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)

chave_publica = key.publickey().export_key()
chave_privada = key.export_key()

print(f"\n\nChave pública: {chave_publica}\n\n")
print(f"Chave privada: {chave_privada}\n\n")

# Criando objetos de criptografia e descriptografia

x = input('Digite a chave pública: ')
cipher = PKCS1_OAEP.new(x)

y = input('Digite a chave privada: ')
decipher = PKCS1_OAEP.new(y)

message = b"opa"

cipher_text = cipher.encrypt(message)

print('\n\n', cipher_text, '\n\n')

plain_text = decipher.decrypt(cipher_text)

print('\n\n', plain_text, '\n\n')