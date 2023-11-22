
# Criar um envelope assinado
# § Entrada: arquivo em claro + arquivo da chave RSA pública do destinatário + arquivo da
# chave RSA privada do remetente + algoritmo simétrico (AES / DES / RC4) e tamanho da
# chave (quando possível)
# § Processamento: Gerar chave simétrica temporária/aleatória. Cifrar arquivo em claro com
# a chave gerada. Assinar o arquivo criptografado com a chave privada do remetente. Cifrar a
# chave temporária com a chave do destinatário.
# § Saída: dois arquivos (Um com a chave de seção criptografada e outro do arquivo
# criptografado assinado).

from Crypto.Hash import SHA256
from Crypto.Cipher import AES, DES, ARC4
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

print('\n\nCHAVE SIMÉTRICA AES\n\n')
# Chave AES de 128 bits (16 bytes)
key = get_random_bytes(16)

print("\n\nChave:", key, "\n\n\n")

# Mensagem a ser criptografada
message = b"Minha mensagem secreta"

# Criando um objeto AES com o modo CBC
cipher_aes = AES.new(key, AES.MODE_CBC)

# Criptografando a mensagem
cipher_text = cipher_aes.encrypt(pad(message, AES.block_size))

print("Texto criptografado:", cipher_text, "\n\n\n")

# Descriptografando a mensagem
decipher_aes = AES.new(key, AES.MODE_CBC, cipher_aes.iv)
plain_text = unpad(decipher_aes.decrypt(cipher_text), AES.block_size)
print("Texto original:", plain_text)

print('\n\nCHAVE SIMÉTRICA DES\n\n')

####################################

# Chave DES de 8 bytes (56 bits)
key = get_random_bytes(8)
print("Chave DES:", key)

# Mensagem a ser criptografada (múltiplo de 8 bytes para DES)
message = b"Minha mensagem"

# Criando um objeto DES com o modo CBC
cipher_des = DES.new(key, DES.MODE_CBC)

# Criptografando a mensagem
cipher_text = cipher_des.encrypt(pad(message, DES.block_size))
print("Texto criptografado com DES:", cipher_text)

# Descriptografando a mensagem
decipher_des = DES.new(key, DES.MODE_CBC, cipher_des.iv)
plain_text = unpad(decipher_des.decrypt(cipher_text), DES.block_size)
print("Texto original com DES:", plain_text)

#####################################

print('\n\nCHAVE SIMÉTRICA RC4\n\n')

# Chave para RC4
key_rc4 = b"Chave secreta"
print("Chave RC4:", key_rc4)

# Mensagem a ser criptografada
message_rc4 = b"Minha mensagem secreta para RC4"

# Criando um objeto RC4
cipher_rc4 = ARC4.new(key_rc4)

# Criptografando a mensagem
cipher_text_rc4 = cipher_rc4.encrypt(message_rc4)
print("Texto criptografado com RC4:", cipher_text_rc4)

# Descriptografando a mensagem
decipher_rc4 = ARC4.new(key_rc4)
plain_text_rc4 = decipher_rc4.decrypt(cipher_text_rc4)
print("Texto original com RC4:", plain_text_rc4)

###################################

print('\n\nCHAVE ASSIMÉTRICA RSA\n\n')

# Gerando um par de chaves RSA
key = RSA.generate(2048)
print("Chave pública:", key.publickey().export_key())
print("Chave privada:", key.export_key())
# Criando objetos de criptografia e descriptografia
cipher = PKCS1_OAEP.new(key)
message = b"Minha mensagem secreta"
cipher_text = cipher.encrypt(message)
print(cipher_text)

plain_text = cipher.decrypt(cipher_text)
print(plain_text)

# Mensagem a ser hashada
message = b"Minha mensagem secreta para o hash"
m = b'Minha mensagem secreta para o hash'

# Criando um objeto de hash SHA-256
hash_object = SHA256.new()
ha = SHA256.new()

# Atualizando o objeto de hash com a mensagem
hash_object.update(message)
ha.update(m)

# Obtendo o hash da mensagem
hash_result = hash_object.digest()
h = ha.digest()
print("Hash SHA-256 da mensagem:", hash_result.hex())
print("Hash SHA-256 da mensagem:", h.hex())
