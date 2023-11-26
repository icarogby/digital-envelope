from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from Crypto.Random import get_random_b

# Chave para RC4
key_rc4 = get_random_bytes()
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