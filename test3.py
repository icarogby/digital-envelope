import rsa

# Gerar chaves (tamanho de chave 2048 bits)
(public_key, private_key) = rsa.newkeys(2048)

print(f'\n\nChave pública: {public_key}\n\nChave privada: {private_key}\n\n')

# Mensagem a ser criptografada
message = b"Hello, RSA encryption!"

# Criptografar a mensagem com a chave pública
encrypted_message = rsa.encrypt(message, public_key)

# Descriptografar a mensagem usando a chave privada
decrypted_message = rsa.decrypt(encrypted_message, private_key)
rsa.sign(message, private_key, 'SHA-256')

print("\n\nMensagem original:\n", message)
print("\n\nMensagem criptografada:\n", encrypted_message)
print("\n\nMensagem descriptografada:\n", decrypted_message)
