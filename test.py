from Crypto.Hash import SHA256

# Mensagem a ser hashada
message = b"Minha mensagem secreta para o hash"
m = b'Minha mensagem secreta par o hash'

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
