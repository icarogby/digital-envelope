import rsa

# Carregar a chave privada
with open('chave_privada.pem', mode='rb') as chave_privada_arquivo:
    chave_privada = rsa.PrivateKey.load_pkcs1(chave_privada_arquivo.read())

# Carregar a mensagem criptografada do arquivo
with open('mensagem_criptografada.bin', 'rb') as arquivo_entrada:
    mensagem_criptografada = arquivo_entrada.read()

# Descriptografar a mensagem
mensagem_descriptografada = rsa.decrypt(mensagem_criptografada, chave_privada).decode('utf-8')

print("Mensagem descriptografada:", mensagem_descriptografada)
