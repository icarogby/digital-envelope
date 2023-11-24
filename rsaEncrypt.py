import rsa

# String a ser criptografada
mensagem = "Esta é uma mensagem secreta."

# Carregar a chave pública
with open('chave_publica.pem', mode='rb') as chave_publica_arquivo:
    chave_publica = rsa.PublicKey.load_pkcs1(chave_publica_arquivo.read())

# Criptografar a mensagem
mensagem_criptografada = rsa.encrypt(mensagem.encode('utf-8'), chave_publica)

# Salvar a mensagem criptografada em um arquivo
with open('mensagem_criptografada.bin', 'wb') as arquivo_saida:
    arquivo_saida.write(mensagem_criptografada)

print("Mensagem criptografada e salva no arquivo 'mensagem_criptografada.bin'.")
