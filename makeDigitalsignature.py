import rsa

# Carregar a chave privada para assinar
with open('chave_privada.pem', mode='rb') as chave_privada_arquivo:
    chave_privada = rsa.PrivateKey.load_pkcs1(chave_privada_arquivo.read())

# String a ser assinada
mensagem = "Esta é a mensagem que será assinada."

# Assinar a mensagem
assinatura = rsa.sign(mensagem.encode('utf-8'), chave_privada, 'SHA-256')

# Salvar a assinatura em um arquivo
with open('assinatura.bin', 'wb') as arquivo_saida:
    arquivo_saida.write(assinatura)

print("Assinatura criada e salva no arquivo 'assinatura.bin'.")
