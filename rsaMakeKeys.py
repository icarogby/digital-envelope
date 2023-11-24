import rsa

# Gerar um par de chaves
(public_key, private_key) = rsa.newkeys(2048)

# Salvar a chave pública em um arquivo
with open('chave_publica.pem', 'wb') as chave_publica_arquivo:
    chave_publica_arquivo.write(public_key.save_pkcs1())

# Salvar a chave privada em um arquivo
with open('chave_privada.pem', 'wb') as chave_privada_arquivo:
    chave_privada_arquivo.write(private_key.save_pkcs1())

print("Par de chaves gerado e salvo nos arquivos 'chave_publica.pem' e 'chave_privada.pem'.")
