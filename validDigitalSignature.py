import rsa

# Carregar a chave pública para verificar a assinatura
with open('chave_publica.pem', mode='rb') as chave_publica_arquivo:
    chave_publica = rsa.PublicKey.load_pkcs1(chave_publica_arquivo.read())

# String original
mensagem_original = "Esta é a mensagem que será assinada."

# Carregar a assinatura a ser verificada
with open('assinatura.bin', 'rb') as arquivo_entrada:
    assinatura = arquivo_entrada.read()

# Verificar a assinatura
try:
    rsa.verify(mensagem_original.encode('utf-8'), assinatura, chave_publica)
    print("A assinatura é válida. A mensagem não foi alterada.")
except rsa.pkcs1.VerificationError:
    print("A assinatura é inválida. A mensagem foi alterada ou a chave pública não corresponde à assinatura.")
