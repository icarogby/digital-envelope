from digitalEnvelope import makeDigitalEnvelope, openDigitalEnvelope
import rsa 

msg = 'Hello world!'.encode('utf-8')

# Carregar a chave pública
with open('chave_publica_remetente.pem', mode='rb') as chave_publica_arquivo:
    chave_publica_remetente = rsa.PublicKey.load_pkcs1(chave_publica_arquivo.read())

# Carregar a chave privada
with open('chave_privada_destinatario.pem', mode='rb') as chave_privada_arquivo:
    chave_privada_destinatario = rsa.PrivateKey.load_pkcs1(chave_privada_arquivo.read())

# Carregar a chave pública
with open('chave_publica_destinatario.pem', mode='rb') as chave_publica_arquivo:
    chave_publica_destinatario = rsa.PublicKey.load_pkcs1(chave_publica_arquivo.read())

# Carregar a chave privada
with open('chave_privada_remetente.pem', mode='rb') as chave_privada_arquivo:
    chave_privada_remetente = rsa.PrivateKey.load_pkcs1(chave_privada_arquivo.read())

# makeDigitalEnvelope(msg, chave_publica_destinatario, chave_privada_remetente, "AES", 16)

with open('encryptedKey.dekey', mode='rb') as encryptedKeyFile:
    encryptedKey = encryptedKeyFile.read()

with open('encryptedSignedMessage.txt', mode='r') as encryptedSignedMessageFile:
    encryptedSignedMessage = encryptedSignedMessageFile.read()

x = openDigitalEnvelope('encryptedKey.dekey', 'encryptedSignedMessage.txt', chave_privada_destinatario, chave_publica_remetente, "AES")
print(x.decode('utf-8'))
