from digitalEnvelope import makeDigitalEnvelope, openDigitalEnvelope
from Crypto.PublicKey import RSA

msg = 'Hello world!'.encode('utf-8')

# Carregar a chave pública
with open('./keys/sender/public_key_sender.pem', mode='rb') as chave_publica_arquivo:
    chave_publica_remetente = RSA.import_key(chave_publica_arquivo.read())

# Carregar a chave privada
with open('./keys/recipient/private_key_recipient.pem', mode='rb') as chave_privada_arquivo:
    chave_privada_destinatario = RSA.import_key(chave_privada_arquivo.read())

# Carregar a chave pública
with open('./keys/recipient/public_key_recipient.pem', mode='rb') as chave_publica_arquivo:
    chave_publica_destinatario = RSA.import_key(chave_publica_arquivo.read())

# Carregar a chave privada
with open('./keys/sender/private_key_sender.pem', mode='rb') as chave_privada_arquivo:
    chave_privada_remetente = RSA.import_key(chave_privada_arquivo.read())

x = 2

if x == 1:
    makeDigitalEnvelope(msg, chave_publica_destinatario, chave_privada_remetente, "AES", 16)

else:
    x = openDigitalEnvelope('encryptedKey.bin', 'encryptedSignedMessage.txt', chave_privada_destinatario, chave_publica_remetente, "AES")
    print(x.decode('utf-8'))
