from digitalEnvelope import makeDigitalEnvelope, openDigitalEnvelope, makeKeys

msg = b'Hello World!'

x = 2

if x == 0:
    # Gerando as chaves
    chave_privada_remetente, chave_publica_remetente = makeKeys()
    chave_privada_destinatario, chave_publica_destinatario = makeKeys()

    # salvar chaves
    with open('chave_privada_remetente.pem', 'wb') as f:
        f.write(chave_privada_remetente)

    with open('chave_publica_remetente.pem', 'wb') as f:
        f.write(chave_publica_remetente)

    with open('chave_privada_destinatario.pem', 'wb') as f:
        f.write(chave_privada_destinatario)

    with open('chave_publica_destinatario.pem', 'wb') as f:
        f.write(chave_publica_destinatario)

elif x == 1:
    makeDigitalEnvelope(msg, 'chave_publica_destinatario.pem', 'chave_privada_remetente.pem', "AES", 128)

else:
    x = openDigitalEnvelope('encryptedKey.bin', 'encryptedSignedMessage.txt', 'chave_privada_destinatario.pem', 'chave_publica_remetente.pem', "AES")
    print(x.decode('utf-8'))
