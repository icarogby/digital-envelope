from Crypto.PublicKey import RSA
import os

try:
    os.makedirs("./keys/sender")
    os.makedirs("./keys/recipient")
except OSError as error:
    pass

keySize = 2048

key = RSA.generate(keySize)

privateKey = key.export_key("PEM", pkcs=8)
publicKey = key.public_key().export_key()

with open("./keys/sender/private_key_sender.pem", 'wb') as outputFile:
    outputFile.write(privateKey)

with open("./keys/sender/public_key_sender.pem", 'wb') as outputFile:
    outputFile.write(publicKey)

key = RSA.generate(keySize)

privateKey = key.export_key("PEM", pkcs=8)
publicKey = key.public_key().export_key()

with open("./keys/recipient/private_key_recipient.pem", "wb") as outputFile:
    outputFile.write(privateKey)

with open("./keys/recipient/public_key_recipient.pem", "wb") as outputFile:
    outputFile.write(publicKey)