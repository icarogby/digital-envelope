with open('encryptedSignedMessage.depak', 'r') as inputFile:
    encryptedSignedMessage = inputFile.read()

# Split the encrypted signed message into signature and cipher text:
signature = encryptedSignedMessage.split('--- END SIGNATURE ---')[0].split('--- BEGUIN SIGNATURE ---')[1].strip()
cipherText = encryptedSignedMessage.split('--- END CIPHER TEXT ---')[0].split('--- BEGUIN CIPHER TEXT ---')[1].strip()

# signature = bytes.fromhex(signature)
# cipherText = bytes.fromhex(cipherText)

print(signature)
print('\n\n\n\n')
print(cipherText)

# Verify the signature with the sender's public key: