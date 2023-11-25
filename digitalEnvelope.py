# Criar um envelope assinado
# § Entrada: arquivo em claro + arquivo da chave RSA pública do destinatário + arquivo da
# chave RSA privada do remetente + algoritmo simétrico (AES / DES / RC4) e tamanho da
# chave (quando possível)
# § Processamento: Gerar chave simétrica temporária/aleatória. Cifrar arquivo em claro com
# a chave gerada. Assinar o arquivo criptografado com a chave privada do remetente. Cifrar a
# chave temporária com a chave do destinatário.
# § Saída: dois arquivos (Um com a chave de seção criptografada e outro do arquivo
# criptografado assinado).

# Abrir um envelope assinado
# § Entrada: arquivos com a mensagem assinada e a chave criptografada + arquivo da chave
# RSA privada do destinatário + arquivo da chave RSA pública do emissor + algoritmo
# simétrico (AES / DES / RC4)
# § Processamento: Abrir o envelope, decifrando e verificando a assinatura do mesmo.
# § Saída: arquivo decifrado e validade ou não da assinatura.

import rsa
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii
# todo mudar para bit e n bytes no tamanho da chave
def makeDigitalEnvelope(plainText: bytes, recipientPublicKey: bytes, senderPrivateKey, symmetricAlgorithm: str, symmetricKeySize: int):
    """
    plainText -> The plain text to be encrypted.
    recipientPublicKey -> The recipient's public key to encrypt the symmetric key.
    privateKeyFile -> The sender's private key to sign the encrypted message.
    symmetricAlgorithm -> The symmetric algorithm to be used.
    symmetricKeySize -> The symmetric key size (for AES and RC4).
    """

    # Generate a random symmetric key and encrypt plainText with it:
    match symmetricAlgorithm:
        case "DES":
            symmetricKey = get_random_bytes(8) # 64 bits key with 56 bits of entropy

            cipher = DES.new(symmetricKey, DES.MODE_CBC) # Create a DES cipher object

            cipherText = cipher.encrypt(pad(plainText, DES.block_size)) # Encrypt the plain text

        case "AES":
            symmetricKey = get_random_bytes(symmetricKeySize) # 128, 192 or 256 bits key

            cipher = AES.new(symmetricKey, AES.MODE_CBC, bytes([0, 1, 2, 3, 4, 5, 6, 7,8,9,10,11,12,13,14,15])) # Create an AES cipher object (CBC mode

            cipherText = cipher.encrypt(pad(plainText, AES.block_size))

        case "RC4":
            symmetricKey = get_random_bytes(symmetricKeySize) # 40 to 2048 bits key
            
            cipher = ARC4.new(symmetricKey)

            cipherText = cipher.encrypt(plainText)

        case _:
            raise ValueError("Invalid symmetric algorithm.")
        
    # Sign the cipher text with the sender's private key:
    signature = rsa.sign(cipherText, senderPrivateKey, 'SHA-256')

    # Encrypt the symmetric key with the recipient's public key:
    encryptedKey = rsa.encrypt(symmetricKey, recipientPublicKey)

    # save the encrypted session key to a file
    with open('encryptedKey.dekey', 'wb') as outputFile:
        outputFile.write(encryptedKey)

    # save the encrypted signed message to a file
    with open('encryptedSignedMessage.txt', 'w') as outputFile:
        outputFile.write('--- BEGUIN SIGNATURE ---\n\n' + signature.hex() + '\n\n--- END SIGNATURE ---\n\n--- BEGUIN CIPHER TEXT ---\n\n' + cipherText.hex() + '\n\n--- END CIPHER TEXT ---\n')

def openDigitalEnvelope(encryptedKeyFile: str, encryptedSignedMessageFile: str, recipientPrivateKey: bytes, senderPublicKey: bytes, symmetricAlgorithm: str):
    """
    encryptedKeyFile -> The encrypted symmetric key file.
    encryptedSignedMessageFile -> The encrypted signed message file.
    recipientPrivateKey -> The recipient's private key to decrypt the symmetric key.
    senderPublicKey -> The sender's public key to verify the signature.
    symmetricAlgorithm -> The symmetric algorithm to be used.
    """

    # Read the encrypted symmetric key from the file:
    with open(encryptedKeyFile, 'rb') as inputFile:
        encryptedKey = inputFile.read()

    # Read the encrypted signed message from the file:
    with open(encryptedSignedMessageFile, 'r') as inputFile:
        encryptedSignedMessage = inputFile.read()

    # Split the encrypted signed message into signature and cipher text:
    signature = binascii.unhexlify(encryptedSignedMessage.split('--- END SIGNATURE ---')[0].split('--- BEGUIN SIGNATURE ---')[1].strip())
    cipherText = binascii.unhexlify(encryptedSignedMessage.split('--- END CIPHER TEXT ---')[0].split('--- BEGUIN CIPHER TEXT ---')[1].strip())

    # Decrypt the symmetric key with the recipient's private key:
    symmetricKey = rsa.decrypt(encryptedKey, recipientPrivateKey)

    # Verify the signature with the sender's public key:
    if rsa.verify(cipherText, signature, senderPublicKey):
        print("The signature is authentic.")
    else:
        print("The signature is not authentic.")

    # Decrypt the cipher text with the symmetric key:
    match symmetricAlgorithm:
        case "DES":
            cipher = DES.new(symmetricKey, DES.MODE_CBC)

            plainText = unpad(cipher.decrypt(cipherText), DES.block_size)

        case "AES":
            cipher = AES.new(symmetricKey, AES.MODE_CBC, bytes([0, 1, 2, 3, 4, 5, 6, 7,8,9,10,11,12,13,14,15]))
            print(cipherText)
            plainText = unpad(cipher.decrypt(cipherText), AES.block_size)

        case "RC4": 
            cipher = ARC4.new(symmetricKey)

            plainText = cipher.decrypt(cipherText)

        case _:
            raise ValueError("Invalid symmetric key size.")

    return plainText