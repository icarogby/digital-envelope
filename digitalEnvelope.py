from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

def makeKeys():
    keySize = 2048

    key = RSA.generate(keySize)

    privateKey = key.export_key("PEM", pkcs=8)
    publicKey = key.public_key().export_key()

    return privateKey, publicKey

def makeDigitalEnvelope(plainText: bytes, recipientPublicKey: str, senderPrivateKey: str, symmetricAlgorithm: str, symmetricKeySizeInBits: int = None):
    """
    plainText -> The plain text to be encrypted.
    recipientPublicKey -> The recipient's public key to encrypt the symmetric key.
    privateKeyFile -> The sender's private key to sign the encrypted message.
    symmetricAlgorithm -> The symmetric algorithm to be used.
    symmetricKeySize -> The symmetric key size (for AES and RC4).
    """

    try:
        with open(recipientPublicKey, mode='rb') as chave_publica_arquivo:
            recipientPublicKey = RSA.import_key(chave_publica_arquivo.read())
    except:
        raise ValueError("Invalid recipient public key file.")
    
    try:
        with open(senderPrivateKey, mode='rb') as chave_privada_arquivo:
            senderPrivateKey = RSA.import_key(chave_privada_arquivo.read())

    except:
        raise ValueError("Invalid sender private key file.")
    
    # Verify the symmetric key size:
    if symmetricAlgorithm == "DES":
        if symmetricKeySizeInBits != None:
            raise ValueError("Not necessary to specify the symmetric key size for DES.")
        
        symmetricKeySizeInBytes = 8

    elif symmetricAlgorithm == "AES":
        if symmetricKeySizeInBits not in [128, 192, 256]:
            raise ValueError("Invalid symmetric key size.")
        
        symmetricKeySizeInBytes = symmetricKeySizeInBits // 8
        
    elif symmetricAlgorithm == "RC4":
        if symmetricKeySizeInBits not in range(320, 2049):
            raise ValueError("Invalid symmetric key size.")
        
        symmetricKeySizeInBytes = symmetricKeySizeInBits // 8
    else:
        raise ValueError("Invalid symmetric algorithm.")

    # Generate a random symmetric key and encrypt plainText with it:
    match symmetricAlgorithm:
        case "DES":
            symmetricKey = get_random_bytes(8) # 64 bits key with 56 bits of entropy

            cipher = DES.new(symmetricKey, DES.MODE_CBC) # Create a DES cipher object

            cipherText = cipher.encrypt(pad(plainText, DES.block_size)) # Encrypt the plain text

        case "AES":
            symmetricKey = get_random_bytes(symmetricKeySizeInBytes) # 128, 192 or 256 bits key

            cipher = AES.new(symmetricKey, AES.MODE_CBC) # Create an AES cipher object (CBC mode

            cipherText = cipher.encrypt(pad(plainText, AES.block_size))

        case "RC4":
            symmetricKey = get_random_bytes(symmetricKeySizeInBytes) # 40 to 2048 bits key
            
            cipher = ARC4.new(symmetricKey)

            cipherText = cipher.encrypt(plainText)

        case _:
            raise ValueError("Invalid symmetric algorithm.")

    try: 
        # Sign the cipher text with the sender's private key:
        hash = SHA256.new(cipherText)
        signature = pkcs1_15.new(senderPrivateKey).sign(hash)
    except:
        raise ValueError("Signature error.")
    
    try:
        # Encrypt the symmetric key with the recipient's public key:
        rsaCipher = PKCS1_OAEP.new(recipientPublicKey)
        encryptedKey = rsaCipher.encrypt(symmetricKey)
    except:
        raise ValueError("Symmetric key encryption error.")

    try:
        # save the encrypted session key to a file
        with open('encryptedKey.bin', 'wb') as outputFile:
            outputFile.write(encryptedKey)
    except:
        raise ValueError("Error writing to encryptedKey.bin.")

    # save the encrypted signed message to a file
    encryptedSignedMessage = '----BEGUIN SIGNATURE----\n\n' + signature.hex() + '\n\n----END SIGNATURE----\n\n----BEGUIN CIPHER TEXT----\n\n' + cipherText.hex() + '\n\n----END CIPHER TEXT----'

    if symmetricAlgorithm == "DES" or symmetricAlgorithm == "AES":
        encryptedSignedMessage += '\n\n----BEGUIN IV----\n\n' + cipher.iv.hex() + '\n\n----END IV----'
    
    try:
        with open('encryptedSignedMessage.txt', 'w') as outputFile:
            outputFile.write(encryptedSignedMessage)
    except:
        raise ValueError("Error writing to encryptedSignedMessage.txt.")

def openDigitalEnvelope(encryptedKeyFile: str, encryptedSignedMessageFile: str, recipientPrivateKey: str, senderPublicKey: str, symmetricAlgorithm: str):
    """
    encryptedKeyFile -> The encrypted symmetric key file.
    encryptedSignedMessageFile -> The encrypted signed message file.
    recipientPrivateKey -> The recipient's private key to decrypt the symmetric key.
    senderPublicKey -> The sender's public key to verify the signature.
    symmetricAlgorithm -> The symmetric algorithm to be used.
    """

    try:
        # Read the encrypted symmetric key from the file:
        with open(encryptedKeyFile, 'rb') as inputFile:
            encryptedKey = inputFile.read()
    except:
        raise ValueError("Invalid encrypted symmetric key file.")

    try:
        # Read the encrypted signed message from the file:
        with open(encryptedSignedMessageFile, 'r') as inputFile:
            encryptedSignedMessage = inputFile.read()
    except:
        raise ValueError("Invalid encrypted signed message file.")
    
    try:
        with open(recipientPrivateKey, mode='rb') as chave_privada_arquivo:
            recipientPrivateKey = RSA.import_key(chave_privada_arquivo.read())
    except:
        raise ValueError("Invalid recipient private key file.")
    
    try:
        with open(senderPublicKey, mode='rb') as chave_publica_arquivo:
            senderPublicKey = RSA.import_key(chave_publica_arquivo.read())
    except:
        raise ValueError("Invalid sender public key file.")

    try:
        # Split the encrypted signed message into signature and cipher text:
        signature = binascii.unhexlify(encryptedSignedMessage.split('----END SIGNATURE----')[0].split('----BEGUIN SIGNATURE----')[1].strip())
        cipherText = binascii.unhexlify(encryptedSignedMessage.split('----END CIPHER TEXT----')[0].split('----BEGUIN CIPHER TEXT----')[1].strip())
        
        # Split the cipher text into cipher text and IV:
        if symmetricAlgorithm == "DES" or symmetricAlgorithm == "AES":
            iv = binascii.unhexlify(encryptedSignedMessage.split('----END IV----')[0].split('----BEGUIN IV----')[1].strip())
    except:
        raise ValueError("Invalid encrypted signed message file.")
        
    try:
        # Decrypt the symmetric key with the recipient's private key:
        rsaDecipher = PKCS1_OAEP.new(recipientPrivateKey)
        symmetricKey = rsaDecipher.decrypt(encryptedKey)
    except:
        raise ValueError("Invalid encrypted symmetric key file.")

    # Verify the signature with the sender's public key:
    try:
        pkcs1_15.new(senderPublicKey).verify(SHA256.new(cipherText), signature)
    except:
        raise ValueError("Invalid signature.")

    try:
        # Decrypt the cipher text with the symmetric key:
        match symmetricAlgorithm:
            case "DES":
                cipher = DES.new(symmetricKey, DES.MODE_CBC, s1)

                plainText = unpad(cipher.decrypt(cipherText), DES.block_size)

            case "AES":
                cipher = AES.new(symmetricKey, AES.MODE_CBC, iv)

                plainText = unpad(cipher.decrypt(cipherText), AES.block_size)

            case "RC4": 
                cipher = ARC4.new(symmetricKey)

                plainText = cipher.decrypt(cipherText)

            case _:
                raise ValueError("Invalid symmetric algorithm.")
    except:
        raise ValueError("Invalid encrypted signed message file.")

    return plainText
