# Criar um envelope assinado
# § Entrada: arquivo em claro + arquivo da chave RSA pública do destinatário + arquivo da
# chave RSA privada do remetente + algoritmo simétrico (AES / DES / RC4) e tamanho da
# chave (quando possível)
# § Processamento: Gerar chave simétrica temporária/aleatória. Cifrar arquivo em claro com
# a chave gerada. Assinar o arquivo criptografado com a chave privada do remetente. Cifrar a
# chave temporária com a chave do destinatário.
# § Saída: dois arquivos (Um com a chave de seção criptografada e outro do arquivo
# criptografado assinado).

from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

def makeDigitalEnvelope(plainText: bytes, recipientPublicKey: bytes, senderPrivateKey: bytes, symmetricAlgorithm: str, symmetricKeySize: int):
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
            key = get_random_bytes(8) # 64 bits key with 56 bits of entropy

            cipher = DES.new(key, DES.MODE_CBC) # Create a DES cipher object

            cipherText = cipher.encrypt(pad(plainText, DES.block_size)) # Encrypt the plain text

        case "AES":
            key = get_random_bytes(symmetricKeySize) # 128, 192 or 256 bits key

            cipher = AES.new(key, AES.MODE_CBC)

            cipherText = cipher.encrypt(pad(plainText, AES.block_size))

        case "RC4":
            key = get_random_bytes(symmetricKeySize) # 40 to 2048 bits key
            
            cipher = ARC4.new(key)

            cipherText = cipher.encrypt(plainText)

        case _:
            raise ValueError("Invalid symmetric algorithm.")
        
    # Sign the cipher text with the sender's private key:

    # # Make a hash of the cipher text
    hashObject = SHA256.new() # Create a SHA-256 hash object

    hashObject.update(cipherText) # Update the hash object with the cipher text

    hashResult = hashObject.digest() # Get the hash result

    # # Sign the hash result with the sender's private key
    cipher = PKCS1_OAEP.new(senderPrivateKey) # Create a PKCS1_OAEP cipher object

    signature = cipher.encrypt(hashResult) # Encrypt the hash result with the sender's private key


        
