# Criar um envelope assinado
# § Entrada: arquivo em claro + arquivo da chave RSA pública do destinatário + arquivo da
# chave RSA privada do remetente + algoritmo simétrico (AES / DES / RC4) e tamanho da
# chave (quando possível)
# § Processamento: Gerar chave simétrica temporária/aleatória. Cifrar arquivo em claro com
# a chave gerada. Assinar o arquivo criptografado com a chave privada do remetente. Cifrar a
# chave temporária com a chave do destinatário.
# § Saída: dois arquivos (Um com a chave de seção criptografada e outro do arquivo
# criptografado assinado).

