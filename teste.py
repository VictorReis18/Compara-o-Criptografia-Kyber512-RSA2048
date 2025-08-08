import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import oqs

# Mensagem de teste
message = b"Desafios e perspectivas da Criptografia Pos Quantica na Seguranca Computacional Moderna"

print("=== RSA (2048 bits) ===")
# Geração de chave
start = time.perf_counter()
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public_key = rsa_private_key.public_key()
end = time.perf_counter()
print(f"Geração de chave: {end - start:.6f} segundos")

# Criptografia
start = time.perf_counter()
rsa_cipher = rsa_public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
end = time.perf_counter()
print(f"Cifrar: {end - start:.6f} segundos")

# Descriptografia
start = time.perf_counter()
rsa_plain = rsa_private_key.decrypt(
    rsa_cipher,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
end = time.perf_counter()
print(f"Decifrar: {end - start:.6f} segundos")

print("\n=== Kyber512 ===")
# Instância do esquema
alg = "Kyber512"
with oqs.KeyEncapsulation(alg) as kem:

    # Geração de chave
    start = time.perf_counter()
    public_key = kem.generate_keypair()
    end = time.perf_counter()
    print(f"Geração de chave: {end - start:.6f} segundos")

    # Encapsulamento (cifrar e gerar chave secreta compartilhada)
    start = time.perf_counter()
    ciphertext, shared_secret_enc = kem.encap_secret(public_key)
    end = time.perf_counter()
    print(f"Cifrar (encapsular): {end - start:.6f} segundos")

    # Decapsulamento (recuperar a chave secreta)
    start = time.perf_counter()
    shared_secret_dec = kem.decap_secret(ciphertext)
    end = time.perf_counter()
    print(f"Decifrar (decapsular): {end - start:.6f} segundos")

    # Verificação
    print(f"Chaves coincidem? {shared_secret_enc == shared_secret_dec}")
