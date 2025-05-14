from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend
import struct

# Mensagem
msg = b"mensagem para verificar"

# Carregar chave privada
with open("ecc_privkey.bin", "rb") as f:
    priv_bytes = f.read()
priv_int = int.from_bytes(priv_bytes, "big")
priv = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())

# Assinar
signature_der = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(signature_der)

# SGX espera r e s como arrays de 8 uint32_t little endian
r_words = [int.from_bytes(r.to_bytes(32, "little")[i*4:(i+1)*4], "little") for i in range(8)]
s_words = [int.from_bytes(s.to_bytes(32, "little")[i*4:(i+1)*4], "little") for i in range(8)]

sig = struct.pack("<8I8I", *r_words, *s_words)

# Salvar assinatura
with open("assinatura.bin", "wb") as f:
    f.write(sig)

print("Assinatura salva em assinatura.bin")

