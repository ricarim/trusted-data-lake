from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

with open("ecc_privkey.bin", "rb") as f:
    priv_bytes = f.read()
assert len(priv_bytes) == 32

priv_int = int.from_bytes(priv_bytes, byteorder='big')
priv_key = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())
pub_numbers = priv_key.public_key().public_numbers()

gx = pub_numbers.x.to_bytes(32, 'little')  # SGX espera little endian
gy = pub_numbers.y.to_bytes(32, 'little')

def format_array(label, data):
    return f"    .{label} = {{ {', '.join(f'0x{b:02x}' for b in data)} }}"

print("static const sgx_ec256_public_t g_static_pubkey = {")
print(format_array("gx", gx) + ",")
print(format_array("gy", gy))
print("};")

