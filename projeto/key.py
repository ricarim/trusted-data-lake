from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def save_privkey_bin(filename):
    priv_key = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = priv_key.private_numbers().private_value.to_bytes(32, 'big')
    with open(filename, "wb") as f:
        f.write(priv_bytes)

save_privkey_bin("ecc_hospital_privkey.bin")
save_privkey_bin("ecc_lab_privkey.bin")

def generate_pubkey_struct(priv_path, var_name):
    with open(priv_path, "rb") as f:
        priv_bytes = f.read()
    assert len(priv_bytes) == 32

    priv_int = int.from_bytes(priv_bytes, byteorder='big')
    priv_key = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())
    pub_numbers = priv_key.public_key().public_numbers()

    gx = pub_numbers.x.to_bytes(32, 'little')  # SGX expects little-endian
    gy = pub_numbers.y.to_bytes(32, 'little')

    def format_array(label, data):
        return f"    .{label} = {{ {', '.join(f'0x{b:02x}' for b in data)} }}"

    print(f"static const sgx_ec256_public_t {var_name} = {{")
    print(format_array("gx", gx) + ",")
    print(format_array("gy", gy))
    print("};\n")


# Generate for hospital
generate_pubkey_struct("ecc_hospital_privkey.bin", "g_pubkey_hospital")

# Generate for lab
generate_pubkey_struct("ecc_lab_privkey.bin", "g_pubkey_lab")

