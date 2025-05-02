from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

with open("hospital_public.pem", "rb") as f:
    key = serialization.load_pem_public_key(f.read(), backend=default_backend())

nums = key.public_numbers()
n = nums.n.to_bytes(384, byteorder="big")
e = nums.e.to_bytes(4, byteorder="little")  # SGX expects little-endian

print("HOSPITAL_PUB_N = {")
for i in range(0, len(n), 12):
    print("    " + ", ".join(f"0x{b:02x}" for b in n[i:i+12]) + ",")
print("};")

print("\nHOSPITAL_PUB_E = { " + ", ".join(f"0x{b:02x}" for b in e) + " };")

