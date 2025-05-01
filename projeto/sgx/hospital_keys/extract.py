from Crypto.PublicKey import RSA
import base64

def to_c_array(data, name):
    lines = []
    lines.append(f"const uint8_t {name}[] = {{")
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append("    " + hex_vals + ",")
    lines[-1] = lines[-1].rstrip(",")  # remove trailing comma
    lines.append("};")
    return "\n".join(lines)

# Load PEM file
with open("hospital_public.pem", "rb") as f:
    key = RSA.import_key(f.read())

n = key.n.to_bytes(384, byteorder="big")  # 3072 bits = 384 bytes
e = key.e.to_bytes(4, byteorder="big")    # Usually small (e.g. 0x10001)

print(to_c_array(n, "HOSPITAL_PUB_N"))
print()
print(to_c_array(e, "HOSPITAL_PUB_E"))

