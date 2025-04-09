from Crypto.Cipher import DES

# Chave usada com INS_LOAD_KEY (8 bytes)
key = b'\x11\x22\x33\x44\x55\x66\x77\x88'

# adminKeyBytes definidos no applet
plaintext = bytes([
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
])

# Inicializar cipher DES-ECB
cipher = DES.new(key, DES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)  # 16 bytes

print("Ciphertext (DES ECB):", ciphertext.hex().upper())

