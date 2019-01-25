fields = ['Value', 'Key', 'Cert'] #Fields of the bid to encrypt
if key == None:
    key = secrets.token_bytes(32)
backend = default_backend()
algorithm = algorithms.AES(key)
iv_list = []

for field in fields:
    if field != 'Value':
        field_value = base64.b64decode(bid[field])
    else:
        field_value = bytes(str(bid[field]), 'utf-8')
    iv = secrets.token_bytes(16)
    iv_list.append(iv)
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode, backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(field_value) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    ct = base64.b64encode(ct).decode('utf-8')
    bid[field] = ct
