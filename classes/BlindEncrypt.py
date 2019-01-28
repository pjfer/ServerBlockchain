fields = ['Value', 'Cert', 'Signature'] #Fields of the bid to encrypt
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
    iv_list.append(base64.b64encode(iv).decode('utf-8'))
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode, backend)
    encryptor = cipher.encryptor()
    padder = syPadding.PKCS7(128).padder()
    padded_data = padder.update(field_value) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    ct = base64.b64encode(ct).decode('utf-8')
    bid[field] = ct
    
if self.pubKey != b'':
    self.key = key
    ct = self.pubKey.encrypt(self.key, asyPadding.OAEP(mgf=asyPadding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    bid['Key'] = base64.b64encode(ct).decode('utf-8')
    bid['IV_list'] = iv_list
