fields = ['Author', 'Cert'] #Fields of the bid to encrypt
key = secrets.token_bytes(32)
backend = default_backend()
algorithm = algorithms.AES(key)
iv_list = []

for field in fields:
    field_value = base64.b64decode(bid[field])
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
    ct = self.pubKey.encrypt(json.dumps({ 'Key' : base64.b64encode(self.key).decode('utf-8'), 'IV_list' : iv_list }).encode(), asyPadding.OAEP(mgf=asyPadding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    bid['Key'] = base64.b64encode(ct).decode('utf-8')
