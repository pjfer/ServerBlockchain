fields = ['Value', 'Cert', 'Signature'] #Fields of the bid to decrypt
backend = default_backend()
algorithm = algorithms.AES(key)

for field in fields:
    field_value = base64.b64decode(bid[field])
    iv = iv_list[fields.index(field)]
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode, backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(field_value) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    bid[field] = data
