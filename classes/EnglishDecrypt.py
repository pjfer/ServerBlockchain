fields = ['Author', 'Cert', 'Signature'] #Fields of the bid to decrypt
backend = default_backend()
key = base64.b64decode(key)
algorithm = algorithms.AES(key)

for field in fields:
    field_value = base64.b64decode(bid[field])
    iv = base64.b64decode(iv_list[fields.index(field)])
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode, backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(field_value) + decryptor.finalize()
    unpadder = syPadding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    bid[field] = data
