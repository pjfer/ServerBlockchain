padd = asyPadding.OAEP(mgf=asyPadding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
keys = chain[-1].getContent()
manKeys = keys['AuctManKeys']
privKey = keys['ClientKey']
key, iv_list = (manKeys[-1][0], manKeys[-1][1])
decrypt = base64.b64decode(chain[0].getContent()['DecDin'])

winnerBlock = chain[-2]
bid = dict(winnerBlock.getContent())

exec(decrypt, locals())

keyPriv = serialization.load_pem_private_key(base64.b64decode(privKey) , password = None, backend=default_backend())
key = keyPriv.decrypt(base64.b64decode(bid['Key']), padd)
key = base64.b64encode(key).decode('utf-8')
for i in ['Author', 'Cert', 'Signature']:
    bid[i] = base64.b64encode(bid[i]).decode('utf-8')

iv_list = bid['IV_list']

exec(decrypt, locals())
winner = bid['Author']
