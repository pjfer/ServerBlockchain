padd = asyPadding.OAEP(mgf=asyPadding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
keys = chain[-1].getContent()
manKeys = keys['AuctManKeys']
privKey = keys['ClientKey']
key, iv_list = (manKeys[-1][0], manKeys[-1][1])
best = (None,None)
keyPriv = serialization.load_pem_private_key(base64.b64decode(privKey) , password = None, backend=default_backend())
decrypt = base64.b64decode(chain[0].getContent()['DecDin'])

for i in range(1,len(chain)-2):
    bid = dict(chain[i].getContent())

    exec(decrypt, locals())

    key = keyPriv.decrypt(base64.b64decode(bid['Key']), padd))
    key = base64.b64encode(key).decode('utf-8')
    for i in ['Value', 'Cert', 'Signature']:
        bid[i] = base64.b64encode(bid[i]).decode('utf-8')

    iv_list = ['IV_list']

    exec(decrypt, locals())
    if best[1] == None or best[1] < bid['Value']:
        best = (bid['Author'], bid['Value'])  

winner = best[0]
