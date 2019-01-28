padd = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
keys = chain[-1].getContent()
manKeys = keys['AuctManKeys']
privKey = keys['clientKey']
key, iv_list = (manKeys[-1][0], manKeys[-1][1])
best = (None,None)
keyPriv = serialization.load_pem_private_key(base64.b64decode(privKey) , password = None, backend=default_backend())
decrypt = open('BlindDecrypt.py').read() 

for i in range(1,len(chain)-2):
    bid = chain[i].getContent().getJson()

    exec(decrypt, locals(), globals())

    keys= keyPriv.decrypt(base64.b64decode(bid['Key']), padd)
    key = base64.b64decode(keys['Key'])

    iv_list = []
    for i in keys['Iv_list']
        iv_list.append(base64.b64decode(i))

    exec(decrypt, locals(), globals())
    if best[1] == None or best[1] < bid['Value']:
        best = (bid['Author'], bid['Value'])  

winner = best[0]
