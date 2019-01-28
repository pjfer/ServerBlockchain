
padd = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
keys = chain[-1].getContent()
manKeys = keys['AuctManKeys']
privKey = keys['clientKey']
key, iv_list = (manKeys[-1][0], manKeys[-1][1])

winnerBlock = chain[-2]
bid = winner.getContent().getJson()

exec(open('EnglishDecrypt.py').read() , locals(), globals())

keyPriv = serialization.load_pem_private_key(base64.b64decode(privKey) , password = None, backend=default_backend())
keys= keyPriv.decrypt(base64.b64decode(bid['Key']), padd)
key = base64.b64decode(keys['Key'])

iv_list = []
for i in keys['Iv_list']
    iv_list.append(base64.b64decode(i))

exec(open('EnglishDecrypt.py').read() , locals(), globals())
winner = bid['Author']








