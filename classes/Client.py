import sys, PyKCS11, json, secrets, base64, os
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding as syPadding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asyPadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Bid import Bid
from Auction import Auction

def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)

path = find('sio2018-p1g20', '/')

class Client:
    def __init__(self):
        self.receipt = {}
        self.customEncrypt = None
        self.pubKey = b''
        self.privKey = b''
        self.last_bid = {}
        self.min_value = 1
        self.max_value = -1
        self.possible_bids = -1
        self.bids_made = {}
        self.name = ''

    def createAuction(self, name, type, endTime, description, customVal='None', customEncryp='None', customDecryp='None', customWinVal='None'):
        self.privKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.pubKey = self.privKey.public_key()
        pubKey = self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return json.dumps({ 'Id' : 0, 'Name' : name, 'Type' : type, 'Time_to_end' : endTime, 'Descr' : description, 'Dynamic_val' : base64.b64encode(customVal.encode()).decode('utf-8'), 'Dynamic_encryp' : base64.b64encode(customEncryp.encode()).decode('utf-8'), 'Dynamic_decryp' : base64.b64encode(customDecryp.encode()).decode('utf-8'), 'Dynamic_winVal' : base64.b64encode(customWinVal.encode()).decode('utf-8'), 'PubKey' : base64.b64encode(pubKey).decode('utf-8') })
    
    def createBid(self, auctionId, value, difficulty, link, customEncrypt=None, pubKey=None):
        if customEncrypt != None:
            self.customEncrypt = base64.b64decode(customEncrypt)
        if pubKey != None:
            self.pubKey = base64.b64decode(pubKey)
            self.pubKey = load_pem_public_key(self.pubKey, backend=default_backend())
        session, cert_der, private_key, mechanism = self.getCCData()
        author = self.name.encode()
        timestamp = datetime.now()
        criptAnswer = self.doChallenge(difficulty, link)
        text_to_sign = author + str(value).encode() + str(timestamp).encode() + str(criptAnswer).encode() + self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) + cert_der.public_bytes(serialization.Encoding.DER)
        signature = self.sign(session, private_key, text_to_sign, mechanism)
        bid = Bid(author, value, str(timestamp), criptAnswer, self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), cert_der.public_bytes(serialization.Encoding.DER), signature)
        bid = self.encrypt(auctionId, bid)
        message = json.dumps({ 'Id' : 13, 'AuctionId' : auctionId, 'Bid' : bid })
        return message

    def sendPrivKey(self, auctionId):
        return json.dumps({ 'Id' : 19, 'AuctionId' : auctionId, 'ClientKey' : base64.b64encode(self.privKey).decode('utf-8') })

    def requestAuction(self, auctionId):
        return json.dumps({ 'Id' : 11, 'AuctionId' : auctionId })

    def requestWinner(self, auctionId):
        return json.dumps({ 'Id' : 12, 'AuctionId' : auctionId })

    def showActAuction(self):
        return json.dumps({ 'Id' : 10 })

    def showFinAuction(self):
        return json.dumps({ 'Id' : 21 })

    def endAuction(self, auctionId):
        return json.dumps({ 'Id' : 1, 'AuctionId' : auctionId })

    def getCustomEncrypt(self):
        return self.customEncrypt

    def encrypt(self, auctionId, bid):
        bid = bid.getJson()
        exec(self.customEncrypt, locals(), globals())
        return bid

    def doChallenge(self, difficulty, link):
        nonce = secrets.token_bytes(8)
        hashF = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hashF.update(nonce + link)
        digest = hashF.finalize()
        while(not digest[0:difficulty] == b'0'*difficulty):
            nonce = secrets.token_bytes(8)
            hashF = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hashF.update(nonce + link)
            digest = hashF.finalize()
        return { 'Nonce' : nonce , 'Response' : digest, 'Difficulty' : difficulty }

    def getCCData(self):
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        backend = default_backend()

        for slot in slots:
            all_attr = list(PyKCS11.CKA.keys())

            #Filter attributes
            all_attr = [e for e in all_attr if isinstance(e, int)]
            session = pkcs11.openSession(slot)
            cert_der = ''

            for obj in session.findObjects():
                # Get object attributes
                attr = session.getAttributeValue(obj, all_attr)
                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
                if attr['CKA_CERTIFICATE_TYPE'] is not None:
                    cert_der = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), backend)
                    break

            private_key = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
            self.name = cert_der.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            return session, cert_der, private_key, mechanism

    def sign(self, session, private_key, text_to_sign, mechanism):
        signature = bytes(session.sign(private_key, text_to_sign, mechanism))
        return signature
    
    def saveAndValidReceipt(self, rec):
        #Cria o Receipt a ser Guardado
        receipt = json.dumps({ 'TimestampRec' : rec['TimestampRec'], 'TimestampEnv' : rec['TimestampEnv'], 'Success' : rec['Success'], 'Pos' : rec['Pos'], 'Sign' : rec['Sign'] })
        #Carrega a Chave pública do AuctionRepository
        padd = asyPadding.PSS(mgf=asyPadding.MGF1(hashes.SHA256()), salt_length=asyPadding.PSS.MAX_LENGTH)
        repKey = x509.load_pem_x509_certificate(open("{}/certs_servers/AuctionRepository.crt".format(path), "rb").read() , backend=default_backend()).public_key()
        #Cria o texto de verificação de Assinatura
        text_to_sign = (rec['TimestampRec'] + rec['TimestampEnv'] + rec['Success'] + str(rec['Pos'])).encode()
        #Verifica a Assinatura
        try:
            repKey.verify(base64.b64decode(rec['Sign']), text_to_sign, padd, hashes.SHA256())
        except Exception:
            print("Error Validating Receipt: " + "Auction{}_Receipt{}.receipt".format(str(rec['AuctionId']), str(rec['ReceiptId'])))
        #Guarda o Receipt
        f = open("{}/receipts/Auction{}_Receipt{}.receipt".format(path, str(rec['AuctionId']), str(rec['ReceiptId'])), "w+")
        f.write(receipt)
        f.close()
        
    def verifyOnChain(self, chain):
        #Load da Chave do Repository
        padd = asyPadding.PSS(mgf=asyPadding.MGF1(hashes.SHA256()), salt_length=asyPadding.PSS.MAX_LENGTH)
        repKey = x509.load_pem_x509_certificate(open("{}/certs_servers/AuctionRepository.crt".format(path), "rb").read() , backend=default_backend()).public_key()
        for i in range(len(chain)):
            if i != 0:
                #Verificação dos links da blockchain
                link = chain[i].getLink()
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                previousLink = chain[i-1].getLink() + chain[i-1].getRepSign()
                digest.update(previousLink)
                if link !=  digest.finalize():
                    return False
                try:
                    #Verificação da Assinatura do Repositório (para os blocos com bids)
                    link = chain[i].getLink()
                    bid =  chain[i].getContent()
                    challenge = chain[i].getChallenge()
                    time = chain[i].getTimestamp()
                    repKey.verify(chain[i].getRepSign(), bid.getAuthor() + bid.getValue() + link +str(time).encode()+ json.dumps(challenge).encode(), padd, hashes.SHA256())
                except Exception as e:
                    print(e)
                    return False
            else:
                try:
                    #Verificação da Assinatura do Repositório para o primeiro bloco (com as regras do auction)
                    link = chain[i].getLink()
                    cont =  chain[i].getContent()
                    verDin = cont['VerDin']
                    encDin = cont['EncDin']
                    repKey.verify(chain[i].getRepSign(), json.dumps(verDin).encode() + json.dumps(encDin).encode() + link, padd, hashes.SHA256())
                except Exception:
                    return False
            return True

    def verifyEndedChain(self, auctionId, chain, winner):
        user = self.name
        #Load da Chave do Repository
        padd = asyPadding.PSS(mgf=asyPadding.MGF1(hashes.SHA256()), salt_length=asyPadding.PSS.MAX_LENGTH)
        repKey = x509.load_pem_x509_certificate(open("{}/certs_servers/AuctionRepository.crt".format(path), "rb").read() , backend=default_backend()).public_key()
        keys = chain[-1].getContent()
        manKeys = keys['AuctManKeys']
        privKey = keys['ClientKey']
        #Perceber se é necessário ou não colocar em que base etc.
        keyPriv = serialization.load_pem_private_key(base64.b64decode(privKey), password=None, backend=default_backend())
        decrypt = base64.b64decode(chain[0].getContent()['DecDin'])
        valDin = base64.b64decode(chain[0].getContent()['VerDin'])
        winVal = base64.b64decode(chain[0].getContent()['WinValDin'])

        #Load dos receipts do cliente
        receipts = fnmatch.filter(os.listdir('{}/receipts/'.format(path)), 'Auction{}_*.receipt'.format(auctionId))
        pos = []
        for i in receipts:
            f = open(i)
            receipt = json.loads(f.read())
            if receipt['Success']:
                pos.append(receipt['Pos'])
            f.close()

        for i in range(len(chain)):
            if i != 0:
                #Verificação dos links da blockchain
                link = chain[i].getLink()
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                previousLink = chain[i-1].getLink() + chain[i-1].getRepSign()
                digest.update(previousLink)
                if link !=  digest.finalize():
                    return False
                if i == len(chain)-1:
                    try:
                        #Verificação da Assinatura do Repositório do Bloco
                        link = chain[i].getLink()
                        cont =  chain[i].getContent()
                        clientKey = cont['ClientKey']
                        auctionManagerKeys = cont['AuctManKeys']
                        repKey.verify(chain[i].getRepSign(), base64.b64decode(clientKey) + json.dumps(auctionManagerKeys).encode() + link, padd, hashes.SHA256())
                    except Exception:
                        return False
                else:
                    try:
                        #Verificação da Assinatura do Repositório (para o bloco final com as chaves)
                        link = chain[i].getLink()
                        bid =  chain[i].getContent()
                        challenge = chain[i].getChallenge()
                        time = chain[i].getTimestamp()
                        repKey.verify(chain[i].getRepSign(), bid.getAuthor() + bid.getValue() + link +str(time).encode()+ json.dumps(challenge).encode(), padd, hashes.SHA256())

                        bid = bid.getJson()
                        key = base64.b64decode(manKeys[i-1][0])

                        iv_list = []
                        for i in manKeys[i-1][1]:
                            iv_list.append(base64.b64decode(i))

                        exec(decrypt, locals(), globals())

                        exec(valDin, locals(), globals())

                        if not validBid:
                            return validBid

                        keys = keyPriv.decrypt(base64.b64decode(bid['Key']), padd)
                        key = base64.b64decode(keys['Key'])

                        iv_list = []
                        for i in keys['IV_list']:
                            iv_list.append(base64.b64decode(i))

                        cert = x509.load_pem_x509_certificate(bid.getCert(), backend=default_backend())
                        cert_chain =  build_chain([], cert, [], certs)
                        if not checkChain(chain, crls):
                            return False

                        #Verificação da Assinatura da Bid
                        cliKey = x509.load_pem_x509_certificate(bid.getCert(), backend=default_backend()).public_key()
                        cliKey.verify(bid.getSignature(), bid.getAuthor() + bid.getValue() +str(bid.getTimestamp()).encode()+ str(bid.getCriptAnswer()).encode() + bid.getCert() + bid.getKey(), padd, hashes.SHA256())
                        
                        #Verificação do criptopuzzle
                        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        response = bid['CriptAnswer']
                        nonce = response['Nonce']
                        digest.update(nonce.encode() + base64.b64decode(challenge['Challenge']))
                        result =  digest.finalize()
                        if result[0:challenge['Difficulty']] != b'0'*challenge['Difficulty'] or result != response['Response']:
                            return False

                        #Verificação dos seus receipts
                        if i in pos and bid.getAuthor() != user:
                            return False
                    except Exception as e:
                        return False
            else:
                try:
                    #Verificação da Assinatura do Repositório para o primeiro bloco (com as regras do auction)
                    link = chain[i].getLink()
                    cont =  chain[i].getContent()
                    verDin = cont['VerDin']
                    encDin = cont['EncDin']
                    repKey.verify(chain[i].getRepSign(), json.dumps(verDin).encode() + json.dumps(encDin).encode() + link, padd, hashes.SHA256())
                except Exception:
                    return False
            if exec(WinVal, locals(), globals()) != winner:
                return False
        return True
