import sys, PyKCS11, json, secrets, base64, os
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import padding as syPadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asyPadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Bid import Bid
from Auction import Auction

def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)

path = find('Projeto', '/') + "/sio2018-p1g20"
#path = find('sio2018-p1g20', '/') + "/classes/"

class Client:
    def __init__(self):
        self.receipt = {}
        self.customEncrypt = None
        self.pubKey = b''
        self.privKey = b''
        self.key = b''

    def verifyOnChain(self, chain):
        #Load da Chave do Repository
        padd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
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

    def verifyChain(self, auctionId, chain, user):
        #Load da Chave do Repository
        padd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
        repKey = x509.load_pem_x509_certificate(open("{}/classes/AuctionRepository.crt".format(path), "rb").read() , backend=default_backend()).public_key()
        #Load dos receipts do cliente
        receipts = fnmatch.filter(os.listdir('.'), 'Auction'+str(auctionId)+'_*.receipt')
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
                    except Exception as e:
                        print(e)
                        return False
                else:
                    try:
                        #Verificação da Assinatura do Repositório (para o bloco final com as chaves)
                        link = chain[i].getLink()
                        bid =  chain[i].getContent()
                        challenge = chain[i].getChallenge()
                        time = chain[i].getTimestamp()
                        repKey.verify(chain[i].getRepSign(), bid.getAuthor() + bid.getValue() + link +str(time).encode()+ json.dumps(challenge).encode(), padd, hashes.SHA256())

                        #Falta Desencriptação Completa das bids
                        cert = x509.load_der_x509_certificate(bid.getCert(), backend=default_backend())
                        cert_chain =  build_chain([], cert, [], certs)
                        if not checkChain(cert_chain, crls):
                            return False
                        cliKey = cert.public_key()
                        cliKey.verify(bid.getSignature(), bid.getAuthor() + bid.getValue() +str(bid.getTimestamp()).encode()+ str(bid.getCriptAnswer()).encode() + bid.getCert() + bid.getKey(), padd, hashes.SHA256())
                        #Verificação da Assinatura da Bid
                        #Verificação dos seus receipts
                        if i in pos and bid.getAuthor() != user:
                            return False
                    except exceptions.InvalidSignature as e:
                        print("Invalid Signature!")
                        return False
            else:
                try:
                    #Verificação da Assinatura do Repositório para o primeiro bloco (com as regras do auction)
                    link = chain[i].getLink()
                    cont =  chain[i].getContent()
                    verDin = cont['VerDin']
                    encDin = cont['EncDin']
                    repKey.verify(chain[i].getRepSign(), json.dumps(verDin).encode() + json.dumps(encDin).encode() + link, padd, hashes.SHA256())
                except Exception as e:
                    print(e)
                    return False
        return True

    def createAuction(self, name, type, endTime, description, customVal, customEncryp, customDecryp, customWinVal):
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
        author = cert_der.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.encode()
        timestamp = datetime.now().timestamp()
        criptAnswer = self.doChallenge(difficulty, link)
        text_to_sign = author + bytes(str(value), 'utf-8') + bytes(str(timestamp), 'utf-8') + bytes(str(criptAnswer), 'utf-8') + self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) + cert_der.public_bytes(serialization.Encoding.DER)
        signature = self.sign(session, private_key, text_to_sign, mechanism)
        bid = Bid(author, value, str(timestamp), criptAnswer, self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), cert_der.public_bytes(serialization.Encoding.DER), signature)
        bid = self.encrypt(auctionId, bid)
        message = json.dumps({ 'Id' : 13, 'AuctionId' : auctionId, 'Bid' : bid })
        return message

    def sendPrivKey(self):
        return self.privKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

    def requestAuction(self, auctionId):
        return json.dumps({ 'Id' : 11, 'auctionId' : auctionId })

    def requestWinner(self, auctionId):
        return json.dumps({ 'Id' : 12, 'auctionId' : auctionId })

    def showActAuction(self):
        return json.dumps({ 'Id' : 10 })

    def endAuction(self, auctionId):
        return json.dumps({ 'Id' : 1, 'AuctionId' : auctionId })

    def getCustomEncrypt(self):
        return self.customEncrypt

    def getPubKey(self):
        return self.pubKey

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

            private_key = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
            return session, cert_der, private_key, mechanism

    def sign(self, session, private_key, text_to_sign, mechanism):
        signature = bytes(session.sign(private_key, text_to_sign, mechanism))
        return signature
