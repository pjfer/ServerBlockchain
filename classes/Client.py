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

path = find('Projeto', '/') + "/sio-1819-g84735-84746/classes/"
#path = find('sio2018-p1g20', '/') + "/classes/"

class Client:
    def __init__(self):
        self.receipt = {}
        self.customEncrypt = None
        self.pubKey = b''
        self.privKey = b''
        self.key = b''

    def createAuction(self, name, type, endTime, description, customVal, customEncryp, customDecryp, customWinVal):
        self.privKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.pubKey = self.privKey.public_key()
        print(self.pubKey)
        pubKey = self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return json.dumps({ 'Id' : 0, 'Name' : name, 'Type' : type, 'Time_to_end' : endTime, 'Descr' : description, 'Dynamic_val' : base64.b64encode(customVal.encode()).decode('utf-8'), 'Dynamic_encryp' : base64.b64encode(customEncryp.encode()).decode('utf-8'), 'Dynamic_decryp' : base64.b64encode(customDecryp.encode()).decode('utf-8'), 'Dynamic_winVal' : base64.b64encode(customWinVal.encode()).decode('utf-8'), 'PubKey' : base64.b64encode(pubKey).decode('utf-8') })
    
    def createBid(self, auctionId, value, customEncrypt=None, pubKey=None):
        if customEncrypt != None:
            self.customEncrypt = base64.b64decode(customEncrypt)
        if pubKey != None:
            self.pubKey = base64.b64decode(pubKey)
            self.pubKey = load_pem_public_key(self.pubKey, backend=default_backend())
        session, cert_der, private_key, mechanism = self.getCCData()
        author = cert_der.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.encode()
        timestamp = datetime.now().timestamp()
        criptAnswer = { 'Response' : base64.b64encode(b'abc').decode('utf-8'), 'Nonce' : base64.b64encode(b'def').decode('utf-8'), 'Difficulty' : 0 }
        text_to_sign = author + bytes(str(timestamp), 'utf-8') + bytes(str(criptAnswer), 'utf-8') + self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) + cert_der.public_bytes(serialization.Encoding.PEM)
        signature = self.sign(session, private_key, text_to_sign, mechanism)
        bid = Bid(author, value, str(timestamp), criptAnswer, self.pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), cert_der.public_bytes(serialization.Encoding.PEM), signature)
        bid = self.encrypt(auctionId, bid, pubKey)
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

    def encrypt(self, auctionId, bid, key=None):
        bid = bid.getJson()
        exec(self.customEncrypt, locals(), globals())
        return bid

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
