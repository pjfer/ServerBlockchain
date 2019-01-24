import sys, PyKCS11, json, secrets
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import Bid
import Auction

class Client:
    def __init__(self):
        self.receipt = {}

    def createAuction(self, type, endTime, description, customVal, customEncryp):
        message = json.dumps({ 'Id' : 0, 'Type' : type, 'Time_to_end' : endTime, 'Descr' : description, 'Dynamic_val' : customVal, 'Dynamic_encryp' : customEncryp })
        return message
    
    def createBid(self, auctionId, value):
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        message = b''
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

            author = bytes(str(cert_der.subject), 'utf-8')
            timestamp = datetime.now().timestamp()
            criptAnswer = b'basdg'
            key = secrets.token_bytes(32)
            cert_der = bytes(str(cert_der), 'utf-8')
            text = author + bytes(str(timestamp), 'utf-8') + bytes(str(criptAnswer), 'utf-8') + key + cert_der
            signature = bytes(session.sign(private_key, text, mechanism))
            bid = Bid.Bid(author, bytes(value, 'utf-8'), str(timestamp), criptAnswer, self.encrypt(key, cert_der), self.encrypt(key, key), signature)
            message = json.dumps({ 'Id' : 2, 'AuctionId' : auctionId, 'Bid' : bid.getJson() })
        return message

    def requestAuction(self, auctionId):
        message = json.dumps({ 'Id' : 11, 'auctionId' : auctionId })
        return message

    def requestWinner(self, auctionId):
        message = json.dumps({ 'Id' : 12, 'auctionId' : auctionId })
        return message

    def showActAuction(self):
        message = json.dumps({ 'Id' : 10 })
        return message

    def endAuction(self, auctionId):
        message = json.dumps({ 'Id' : 1, 'AuctionId' : auctionId })
        return message

    def encrypt(self, key, field):
        backend = default_backend()
        algorithm = algorithms.AES(key)
        iv = secrets.token_bytes(16)
        mode = modes.CBC(iv)
        cipher = Cipher(algorithm, mode, backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(field) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
