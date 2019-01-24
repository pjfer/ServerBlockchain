import socket
import sys
import PyKCS11
import binascii
import base64
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

class Client:
    def __init__(self):
        return
    
    def main(self):
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        message = ''
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

            text = b'text to sign'
            signature = bytes(session.sign(private_key, text, mechanism))
            print("SIGNATURE: " + str(signature))
            message = bytes(json.dumps({'certificate':base64.b64encode(cert_der.public_bytes(Encoding.DER)).decode('utf-8'), 'signature':base64.b64encode(signature).decode('utf-8')}), 'utf-8')

        #Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #Connect the socket to the port where the server is listening
        server_address = ('localhost', 2019)
        print('Connection to port', server_address)
        sock.connect(server_address)

        try:
            #Send data
            print('sending', message)
            sock.sendall(message)

            #Look for the response
            amount_received = 0
            amount_expected = len(message)

            if amount_received < amount_expected:
                data = sock.recv(4096)
                amount_received += len(data)
                print('received', data)

        finally:
            print('Closing Socket')
            sock.close()

client = Client()
if __name__ == "__main__":
    client.main()
