import socket
import json
import binascii
import base64
from os import scandir
from datetime import datetime
from collections import OrderedDict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

class AuctionRepository:
    def __init__(self):
        return

    def validation(self, cert):
        return x509.load_pem_x509_certificate(cert, default_backend())

    def trustAnchor(self):
        roots = dict()

        for fil in scandir('/etc/ssl/certs'):
            if '.pem' in fil.path:
                with open(fil.path, 'rb') as f:
                    cert1 = f.read()
                    cert = self.validation(cert1)
                    if datetime.now() < cert.not_valid_after:
                        roots[cert.subject] = cert

        return roots

    def build_issues(self, chain, cert, user_roots, roots):
        chain.append(cert)
        issuer = cert.issuer
        subject = cert.subject

        if issuer == subject and subject in roots.keys():
            print("Chain completed!")
            return chain

        if issuer in user_roots.keys():
            return self.build_issues(chain, user_roots[issuer], user_roots, roots)

        if issuer in roots.keys():
            return self.build_issues(chain, roots[issuer], user_roots, roots)

        print("Chain not found!")
        return

    def validatePath(self, chain):
        if len(chain) < 1:
            return True
        
        cert = chain[-1]
        chain.remove(cert)
        signature = cert.signature

        #if not cert in crl:
        if not cert in []:
            return True and self.validatePath(chain)
        else:
            return False and self.validatePath(chain)

        return True

    def main(self):
        #Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #Bind the socket to the port
        server_address = ('localhost', 2019)
        print('Starting up on', server_address)
        sock.bind(server_address)

        #Listen for incoming connections
        sock.listen(1)

        while True:
            #Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            
            try:
                print('connection from', client_address)

                #Receive the data in small chunks and retransmit it
                while True:
                    roots = self.trustAnchor()
                    data = connection.recv(4096)
                    print('received', data)
                    if data:
                        j = json.loads(data)
                        b64cert = base64.b64decode(j['certificate'])
                        signature = base64.b64decode(j['signature'])
                        print("SIGNATURE: " + str(signature))

                        cert = x509.load_der_x509_certificate(b64cert, default_backend())
                        user_roots = {cert.subject:cert}
                        print(user_roots)
                        chain = self.build_issues([], cert, user_roots, roots)
                        print(chain)
                        print(cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm))

                        print('sending data back to the client')
                        connection.sendall(data)
                    else:
                        print('no more data from', client_address)
                        break
            finally:
                #Clean up connection
                connection.close()

auctionRepository = AuctionRepository()
if __name__ == "__main__":
    auctionRepository.main()
