import socket, ssl, sys, json, os, secrets, base64, fnmatch, PyKCS11, traceback
from os import scandir
from threading import Thread
from cryptography import x509
from collections import OrderedDict
from urllib import request, response
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding as syPadding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asyPadding
from cryptography.hazmat.primitives.serialization import load_der_public_key
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('sio2018-p1g20', '/')
sys.path.append('{}/classes/'.format(path))
from AuctionManager import AuctionManager

def getCerts():
    certs = {}
    for c in open("/etc/ssl/certs/PTEID.pem", "rb").read().split(b"-----END CERTIFICATE-----")[0:-2]:
        cert = x509.load_pem_x509_certificate((c.decode() + "-----END CERTIFICATE-----").encode(), default_backend())
        if cert.not_valid_after > datetime.now() and cert.not_valid_before < datetime.now():
            certs[cert.subject] = cert
    cert = x509.load_der_x509_certificate(open("{}/certs_servers/ecraizestado.crt".format(path), "rb").read(), default_backend())
    certs[cert.subject] = cert
    #Verificar data dos certs
    return certs

def getCRLs(certs):
    CRLs = []
    for cert in certs:
        for i in cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value:
            for dist_point in i.full_name:
                if dist_point.value not in CRLs:
                    CRLs.append(dist_point.value)
    crls = []
    for crl in CRLs:
        crls.append(x509.load_der_x509_crl(request.urlopen(crl).read(), default_backend()))
    return crls

def build_chain(chain, cert, intermediate_certs, checked_certs):
    chain.append(cert)
    issuer = cert.issuer
    subject = cert.subject

    if issuer == subject and subject in checked_certs.keys():
        print("Chain completed!")
        return chain

    if issuer in intermediate_certs:
        return build_chain(chain, intermediate_certs[issuer], intermediate_certs, checked_certs)

    if issuer in checked_certs.keys():
        return build_chain(chain, checked_certs[issuer], intermediate_certs, checked_certs)

    print("Chain not found!")
    return

def checkChain(chain, crls):
    for cert in range(0, len(chain)-1):
        purpose = chain[cert].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if cert == 0 and purpose.digital_signature == False:
            return False
        for crl in crls:
            serial = chain[cert].serial_number
            if False:#crl.get_revoked_certificate_by_serial_number(serial) != None:
                return False
        if chain[cert].not_valid_after < datetime.now()  or  chain[cert].not_valid_before > datetime.now():
            return False

        if cert != len(chain)-1 and chain[cert+1].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign == False:
            return False
        try:
            pub_key = chain[cert+1].public_key()
            pub_key.verify(chain[cert].signature, chain[cert].tbs_certificate_bytes, asyPadding.PKCS1v15(), chain[cert].signature_hash_algorithm)
        except Exception as e:
            print(e)
            return False
    return True

def receive(conn):
    data = conn.recv(1024)
    i = data.index(b':')
    idx = data.index(b'{')
    data_size = int(data[i+1:idx]) - 1024
    while data_size > 0 and (data[-6:-1] + b'\n') != b'\r\n\r\n\r\n':
        data_size -= 1024
        data += conn.recv(1024)
    new_data = data[idx:]
    return new_data

def encrypt(nonce, request):
    requestEnc = aesgcm.encrypt(nonce, request.encode(), None)
    nonce = base64.b64encode(nonce).decode('utf-8')
    requestEnc = base64.b64encode(requestEnc).decode('utf-8')
    return nonce, requestEnc

def decrypt(nonce, response):
    nonce = base64.b64decode(nonce)
    responseDec = aesgcm.decrypt(nonce, base64.b64decode(response), None)
    return nonce, json.loads(responseDec.decode())

def connAuctReposSer():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="{}/certs_servers/AuctionManager.crt".format(path), keyfile="{}/certs_servers/AuctionManagerKey.pem".format(path))
    context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
    context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    bindsocket = socket.socket()
    bindsocket.bind(('localhost', 2029))
    #bindsocket.bind(('192.168.1.2', 2029))
    bindsocket.listen(5)
    
    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        firstTime = True
        
        try:
            while True:
                if not firstTime:
                    newsocket, fromaddr = bindsocket.accept()
                    connstream = context.wrap_socket(newsocket, server_side=True)
                firstTime = False
                client_cert = connstream.getpeercert()
                owner = client_cert['subject'][-1][-1][-1]
                new_data = receive(connstream)
                message = json.loads(new_data)
                id = message['Id']
                new_message = b''

                if id == 2:
                    payload = auctionManager.validateBid(message['AuctionId'], message['Bid'], message['AuctionOwner'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    print(new_message)

                connstream.send(new_message)
                print("SENT")
                print(connstream.version())
        except Exception:
            print(traceback.format_exc())
            bindsocket.close()

def firstMessage(connstream, message):
    global aesgcm
    global flag
    global owner
    assinPadd = asyPadding.PKCS1v15()
    encrptPadd = asyPadding.OAEP(mgf=asyPadding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    privKey = serialization.load_pem_private_key(open("{}/certs_servers/AuctionManagerKey.pem".format(path), "rb").read(), password=None, backend=default_backend())
    flag = False
    cert = base64.b64decode(message['Cert'])
    cert = x509.load_der_x509_certificate(cert, default_backend())
    cert_chain = build_chain([], cert, [], certs)
    if not checkChain(cert_chain, crls):
        print("Chain Invalid!")
    owner = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    simKey = privKey.decrypt(base64.b64decode(message['Key']), encrptPadd)
    aesgcm = AESGCM(simKey)
    nonce = secrets.token_bytes(16)

    pubKeyCli = cert.public_key()
    text_to_verify = cert.public_bytes(serialization.Encoding.DER) + simKey

    try:
        pubKeyCli.verify(base64.b64decode(message['Assin']), text_to_verify, assinPadd, hashes.SHA1())
        flag = True
    except Exception:
        print("Invalid Message!")

    if flag:
        message = json.dumps({ 'ACK' : 'Ok' })
        nonce, requestEnc = encrypt(nonce, message)
        payload = json.dumps({'Message' : requestEnc, 'Nonce' : nonce })
        size = sys.getsizeof(header + str(payload))
        size += sys.getsizeof(size)
        message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
        connstream.sendall(message)
    return flag, aesgcm, owner

def connClient():
    global flag
    global owner
    global aesgcm
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 2019))
    #s.bind(('192.168.1.2', 2019))
    s.listen(5)

    while True:
        connstream, addr = s.accept()
        new_data = receive(connstream)
        message = json.loads(new_data)

        if 'Cert' in message.keys():
            flag, aesgcm, owner = firstMessage(connstream, message)

        if flag:
            try:
                while True:
                    new_data = receive(connstream)
                    message = json.loads(new_data)
                    nonce, message = decrypt(message['Nonce'], message['Message'])
                    id = message['Id']
                    new_message = b''

                    if id == 0:
                        payload = auctionManager.createAuction(message['Name'], message['Type'], message['Time_to_end'], owner, message['Descr'], message['PubKey'], message['Dynamic_val'], message['Dynamic_encryp'], message['Dynamic_decryp'], message['Dynamic_winVal'])
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                        conn = connAuctRepos()
                        conn.sendall(new_message)
                        new_data = json.loads(receive(conn))
                        if new_data['Id'] != 216:
                            auctionManager.clear()
                        nonce, requestEnc = encrypt(nonce, json.dumps(new_data))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 1:
                        payload = auctionManager.endAuction(message['AuctionId'], owner)
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                        conn = connAuctRepos()
                        conn.sendall(new_message)
                        new_data = json.loads(receive(conn))
                        nonce, requestEnc = encrypt(nonce, json.dumps(new_data))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 19:
                        payload = auctionManager.ownersKey(message['AuctionId'], message['ClientKey'], owner)
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                        conn = connAuctRepos()
                        conn.sendall(new_message)
                        new_data = json.loads(receive(conn))
                        nonce, requestEnc = encrypt(nonce, json.dumps(new_data))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')

                    connstream.sendall(new_message)
                    print("SENT")
            except Exception:
                print(traceback.format_exc())
                connstream.close()

def connAuctRepos():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain(certfile="{}/certs_servers/AuctionManagerCli.crt".format(path), keyfile="{}/certs_servers/AuctionManagerCliKey.pem".format(path))
    context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
    context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionRepository")
    conn.connect(("localhost", 2030))
    #conn.connect(("192.168.1.3", 2029))
    return conn

auctionManager = AuctionManager()
header = 'HEAD / HTTP/1.0\r\nSize:'
certs = getCerts()
crls = getCRLs(certs.values())
CA = x509.load_der_x509_certificate(open("/etc/ssl/certs/BaltimoreCyberTrustRoot.crt".format(path), "rb").read(), default_backend())
certs[CA.subject] = CA
aesgcm = ''
flag = False
owner = ''

p = Thread(target=connClient)
p2 = Thread(target=connAuctReposSer)
p.start()
p2.start()
p.join()
p2.join()
