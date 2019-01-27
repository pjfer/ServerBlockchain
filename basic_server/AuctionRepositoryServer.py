import socket, ssl, sys, traceback, json, os, secrets, base64
from os import scandir
from threading import Thread
from cryptography import x509
from datetime import datetime
from collections import OrderedDict
from cryptography.x509.oid import NameOID
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
path = find('Projeto', '/') + "/sio2018-p1g20"
#path = find('sio2018-p1g20', '/')
sys.path.append('{}/classes'.format(path))
from AuctionRepository import AuctionRepository

def validation(cert):
    return x509.load_pem_x509_certificate(cert, default_backend())

def trustAnchor():
    roots = dict()

    for fil in scandir('/etc/ssl/certs'):
        if '.pem' in fil.path:
            with open(fil.path, 'rb') as f:
                cert1 = f.read()
                cert = validation(cert1)
                if datetime.now() < cert.not_valid_after:
                    roots[cert.subject] = cert
    return roots

def build_issues(chain, cert, user_roots, roots):
    chain.append(cert)
    issuer = cert.issuer
    subject = cert.subject

    if issuer == subject and subject in roots.keys():
        print("Chain completed!")
        return chain

    if issuer in user_roots.keys():
        return build_issues(chain, user_roots[issuer], user_roots, roots)

    if issuer in roots.keys():
        return build_issues(chain, roots[issuer], user_roots, roots)

    print("Chain not found!")
    return

def validatePath(chain):
    if len(chain) < 1:
        return True

    cert = chain[-1]
    chain.remove(cert)
    signature = cert.signature

    #if not cert in crl:
    if not cert in []:
        return True and validatePath(chain)
    else:
        return False and validatePath(chain)
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
    nonce += secrets.token_bytes(16)
    requestEnc = aesgcm.encrypt(nonce, request.encode(), None)
    nonce = base64.b64encode(nonce).decode('utf-8')
    requestEnc = base64.b64encode(requestEnc).decode('utf-8')
    return nonce, requestEnc

def decrypt(nonce, response):
    nonce = base64.b64decode(nonce)
    responseDec = aesgcm.decrypt(nonce, base64.b64decode(response), None)
    return nonce, json.loads(responseDec.decode())

def connAuctManSer():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="{}/certs_servers/AuctionRepository.crt".format(path), keyfile="{}/certs_servers/AuctionRepositoryKey.pem".format(path))
    context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
    context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    bindsocket = socket.socket()
    bindsocket.bind(('localhost', 2030))
    #bindsocket.bind(('192.168.1.3', 2029))
    bindsocket.listen(5)
    
    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        
        try:
            while True:
                client_cert = connstream.getpeercert()
                owner = client_cert['subject'][-1][-1][-1]
                new_data = receive(connstream)
                message = json.loads(new_data)
                id = message['Id']
                new_message = b''

                if id == 10:
                    payload = auctionRepository.showActvAuct()
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 11:
                    payload = auctionRepository.showAuction(message['AuctionId'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 12:
                    payload = auctionRepository.showWinner(message['AuctionId'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 13:
                    payload = auctionRepository.validateBid(message['AuctionId'], message['Bid'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    conn = connAuctMan()
                    conn.sendall(new_message)
                    new_data = json.loads(receive(conn))
                    if new_data['Id'] == 202:
                        payload = auctionRepository.placeBid(message['AuctionId'], message['Bid'])
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    else:
                        payload = json.dumps(new_data)
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 14:
                    payload = auctionRepository.getChallenge(message['AuctionId'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 15:
                    payload = auctionRepository.closeAuction(message['Requester'], message['AuctionId'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 16:
                    payload = auctionRepository.createAuction(message['Requester'], message['Name'], message['AuctionId'], message['Type'], message['Time_to_end'], message['Descr'], message['Dynamic_val'], message['Dynamic_encryp'], message['PubKey'], message['Dynamic_decryp'], message['Dynamic_winVal'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                elif id == 20:
                    payload = auctionRepository.getFirstBlock(message['AuctionId'])
                    size = sys.getsizeof(header + str(payload))
                    size += sys.getsizeof(size)
                    new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')

                print(new_message)
                connstream.send(new_message)
                print(connstream.version())
        except Exception:
            print(traceback.format_exc())
            bindsocket.close()

def firstMessage(connstream, message):
    global aesgcm
    global flag
    global owner
    assinPadd = asyPadding.PSS(mgf=asyPadding.MGF1(hashes.SHA256()), salt_length=asyPadding.PSS.MAX_LENGTH)
    encrptPadd = asyPadding.OAEP(mgf=asyPadding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    privKey = serialization.load_pem_private_key(open("{}/certs_servers/AuctionRepositoryKey.pem".format(path), "rb").read(), password=None, backend=default_backend())
    flag = False
    cert = base64.b64decode(message['Cert'])
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    user_roots = { cert.subject:cert }
    chain = build_issues([], cert, user_roots, roots)
    owner = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    simKey = privKey.decrypt(base64.b64decode(message['Key']), encrptPadd)
    nonce = secrets.token_bytes(16)
    aesgcm = AESGCM(simKey)

    pubKeyCli = cert.public_key()
    text_to_verify = cert.public_bytes(serialization.Encoding.PEM) + simKey

    try:
        flag = pubKeyCli.verify(base64.b64decode(message['Assin']), text_to_verify, assinPadd, hashes.SHA256())
        #flag = True
    except Exception:
        print("Invalid Message!")

    flag = True

    if flag:
        message = json.dumps({ 'ACK' : 'Ok' })
        assin = privKey.sign(message.encode() + nonce, assinPadd, hashes.SHA256())
        nonce, requestEnc = encrypt(nonce, message)
        payload = json.dumps({'Message' : requestEnc, 'Nonce' : nonce, 'Assin' : base64.b64encode(assin).decode('utf-8') })
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
    s.bind(('localhost', 2020))
    #s.bind(('192.168.1.3', 2019))
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

                    if id == 10:
                        nonce, requestEnc = encrypt(nonce, auctionRepository.showActvAuct())
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 11:
                        nonce, requestEnc = encrypt(nonce, auctionRepository.showAuction(message['AuctionId']))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 12:
                        nonce, requestEnc = encrypt(nonce, auctionRepository.showWinner(message['AuctionId']))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 13:
                        payload = auctionRepository.validateBid(message['AuctionId'], message['Bid'])
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                        conn = connAuctMan()
                        conn.sendall(new_message)
                        new_data = json.loads(receive(conn))
                        if new_data['Id'] == 202:
                            nonce, requestEnc = encrypt(nonce, auctionRepository.placeBid(message['AuctionId'], message['Bid']))
                            payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                            size = sys.getsizeof(header + str(payload))
                            size += sys.getsizeof(size)
                            new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                        else:
                            nonce, requestEnc = encrypt(nonce, json.dumps(new_data))
                            payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                            size = sys.getsizeof(header + str(payload))
                            size += sys.getsizeof(size)
                            new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 14:
                        nonce, requestEnc = encrypt(nonce, auctionRepository.getChallenge(message['AuctionId']))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 15:
                        nonce, requestEnc = encrypt(nonce, auctionRepository.closeAuction(message['Requester'], message['AuctionId']))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
                    elif id == 20:
                        nonce, requestEnc = encrypt(nonce, auctionRepository.getFirstBlock(message['AuctionId']))
                        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                        size = sys.getsizeof(header + str(payload))
                        size += sys.getsizeof(size)
                        new_message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')

                    connstream.send(new_message)
                    print("SENT")
            except Exception:
                print(traceback.format_exc())
                connstream.close()

def connAuctMan():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain(certfile="{}/certs_servers/AuctionRepositoryCli.crt".format(path), keyfile="{}/certs_servers/AuctionRepositoryCliKey.pem".format(path))
    context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
    context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionManager")
    conn.connect(("localhost", 2029))
    #conn.connect(("192.168.1.2", 2029))
    return conn

auctionRepository = AuctionRepository()
header = 'HEAD / HTTP/1.0\r\nSize:'
roots = trustAnchor()
aesgcm = ''
flag = False
owner = ''

p = Thread(target=connClient)
p2 = Thread(target=connAuctManSer)
p.start()
p2.start()
p.join()
p2.join()
