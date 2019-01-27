import ssl, socket, sys, json, base64, os, secrets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('Projeto', '/') + "/sio2018-p1g20"
#path = find('sio2018-p1g20', '/')
sys.path.append('{}/classes'.format(path))
from Client import Client

def firstMessage():
    if server == 'AuctionManager':
        s.connect(('localhost', 2019))
        #s.connect(('192.168.1.2', 2019))
    else:
        s.connect(('localhost', 2020))
        #s.connect(('192.168.1.3', 2019))
    assinPadd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    encrptPadd = padding.OAEP(mgf =padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    pubKeyMan = x509.load_pem_x509_certificate(open("{}/certs_servers/{}.crt".format(path, server), "rb").read(), backend=default_backend()).public_key()
    #Cria assinatura com o CC dos dados que vai enviar na mensagem
    session, cert, private_key, mechanism = client.getCCData()
    text_to_sign = cert.public_bytes(serialization.Encoding.PEM) + simKey
    assin = client.sign(session, private_key, text_to_sign, mechanism)
    #Encripta os campos necessários
    simKeyEnc = pubKeyMan.encrypt(simKey, encrptPadd)
    #Cria a mensagem a Enviar
    payload = json.dumps({'Cert' : base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode('utf-8'), 'Key' : base64.b64encode(simKeyEnc).decode('utf-8'), 'Assin' : base64.b64encode(assin).decode('utf-8')})
    size = sys.getsizeof(header + str(payload))
    size += sys.getsizeof(size)
    message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
    #Envia a mensagem
    s.sendall(message)
    #Espera a verficação do lado do servidor e a sua resposta
    new_data = receive(s)
    message = json.loads(new_data)
    nonce, responseDec = decrypt(message['Nonce'], message['Message'])

    #Verifica a assinatura do Servidor
    try:
        pubKeyMan.verify(base64.b64decode(message['Assin']), responseDec + nonce, assinPadd, hashes.SHA256())
    except Exception:
        print("Invalid Message!")

    if responseDec['ACK'] != 'Ok':
        print("Invalid Message!")

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

def encrypt(request):
    nonce = secrets.token_bytes(16)
    requestEnc = aesgcm.encrypt(nonce, request.encode(), None)
    nonce = base64.b64encode(nonce).decode('utf-8')
    requestEnc = base64.b64encode(requestEnc).decode('utf-8')
    return nonce, requestEnc

def decrypt(nonce, response):
    nonce = base64.b64decode(nonce)
    responseDec = aesgcm.decrypt(nonce, base64.b64decode(response), None)
    return nonce, json.loads(responseDec.decode())

client = Client()
header = 'HEAD / HTTP/1.0\r\nSize:'
server = ''

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Gera a chave e o nonce que vai usar para enviar o pedido
simKey = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(simKey)

while True:
    option = int(input("""
    1) Create Auction.
    2) Create Bid.
    3) Validate Auction.
    4) Ask for Winner.
    5) Active Auctions.
    6) End Auction.
    0) Exit.
    Option = """))

    message = b''

    if option == 0:
        s.close()
        break

    if option != 1:
        if server == '' or server == 'AuctionManager':
            if server == 'AuctionManager':
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server = 'AuctionRepository'
            firstMessage()
    else:
        if server == '' or server == 'AuctionRepository':
            if server == 'AuctionRepository':
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server = 'AuctionManager'
            firstMessage()

    if option == 1:
        name = input("Auction Name = ")
        type = int(input("Auction Type = "))
        endTime = int(input("Time to End (minutes) = "))
        description = input("Auction Description = ")
        customValFile = input("Validation Filename (None if no file) = ")
        customEncryptFile = input("Encryption Filename (None if no file) = ")
        customDecryptFile = input("Decryption Filename (None if no file) = ")
        customWinValFile = input("Winner Validation Filename (None if no file) = ")
        nonce, requestEnc = encrypt(client.createAuction(name, type, endTime, description, customValFile, customEncryptFile, customDecryptFile, customWinValFile))
        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
        size = sys.getsizeof(header + str(payload))
        size += sys.getsizeof(size)
        message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
    elif option == 2:
        auctionId = int(input("Auction ID = "))
        value = float(input("Bid Value = "))
        if client.getCustomEncrypt() == None:
            nonce, requestEnc = encrypt(json.dumps({ 'Id' : 20, 'AuctionId' : auctionId }))
            payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
            size = sys.getsizeof(header + str(payload))
            size += sys.getsizeof(size)
            message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
            s.sendall(message)
            new_data = receive(s)
            new_data = json.loads(new_data)
            nonce, responseDec = decrypt(new_data['Nonce'], new_data['Message'])
            if responseDec['Id'] == 220:
                first_block = responseDec['FirstBlock']
                customEncrypt = first_block['Content']['EncDin']
                pubKey = first_block['Content']['PubKey']
                print(pubKey)
                nonce, requestEnc = encrypt(client.createBid(auctionId, value, customEncrypt, pubKey))
                payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                size = sys.getsizeof(header + str(payload))
                size += sys.getsizeof(size)
                message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
            else:
                nonce, requestEnc = encrypt(new_data)
                payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
                size = sys.getsizeof(header + str(payload))
                size += sys.getsizeof(size)
                message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
        else:
            nonce, requestEnc = encrypt(client.createBid(auctionId, value))
            payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
            size = sys.getsizeof(header + str(payload))
            size += sys.getsizeof(size)
            message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
    elif option == 3:
        auctionId = int(input("Auction ID = "))
        nonce, requestEnc = encrypt(client.requestAuction(auctionId))
        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
        size = sys.getsizeof(header + str(payload))
        size += sys.getsizeof(size)
        message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
    elif option == 4:
        auctionId = int(input("Auction ID = "))
        nonce, requestEnc = encrypt(client.requestWinner(auctionId))
        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
        size = sys.getsizeof(header + str(payload))
        size += sys.getsizeof(size)
        message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
    elif option == 5:
        nonce, requestEnc = encrypt(client.showActAuction())
        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
        size = sys.getsizeof(header + str(payload))
        size += sys.getsizeof(size)
        message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')
    elif option == 6:
        auctionId = int(input("Auction ID = "))
        nonce, requestEnc = encrypt(client.endAuction(auctionId))
        payload = json.dumps({ 'Message' : requestEnc, 'Nonce' : nonce })
        size = sys.getsizeof(header + str(payload))
        size += sys.getsizeof(size)
        message = bytes('{}{}\r\n\r\n{}\r\n\r\n\r\n'.format(header, size, payload), 'utf-8')

    s.sendall(message)
    print("SENT")
    data = receive(s)
    data = json.loads(data)
    nonce, responseDec = decrypt(data['Nonce'], data['Message'])
    print(responseDec)
