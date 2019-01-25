import socket, ssl, sys, traceback, json, os
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('Projeto', '/') + "/sio-1819-g84735-84746"
#path = find('sio2018-p1g20', '/')
sys.path.append('{}/classes'.format(path))
import AuctionRepository

def receive(conn):
    data = conn.recv(1024)
    i = data.index(b':')
    idx = data.index(b'{')
    data_size = int(data[i+1:idx])
    while data_size > 1024:
        data_size -= 1024
        data += conn.recv(1024)
    new_data = data[idx:]
    return new_data

def connClient():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="{}/certs_servers/AuctionRepository.crt".format(path), keyfile="{}/certs_servers/AuctionRepositoryKey.pem".format(path))
    context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
    context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    bindsocket = socket.socket()
    bindsocket.bind(('localhost', 2020))
    #bindsocket.bind(('192.168.1.3', 2019))
    bindsocket.listen(5)
    return bindsocket, context

def connAuctMan():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain(certfile="{}/certs_servers/AuctionRepositoryCli.crt".format(path), keyfile="{}/certs_servers/AuctionRepositoryCliKey.pem".format(path))
    context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
    context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionManager")
    conn.connect(("localhost", 2019))
    #conn.connect(("192.168.1.2", 2019))
    return conn

bindsocket, context = connClient()
auctionRepository = AuctionRepository.AuctionRepository()

try:
    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        client_cert = connstream.getpeercert()
        owner = client_cert['subject']
        new_data = receive(connstream)
        print(new_data)
        message = json.loads(new_data)
        id = message['Id']
        header = 'HEAD / HTTP/1.0\r\nSize:'
        new_message = b''

        if id == 10:
            payload = auctionRepository.showActvAuct()
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 11:
            payload = auctionRepository.showAuction(message['AuctionId'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 12:
            payload = auctionRepository.showWinner(message['AuctionId'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 13:
            payload = auctionRepository.validateBid(message['AuctionId'], message['Bid'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
            conn = connAuctMan()
            conn.sendall(new_message)
            new_data = json.loads(receive(conn))
            if new_data['Id'] == 202:
                payload = auctionRepository.placeBid(message['AuctionId'], message['Bid'])
                new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
            else:
                payload = json.dumps(new_data)
                new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 14:
            payload = auctionRepository.getChallenge(message['AuctionId'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 15:
            payload = auctionRepository.closeAuction(message['Requester'], message['AuctionId'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 16:
            payload = auctionRepository.createAuction(message['Requester'], message['Name'], message['AuctionId'], message['Type'], message['Time_to_end'], message['Descr'], message['Dynamic_val'], message['Dynamic_encryp'], message['PubKey'], message['Dynamic_decryp'], message['Dynamic_winVal'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 20:
            payload = auctionRepository.getFirstBlock(message['AuctionId'])
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')

        print(new_message)
        connstream.send(new_message)
        print(connstream.version())
except Exception:
    print(traceback.format_exc())
    bindsocket.close()
