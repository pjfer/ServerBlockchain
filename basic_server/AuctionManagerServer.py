import socket, ssl, sys, traceback, json, os
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('Projeto', '/') + "/sio-1819-g84735-84746"
#path = find('sio-1819-g84735-84746', '/')
sys.path.append('{}/classes'.format(path))
import AuctionManager

auctionManager = AuctionManager.AuctionManager()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="{}/certs_servers/AuctionManager.crt".format(path), keyfile="{}/certs_servers/AuctionManagerKey.pem".format(path))
context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False
bindsocket = socket.socket()
bindsocket.bind(('localhost', 2019))
#bindsocket.bind(('192.168.1.2', 2019))
bindsocket.listen(5)

try:
    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        client_cert = connstream.getpeercert()
        owner = client_cert['subject']
        data = connstream.recv(1024)
        i = data.index(b':')
        idx = data.index(b'{')
        message_size = int(data[i+1:idx])
        while message_size > 1024:
            message_size -= 1024
            data += connstream.recv(1024)
        new_data = data[idx:]
        print(new_data)
        message = json.loads(new_data)
        id = message['Id']
        header = 'HEAD / HTTP/1.0\r\nSize:'
        new_message = b''

        if id == 0:
            payload = str(auctionManager.createAuction(message['Type'], message['Time_to_end'], owner, message['Descr']))
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 1:
            payload = str(auctionManager.endAuction(message['AuctionId'], owner))
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        elif id == 2:
            payload = str(auctionManager.validateBid(message['AuctionId'], message['Bid']))
            new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        #else:
        #Enviar para o Repository ou dar erro/ignorar

        connstream.send(new_message)
        print(connstream.version())
except Exception:
    print(traceback.format_exc())
    bindsocket.close()
