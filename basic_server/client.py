import ssl, socket, sys, json, base64, os
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('Projeto', '/') + "/sio-1819-g84735-84746"
#path = find('sio2018-p1g20', '/')
sys.path.append('{}/classes'.format(path))
import Client

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

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_cert_chain(certfile="{}/certs_servers/AuctionRepositoryCli.crt".format(path), keyfile="{}/certs_servers/AuctionRepositoryCliKey.pem".format(path))
context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")

while True:
    client = Client.Client()

    option = int(input("""
    1) Create Auction.
    2) Create Bid.
    3) Validate Auction.
    4) Ask for Winner.
    5) Active Auctions.
    6) End Auction.
    0) Exit.
    Option = """))

    header = 'HEAD / HTTP/1.0\r\nSize:'
    message = ''

    if option == 1:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionManager")
        conn.connect(("localhost", 2019))
        #conn.connect(("192.168.1.2", 2019))
        name = input("Auction Name = ")
        type = int(input("Auction Type = "))
        endTime = int(input("Time to End (minutes) = "))
        description = input("Auction Description = ")
        customValFile = input("Validation Filename (None if no file) = ")
        customEncryptFile = input("Encryption Filename (None if no file) = ")
        customDecryptFile = input("Decryption Filename (None if no file) = ")
        customWinValFile = input("Winner Validation Filename (None if no file) = ")
        payload = client.createAuction(name, type, endTime, description, customValFile, customEncryptFile, customDecryptFile, customWinValFile)
        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
    elif option == 2:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionRepository")
        conn.connect(("localhost", 2020))
        #conn.connect(("192.168.1.3", 2019))
        auctionId = int(input("Auction ID = "))
        value = float(input("Bid Value = "))
        if client.getCustomEncrypt() == None:
            payload = json.dumps({ 'Id' : 20, 'AuctionId' : auctionId })
            message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
            conn.sendall(message)
            new_data = receive(conn)
            payload = json.loads(new_data)
            if payload['Id'] == 220:
                first_block = payload['FirstBlock']
                customEncrypt = first_block['Content']['EncDin']
                pubKey = first_block['Content']['PubKey']
                payload = client.createBid(auctionId, value, customEncrypt, pubKey)
                message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
            else:
                message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        else:
            payload = client.createBid(auctionId, value)
            message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
    elif option == 3:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionRepository")
        conn.connect(("localhost", 2020))
        #conn.connect(("192.168.1.3", 2019))
        auctionId = int(input("Auction ID = "))
        payload = client.requestAuction(auctionId)
        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
    elif option == 4:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionRepository")
        conn.connect(("localhost", 2020))
        #conn.connect(("192.168.1.3", 2019))
        auctionId = int(input("Auction ID = "))
        payload = client.requestWinner(auctionId)
        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
    elif option == 5:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionRepository")
        conn.connect(("localhost", 2020))
        #conn.connect(("192.168.1.3", 2019))
        payload = client.showActAuction()
        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
    elif option == 6:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionManager")
        conn.connect(("localhost", 2019))
        #conn.connect(("192.168.1.2", 2019))
        auctionId = int(input("Auction ID = "))
        payload = client.endAuction()
        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
    elif option == 0:
        break

    cert = conn.getpeercert()
    print(message)
    conn.sendall(message)
    data = receive(conn)

    print(data)
