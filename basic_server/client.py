import ssl, socket, pprint, sys, json, base64, os
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('Projeto', '/') + "/sio-1819-g84735-84746"
#path = find('sio-1819-g84735-84746', '/')
sys.path.append('{}/classes'.format(path))
import Client

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_cert_chain(certfile="{}/certs_servers/AuctionRepositoryCli.crt".format(path), keyfile="{}/certs_servers/AuctionRepositoryCliKey.pem".format(path))
context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")

conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="AuctionManager")
client = Client.Client()

option = int(input("""
1) Create Auction.
2) Create Bid.
3) Validate Auction.
4) Ask for Winner.
5) Active Auctions.
6) End Auction.
Option = """))

header = 'HEAD / HTTP/1.0\r\nSize:'
message = ''

if option == 1:
    conn.connect(("localhost", 2019))
    #conn.connect(("192.168.1.2", 2019))
    type = int(input("Auction Type = "))
    endTime = int(input("Time to End (minutes) = "))
    description = input("Auction Description = ")
    customValFile = input("Validation Filename (None if no file) = ")
    customEncriptFile = input("Encryption Filename (None if no file) = ")
    payload = str(client.createAuction(type, endTime, description, customValFile, customEncriptFile))
    message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
elif option == 2:
    conn.connect(("localhost", 2019))
    #conn.connect(("192.168.1.2", 2019))
    auctionId = input("Auction ID = ")
    value = input("Bid Value = ")
    payload = str(client.createBid(auctionId, value))
    message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
elif option == 3:
    conn.connect(("localhost", 2020))
    #conn.connect(("192.168.1.3", 2019))
    auctionId = input("Auction ID = ")
    payload = str(client.requestAuction(auctionId))
    message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
elif option == 4:
    conn.connect(("localhost", 2020))
    #conn.connect(("192.168.1.3", 2019))
    auctionId = input("Auction ID = ")
    payload = str(client.requestWinner(auctionId))
    message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
elif option == 5:
    conn.connect(("localhost", 2020))
    #conn.connect(("192.168.1.3", 2019))
    payload = str(client.showActAuction())
    message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
elif option == 6:
    conn.connect(("localhost", 2019))
    #conn.connect(("192.168.1.2", 2019))
    auctionId = int(input("Auction ID = "))
    payload = str(client.endAuction())
    message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')

cert = conn.getpeercert()
print(message)
conn.sendall(message)
pprint.pprint(conn.recv(1024))
