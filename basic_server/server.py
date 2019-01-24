import socket, ssl, sys, traceback


def deal_with_client(connstream):
    data = connstream.recv(1024)
    print(data) 
    connstream.send(data)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="../certs_servers/AuctionManager.crt", keyfile="../certs_servers/AuctionManagerKey.pem")
context.load_verify_locations("/etc/ssl/certs/AuctionSigner.crt")
context.options = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False
bindsocket = socket.socket()
bindsocket.bind(('localhost', 2019))
bindsocket.listen(5)

try:
    newsocket, fromaddr = bindsocket.accept()
    connstream = context.wrap_socket(newsocket, server_side=True)
    deal_with_client(connstream)
    print(connstream.version())
    bindsocket.close()
except Exception: 
    print(traceback.format_exc())
    bindsocket.close()
