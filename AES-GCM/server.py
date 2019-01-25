import socket, sys, json, base64, secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', 2019))
s.listen(5)
header = 'HEAD / HTTP/1.0\r\nSize:'
assinPadd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
encrptPadd = padding.OAEP(mgf =padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
privKey = serialization.load_pem_private_key( open("AuctionManagerKey.pem", "rb").read(), password = None,   backend=default_backend())

while True:
    conn, addr = s.accept()
    print('Connected by', addr)
    while True:
        #Recebe a primeira mensagem
        data = conn.recv(1024)
        if not data:
            break
        i = data.index(b':')
        idx = data.index(b'{')
        message_size = int(data[i+1:idx])
        while message_size > 1024 and data.decode()[-1] != "}" :
            message_size -= 1024
            data += conn.recv(1024)
        new_data = data[idx:]
        message = json.loads(new_data)
        #FALTAAAAA
        #Tem de verificar aqui o certificado
        
        #Descencripta a chave e a nonce a ser usada na mensagem que vai receber
        cert = base64.b64decode(message['Cert'])
        simKey = privKey.decrypt(base64.b64decode(message['Key']), encrptPadd)
        nonce = secrets.token_bytes(16)
        aesgcm = AESGCM(simKey)

        pubKeyCli = x509.load_pem_x509_certificate(cert, backend = default_backend()).public_key()
        #Verifica a assinatura dos conteúdos da mesagem recebida
        text_to_verify =  cert + simKey
        try:
            pubKeyCli.verify(base64.b64decode(message['Assin']), text_to_verify, assinPadd, hashes.SHA256())
        except Exception:
            print("Mensagem Inválida")


        #Cria o Json para enviar
        message = json.dumps({'ACK' : "Ok",})
        
        #Gera a assinatura da mensagem que vai enviar
        assin = privKey.sign(message.encode() + nonce, assinPadd, hashes.SHA256())
        
        payload = json.dumps({'Message' : base64.b64encode(aesgcm.encrypt(nonce, message.encode(), None)).decode('utf-8'), 'Nonce' : base64.b64encode(nonce).decode('utf-8'), 'Assin' : base64.b64encode(assin).decode('utf-8') })

        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        #Envia
        conn.sendall(message)
        #Recebe a mensagem com o pedido a realizar
        data = conn.recv(1024)
        i = data.index(b':')
        idx = data.index(b'{')
        while message_size > 1024 and data.decode()[-1] != "}" :
            message_size -= 1024
            data += conn.recv(1024)
        new_data = data[idx:]
        message = json.loads(new_data)

        decNonce = base64.b64decode(message['Nonce'])
        #Cria a chave para desencriptar o pedido
        request = aesgcm.decrypt(decNonce, base64.b64decode(message['Message']), None)

        #Agora faz o tratamento da mensagem que recebeu e cria a resposta
        answer = request.decode()

        nonce += secrets.token_bytes(16)
        
        #Encripta a mensagem e adiciona-a na mensagem a ser enviada.
        answer = aesgcm.encrypt(nonce, answer.encode(), None)
        payload = json.dumps({'Message' : base64.b64encode(answer).decode('utf-8'), 'Nonce' : base64.b64encode(nonce).decode('utf-8')})

        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        #Envia a resposta.
        conn.sendall(message)

    conn.close()
    break







