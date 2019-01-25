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
        while message_size > 1024:
            message_size -= 1024
            data += conn.recv(1024)
        new_data = data[idx:]
        message = json.loads(new_data)
        #FALTAAAAA
        #Tem de verificar aqui o certificado
        pubKeyRep = x509.load_pem_x509_certificate( base64.b64decode(message['Cert']), backend = default_backend()).public_key()
        #Descencripta a chave e a nonce a ser usada na mensagem que vai receber
        simKeyCli = privKey.decrypt(base64.b64decode(message['Key']), encrptPadd)
        nonceCli = privKey.decrypt(base64.b64decode(message['Nonce']), encrptPadd)
        #Verifica a assinatura dos conteúdos da mesagem recebida
        text_to_verify =  base64.b64decode(message['Cert']) + simKeyCli + nonceCli
        try:
            pubKeyRep.verify(base64.b64decode(message['Assin']), text_to_verify, assinPadd, hashes.SHA256())
        except Exception:
            print("Mensagem Inválida")

        #Gera a chave e o nonce que vai usar para responder à próxima mensagem
        simKey = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(16)
        
        #Gera a assinatura da mensagem que vai enviar
        assin = privKey.sign(simKey + nonce, assinPadd, hashes.SHA256())

        simKeyEnc = pubKeyRep.encrypt(simKey, encrptPadd)
        nonceEnc = pubKeyRep.encrypt(nonce, encrptPadd)
        #Cria o Json para enviar
        payload = json.dumps({'Key' : base64.b64encode(simKeyEnc).decode('utf-8'), 'Nonce' : base64.b64encode(nonceEnc).decode('utf-8'), 'Assin' : base64.b64encode(assin).decode('utf-8')})
        
        new_message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        #Envia
        conn.sendall(new_message)
        
        #Recebe a mensagem com o pedido a realizar
        data = conn.recv(1024)
        i = data.index(b':')
        idx = data.index(b'{')
        message_size = int(data[i+1:idx])
        while message_size > 1024:
            message_size -= 1024
            data += conn.recv(1024)
        new_data = data[idx:]
        message = json.loads(new_data)
        #Cria a chave para desencriptar o pedido
        aesgcm = AESGCM(simKeyCli)
        request = aesgcm.decrypt(nonceCli, base64.b64decode(message['Message']), None)

        #Agora faz o tratamento da mensagem que recebeu e cria a resposta
        answer = request.decode()

        #Gera a chave para enviar a resposta ao pedido do cliente
        aesgcm = AESGCM(simKey)
        
        #Encripta a mensagem e adiciona-a na mensagem a ser enviada.
        answer = aesgcm.encrypt(nonce, answer.encode(), None)
        payload = json.dumps({'Message' : base64.b64encode(answer).decode('utf-8')})

        message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
        #Envia a resposta.
        conn.sendall(message)

    conn.close()
    break







