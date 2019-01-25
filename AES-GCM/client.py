import socket, sys, json, secrets, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 2019))
#Constantes a que o Client tem acesso e vai necessitar
header = 'HEAD / HTTP/1.0\r\nSize:'
assinPadd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
encrptPadd = padding.OAEP(mgf =padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
privKey = serialization.load_pem_private_key( open("AuctionRepositoryKey.pem", "rb").read(), password = None,   backend=default_backend())
pubKeyMan = x509.load_pem_x509_certificate( open("AuctionManager.crt", "rb").read(), backend = default_backend()).public_key()
cert = open("AuctionRepository.crt", "rb").read()


#Gera a chave e o nonce que vai usar para enviar o pedido
simKey = AESGCM.generate_key(bit_length=256)
nonce = secrets.token_bytes(16)

#Cria assinatura com o CC dos dados que vai enviar na mensagem
text_to_sign = cert + simKey + nonce
assin = privKey.sign(text_to_sign, assinPadd, hashes.SHA256())
#Encripta os campos necessários
simKeyEnc = pubKeyMan.encrypt(simKey, encrptPadd)
nonceEnc = pubKeyMan.encrypt(nonce, encrptPadd)
#Cria a mensagem a Enviar
payload = json.dumps({'Cert' : base64.b64encode(cert).decode('utf-8'), 'Key' : base64.b64encode(simKeyEnc).decode('utf-8'), 'Nonce' : base64.b64encode(nonceEnc).decode('utf-8'), 'Assin' : base64.b64encode(assin).decode('utf-8')})

message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
#Envia a mensagem
s.sendall(message)
#Espera a verficação do lado do servidor e a sua resposta
data = s.recv(1024)
i = data.index(b':')
idx = data.index(b'{')
message_size = int(data[i+1:idx])
while message_size > 1024:
    message_size -= 1024
    data += s.recv(1024)
new_data = data[idx:]
message = json.loads(new_data)
#Desencripta os campos da mensagem do Servidor e obtém a chave e o nonce que
#este vai usar para encriptar a mensagem de resposta ao pedido.
simKeyMan = privKey.decrypt(base64.b64decode(message['Key']), encrptPadd)
nonceMan = privKey.decrypt(base64.b64decode(message['Nonce']), encrptPadd)
#Verifica a assinatura do Servidor
text_to_verify = simKeyMan + nonceMan
try:
    pubKeyMan.verify(base64.b64decode(message['Assin']), text_to_verify, assinPadd, hashes.SHA256())
except Exception:
    print("Mensagem Inválida")

#Cria a sua chave para encriptar o pedido
aesgcm = AESGCM(simKey)
request = json.dumps({ 'Id' : 1, 'Text' : 'Qualquer Coisa'})
#Assina o pedido
assin = privKey.sign(request.encode(), assinPadd, hashes.SHA256())
#Encripta o pedido e adiciona-o à mensagem
requestEnc = aesgcm.encrypt(nonce, request.encode(), None)
payload = json.dumps({'Message' :base64.b64encode(requestEnc).decode('utf-8'), 'Assin' : base64.b64encode(assin).decode('utf-8')})

message = bytes('{}{}\r\n\r\n{}'.format(header, sys.getsizeof(payload), payload), 'utf-8')
#Envia a mensagem
s.sendall(message)

#Espera a resposta do pedido
data = s.recv(1024)
i = data.index(b':')
idx = data.index(b'{')
message_size = int(data[i+1:idx])
while message_size > 1024:
    message_size -= 1024
    data += s.recv(1024)
new_data = data[idx:]
message = json.loads(new_data)

#Cria a chave para desencriptar a resposta
aesgcm = AESGCM(simKeyMan)
#Desencripta
answer = aesgcm.decrypt(nonceMan, base64.b64decode(message['Message']), None)
#Verifica a assinatura da resposta 
try:
    pubKeyMan.verify(base64.b64decode(message['Assin']), answer, assinPadd, hashes.SHA256())
except Exception:
    print("Mensagem Inválida")

print(json.loads(answer))

s.close()







