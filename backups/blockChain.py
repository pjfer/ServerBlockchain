from AuctionRepository import AuctionRepository
from Auction import Auction
from Bid import Bid
from Block import Block
from datetime import datetime, timedelta
import base64, json, secrets, os, fnmatch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

def doChallenge(link, difficulty):  
    #Escolhe um nonce aleatório
    nonce = secrets.token_bytes(8)
    #Cria a função de Hash e obtém o primeiro digest
    hashF = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hashF.update(nonce + link)
    digest = hashF.finalize()
    #Compara o resultado
    while(not digest[0:difficulty] == b'0'*difficulty):
        nonce = secrets.token_bytes(8)
        hashF = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hashF.update(nonce + link)
        digest = hashF.finalize()
    return { 'Nonce' : nonce , 'Response' : digest, 'Difficulty' : difficulty  }

def verifyChain(auctionId, chain, user):
    #Load da Chave do Repository
    padd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
    repKey = x509.load_pem_x509_certificate(open("../certs_servers/AuctionRepository.crt", "rb").read() , backend=default_backend()).public_key()
    #Load dos receipts do cliente
    receipts = fnmatch.filter(os.listdir('.'), 'Auction'+str(auctionId)+'_*.receipt')
    pos = []
    for i in receipts:
        f = open(i)
        receipt = json.loads(f.read())
        if receipt['Success']:
            pos.append(receipt['Pos'])
        f.close()

    for i in range(len(chain)):
        if i != 0:
            #Verificação dos links da blockchain
            link = chain[i].getLink()
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            previousLink = chain[i-1].getLink() + chain[i-1].getRepSign()
            digest.update(previousLink) 
            if link !=  digest.finalize():
                return False
            if i == len(chain)-1:
                try:
                    #Verificação da Assinatura do Repositório do Bloco
                    link = chain[i].getLink()
                    cont =  chain[i].getContent()
                    clientKey = cont['ClientKey']
                    auctionManagerKeys = cont['AuctManKeys']
                    repKey.verify(chain[i].getRepSign(), base64.b64decode(clientKey) + json.dumps(auctionManagerKeys).encode() + link, padd, hashes.SHA256())
                except Exception:
                    return False
            else:
                try:
                    #Verificação da Assinatura do Repositório (para o bloco final com as chaves)
                    link = chain[i].getLink()
                    bid =  chain[i].getContent()
                    challenge = chain[i].getChallenge()
                    time = chain[i].getTimestamp()
                    repKey.verify(chain[i].getRepSign(), bid.getAuthor() + bid.getValue() + link +str(time).encode()+ json.dumps(challenge).encode(), padd, hashes.SHA256())
                    #Verificação da Assinatura da Bid
                    #Falta Desencriptação Completa das bids
                    cliKey = x509.load_pem_x509_certificate(bid.getCert(), backend=default_backend()).public_key()
                    cliKey.verify(bid.getSignature(), bid.getAuthor() + bid.getValue() +str(bid.getTimestamp()).encode()+ str(bid.getCriptAnswer()).encode() + bid.getCert() + bid.getKey(), padd, hashes.SHA256())
                    #Verificação dos seus receipts                   
                    if i in pos and bid.getAuthor() != user:
                        return False
                except Exception as e:
                    return False
        else:
            try:
                #Verificação da Assinatura do Repositório para o primeiro bloco (com as regras do auction)
                link = chain[i].getLink()
                cont =  chain[i].getContent()
                verDin = cont['VerDin']
                encDin = cont['EncDin']
                repKey.verify(chain[i].getRepSign(), json.dumps(verDin).encode() + json.dumps(encDin).encode() + link, padd, hashes.SHA256())
            except Exception:
                return False
    return True

def bidSign(author, value, date, resp, cert, key):
    #Carrega a Chave do Client
    pkey = serialization.load_pem_private_key( open("../certs_servers/AuctionRepositoryKey.pem", "rb").read(), password = None,   backend=default_backend())
    padd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
    #Cria o texto para Assinar
    text_to_sign = author + value + str(date).encode() + str(resp).encode() + cert + key 
    #Retorna a Assinatura dos campos
    return pkey.sign(text_to_sign, padd, hashes.SHA256())

def saveAndValidReceipt(rec):
    #Cria o Receipt a ser Guardado
    receipt = json.dumps( {'TimestampRec' : rec['TimestampRec'], 'TimestampEnv' : rec['TimestampEnv'], 'Success' : rec['Success'], 'Pos' : rec['Pos'], 'Sign' : rec['Sign'] })
    #Carrega a Chave pública do AuctionRepository
    padd = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
    repKey = x509.load_pem_x509_certificate(open("../certs_servers/AuctionRepository.crt", "rb").read() , backend=default_backend()).public_key()
    #Cria o texto de verificação de Assinatura
    text_to_sign = (rec['TimestampRec'] + rec['TimestampEnv'] + rec['Success'] + str(rec['Pos'])).encode()
    #Verifica a Assinatura
    try:
        repKey.verify(base64.b64decode(rec['Sign']), text_to_sign, padd, hashes.SHA256())
    except Exception:
        print("Error Validating Receipt: " + "Auction"+str(rec['AuctionId']) +"_Receipt"+str(rec['ReceiptId'])+".receipt")
    #Guarda o Receipt
    f = open("Auction"+str(rec['AuctionId']) +"_Receipt"+str(rec['ReceiptId'])+".receipt", "w+")
    f.write(receipt)
    f.close()

'''Exemplo de como funcionaria'''

#Cria Auction
a = AuctionRepository()
a.createAuction("AuctionManager","Leilão", 1, 10, (datetime.now() + timedelta(days=1)), "Big Desc", "verificacao dinamica", "encasdasdDin", "pubkey")

#Vai buscar o cert do CC (de assinatura)
cert = open("../certs_servers/AuctionRepository.crt", "rb").read()
c = json.loads(a.getChallenge(1))
date = datetime.now()
#Executa a função de resposta ao challenge
resp = doChallenge(base64.b64decode(c['Challenge']), c['Difficulty'])
#Faz a assinatura para a bid
assin = bidSign(b"Joao", b"750", date, resp, cert, b"key") 
#Cria a bid(tem de encriptar os campos antes)
b = Bid(b"Joao", b"750", date, resp, cert, b"key", assin)
#Envia a bid e guarda o receipt
saveAndValidReceipt(json.loads(a.placeBid(1,b)))

#Leilão é fechado e as keys disponibilizadas.
a.closeAuction("AuctionManager",1)
a.addKeys(1, base64.b64encode(b"key").decode('utf-8'), [{'1': base64.b64encode(b"key1").decode('utf-8')}, {'1' : base64.b64encode(b"key2").decode('utf-8'), '2' : base64.b64encode(b"key3").decode('utf-8')}])
#Vai buscar a chain (supostamente aqui é por o getAuction do repositório->Fazer um préprocessamento para tudo chegar já em bytes, mas assim fica mais simples para o test)
chain = a.finishedAuctions[1].blockchain
#Verifica a integridade do leilão (falta fazer a verificação de um ongoing)
print(verifyChain(1, chain, b"Joao"))






