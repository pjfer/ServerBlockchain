import json, secrets, base64
from datetime import datetime
from Auction import Auction
from Bid import Bid
from Block import Block
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

class AuctionRepository:
    def __init__(self):
        self.activeAuctions = {} #contém os auctions ativos {id, auction}
        self.finishedAuctions = {} #contém os auctions acabados {id, auction}
        self.key = serialization.load_pem_private_key( open("../certs_servers/AuctionManagerKey.pem", "rb").read(), password = None,   backend=default_backend())

        self.padding = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)

    def showActvAuct(self):
        auctions = {}
        
        for auctionId in self.activeAuctions:
            auctions[auctionId] = { 'Type' : self.activeAuctions[auctionId].getType() }

        response = { 'Id' : 17, 'Auctions' : auctions }
        return json.dumps(response)
            

    def showAuction(self, auctionId):
        if auctionId in self.activeAuctions: 
            return json.dumps( { 'Id' : 18, 'Chain' : self.activeAuctions[auctionId].getJson() })

        elif auctionId in self.finishedAuctions:
            return json.dumps( { 'Id' : 18, 'Chain' : self.finishedAuctions[auctionId].getJson()})

        return json.dumps({ 'Id':111, 'Reason': 'Auction does not exist' })
        
    def showWinner(self, auctionId):
        if auctionId in self.finishedAuctions and not self.finishedAuctions[auctionId].getWinner() ==  None:
            return json.dumps({ 'Id':212, 'Winner': self.finishedAuctions[auctionId].getWinner() })

        return json.dumps({ 'Id':112, 'Reason':'Auction does not exist or it isnt finished'})
            
    def placeBid(self, auctionId, bid):
        recvTime = datetime.now()
        if auctionId in self.activeAuctions:

            if self.verifyChallenge(auctionId, bid):
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

                #Cria o link para o previous block
                previousLink = self.activeAuctions[auctionId].getLastBlock().getLink() + self.activeAuctions[auctionId].getLastBlock().getRepSign()
                digest.update(previousLink) 
                link =  digest.finalize()
                
                #Vai buscar o challenge que foi respondido para esta bid.
                challenge = json.loads(self.getChallenge(auctionId))
                challenge = {'Challenge' : challenge['Challenge'], 'Difficulty' : challenge['Difficulty'], 'Hash' : challenge['Hash']}
               
                #Criar a assinatura do AuctionRep para aquele bloco
                text_to_sign = bid.getAuthor() + bid.getValue() + link + str(recvTime).encode() + json.dumps(challenge).encode()
                assin = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
                #Cria o bloco e adiciona à blockchain
                block = Block(bid, recvTime, link, challenge, assin)
                self.activeAuctions[auctionId].addToBlockChain(block)

                sendTime = datetime.now()
                #Cria a mensagem de resposta (com o receipt).
                text_to_sign = (str(recvTime) + str(sendTime) + "True" + str(self.activeAuctions[auctionId].getLastPosition())).encode()
                ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
                return json.dumps({ 'Id' : 213 , 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'True', 'Pos' : self.activeAuctions[auctionId].getLastPosition(), 'Sign' : base64.b64encode(ass).decode('utf-8') })

            #Se o desafio não for comprido
            sendTime = datetime.now()
            text_to_sign = (str(recvTime) + str(sendTime) + "False").encode()
            ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            return json.dumps({ 'Id' : 113, 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'False', 'Reason' : 'Wrong Answer to Challenge', 'Sign' : base64.b64encode(ass).decode('utf-8') })

        #Se o Auction já tiver acabado ou não existir
        sendTime = datetime.now()
        text_to_sign = (str(recvTime) + str(sendTime) + "False").encode()
        ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
        return json.dumps({ 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'False', 'Reason' : 'Auction as ended or does not exist', 'Sign' : base64.b64encode(ass).decode('utf-8') })

    def getChallenge(self, auctionId):
        if auctionId in self.activeAuctions:
            challenge = self.activeAuctions[auctionId].getLastBlock().getLink()
            nhash = "SHA256"
            dificulty = 3 #número de números iguais a 0.

            return json.dumps({ 'Id' : 214, 'Difficulty' : dificulty, 'Challenge' :  base64.b64encode(challenge).decode('utf-8'), 'Hash' : nhash })
        
        return json.dumps({ 'Id' : 114, 'Reason' : 'Invalid Auction'})        

    def closeAuction(self, requester, auctionId):
        if requester == "AuctionManager": 
            
            if auctionId in self.activeAuctions:
                
                self.activeAuctions[auctionId].close()
                self.finishedAuctions[auctionId] = self.activeAuctions[auctionId]
                self.activeAuctions.pop(auctionId)
                return json.dumps({ 'Id' : 216 })
            
            return json.dumps({ 'Id' : 116, 'Reason' : 'Invalid Auction' })
        
        return json.dumps({ 'Id' : 116, 'Reason' : 'Invalid Requester' })

    def addKeys(self,auctionId, clientKey, auctionManagerKeys):
        if auctionId in self.finishedAuctions:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

            #Cria o link para o previous block
            previousLink = self.finishedAuctions[auctionId].getLastBlock().getLink() + self.finishedAuctions[auctionId].getLastBlock().getRepSign()
            digest.update(previousLink) 
            link =  digest.finalize()
            text_to_sign = base64.b64decode(clientKey) + json.dumps(auctionManagerKeys).encode() + link 
            assin = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            #Cria o bloco e adiciona à blockchain
            block = Block({'ClientKey' : clientKey, 'AuctManKeys': auctionManagerKeys} , None, link, None, assin)
            self.finishedAuctions[auctionId].addToBlockChain(block)

    def createAuction(self, requester, auctionId, type, endTime, descr, verDin, encDin):
        if auctionId in self.activeAuctions or auctionId in self.finishedAuctions:
            return json.dumps({ 'Id' : 115, 'Reason' : 'Invalid AuctionId' })
        
        if requester == "AuctionManager":
            auction = Auction(type, auctionId, endTime, descr, key)
            self.activeAuctions[auctionId] = auction
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

            #Cria o link para os próximos blocos
            previousLink = secrets.token_bytes(16)
            digest.update(previousLink) 
            link =  digest.finalize()
            text_to_sign = json.dumps(verDin).encode() + json.dumps(encDin).encode() + link 
            assin = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            #Cria o bloco e adiciona à blockchain
            block = Block({'VerDin' : verDin, 'EncDin': encDin, 'PubKey' : key} , None, link, None, assin)
            auction.addToBlockChain(block)
            return json.dumps({ 'Id' : 215 })
        
        return json.dumps({ 'Id' : 115, 'Reason' : 'Invalid Requester' })

    def verifyChallenge(self, auctionId, bid):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        response = bid.getCriptAnswer()
        nonce = response['Nonce']
        dif = response['Difficulty']

        digest.update(nonce + self.activeAuctions[auctionId].getLastBlock().getLink())
        result =  digest.finalize()
        
        if result[0:dif] == 0 and result == response['Response']:
            return True
        else:
            return False
        return True

    def backgroudChecker():
        '''
        Fazer uma Thread que percorre todos os leilões ativos e verifica se estes já acabaram ou não.
        '''
        return True


















