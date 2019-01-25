import json, secrets, base64, random
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
        self.key = serialization.load_pem_private_key( open("../certs_servers/AuctionRepositoryKey.pem", "rb").read(), password = None,   backend=default_backend())

        self.padding = padding.PSS(mgf =padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH)
        self.receiptId = 0
        self.difficulty = random.randint(1, 3)

    def showActvAuct(self):
        auctions = {}
        
        for auctionId in self.activeAuctions:
            auctions[auctionId] = { 'Type' : self.activeAuctions[auctionId].getType() }

        return json.dumps( { 'Id' : 17, 'Auctions' : auctions })

    def showFinAuct(self):
        auctions = {}
        for auctionId in self.finishedAuctions:
            auctions[auctionId] = { 'Type' : self.finishedAuctions[auctionId].getType()}
        #Precisa de novo Id -> a selecionar
        return {'Id' : 300, 'Auctions':auctions}
            
    def showAuction(self, auctionId):
        if auctionId in self.activeAuctions: 
            return json.dumps( { 'Id' : 18, 'Chain' : self.activeAuctions[auctionId].getJson(), 'Status' : True })
#----------------------------------------------------------------------------------------------------------------------------------------------'''
        elif auctionId in self.finishedAuctions and self.finishedAuctions[auctionId].getWinner() != '':
            return json.dumps( { 'Id' : 18, 'Chain' : self.finishedAuctions[auctionId].getJson(), 'Status' : False})
#----------------------------------------------------------------------------------------------------------------------------------------------'''
        elif auctionId in self.finishedAuctions and self.finishedAuctions[auctionId].getWinner() == '':
            return json.dumps( { 'Id' : 18, 'Chain' : self.finishedAuctions[auctionId].getJson(), 'Status' : True})

        return json.dumps({ 'Id':111, 'Reason': 'Auction does not exist' })
        
    def showWinner(self, auctionId):
        if auctionId in self.finishedAuctions and not self.finishedAuctions[auctionId].getWinner() ==  None:
            return json.dumps({ 'Id':212, 'Winner': self.finishedAuctions[auctionId].getWinner() })

        return json.dumps({ 'Id':112, 'Reason':'Auction does not exist or it isnt finished'})
#----------------------------------------------------------------------------------------------------------------------------------------------'''           
    def placeBid(self, auctionId, bid):
        recvTime = datetime.now()
        self.receiptId += 1
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
                text_to_sign = (str(auctionId) + str(self.receiptId) + str(recvTime) + str(sendTime) + "True" + str(self.activeAuctions[auctionId].getLastPosition())).encode()
                ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
                #-------------------
                self.difficulty = random.randint(0, 3)
                return json.dumps({ 'Id' : 213 , 'AuctionId' : auctionId, 'ReceiptId' : self.receiptId, 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'True', 'Pos' : self.activeAuctions[auctionId].getLastPosition(), 'Sign' : base64.b64encode(ass).decode('utf-8') })

            #Se o desafio não for comprido
            sendTime = datetime.now()
            text_to_sign = (str(auctionId) + str(self.receiptId) + str(recvTime) + str(sendTime) + "False").encode()
            ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            return json.dumps({ 'Id' : 113, 'AuctionId' : auctionId, 'ReceiptId' : self.receiptId, 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'False', 'Reason' : 'Wrong Answer to Challenge', 'Sign' : base64.b64encode(ass).decode('utf-8') })

        #Se o Auction já tiver acabado ou não existir
        sendTime = datetime.now()
        text_to_sign = (str(auctionId) + str(self.receiptId) + str(recvTime) + str(sendTime) + "False").encode()
        ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
        return json.dumps({'Id' : 113, 'AuctionId' : auctionId, 'ReceiptId' : self.receiptId,'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'False', 'Reason' : 'Auction as ended or does not exist', 'Sign' : base64.b64encode(ass).decode('utf-8') })

#----------------------------------------------------------------------------------------------------------------------------------------------
    def getChallenge(self, auctionId):
        if auctionId in self.activeAuctions:
            challenge = self.activeAuctions[auctionId].getLastBlock().getLink()
            nhash = "SHA256"

            return json.dumps({ 'Id' : 214, 'Difficulty' : self.difficulty, 'Challenge' :  base64.b64encode(challenge).decode('utf-8'), 'Hash' : nhash })
        
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

    def createAuction(self, requester, name, auctionId, type, endTime, descr, verDin, encDin, key):
        if auctionId in self.activeAuctions or auctionId in self.finishedAuctions:
            return json.dumps({ 'Id' : 115, 'Reason' : 'Invalid AuctionId' })
        
        if requester == "AuctionManager":
            auction = Auction(name, type, auctionId, endTime, descr)
            self.activeAuctions[auctionId] = auction
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

            #Cria o link para os próximos blocos
            previousLink = secrets.token_bytes(16)
            digest.update(previousLink) 
            link =  digest.finalize()
            text_to_sign = json.dumps(verDin).encode() + json.dumps(encDin).encode() + link 	#Adicionar a chave pública à assinatura
            assin = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            #Cria o bloco e adiciona à blockchain
            block = Block({'VerDin' : verDin, 'EncDin': encDin, 'PubKey' : key} , None, link, None, assin)
            auction.addToBlockChain(block)
            return json.dumps({ 'Id' : 215 })
        
        return json.dumps({ 'Id' : 115, 'Reason' : 'Invalid Requester' })
#----------------------------------------------------------------------------------------------------------------------------------------------
    def verifyChallenge(self, auctionId, bid):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        response = bid.getCriptAnswer()
        nonce = response['Nonce']
        digest.update(nonce + self.activeAuctions[auctionId].getLastBlock().getLink())
        result =  digest.finalize()
        
        if result[0:self.difficulty] == b'0'*self.difficulty and result == response['Response']:
            return True
        else:
            return False
        
#-------------------------------------------------Falta Criar uma thread no servidor para estar a correr isto periodicamente---------------------------------------------------------------------------------------------
    def backgroudChecker(self):
        for i in self.activeAuctions:
            if self.activeAuctions[i].hasEnded():
                self.activeAuctions[auctionId].close()
                self.finishedAuctions[auctionId] = self.activeAuctions[auctionId]
                self.activeAuctions.pop(auctionId)


















