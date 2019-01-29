import json, secrets, base64, os, sys, random, time
from threading import Thread
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as syPadding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asyPadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Bid import Bid
from Block import Block
from Auction import Auction

def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)
path = find('sio2018-p1g20', '/')

class AuctionRepository:
    def __init__(self):
        self.activeAuctions = {} #contém os auctions ativos {id, auction}
        self.finishedAuctions = {} #contém os auctions acabados {id, auction}
        self.key = serialization.load_pem_private_key(open("{}/certs_servers/AuctionRepositoryKey.pem".format(path), "rb").read(), password = None, backend=default_backend())
        self.padding = asyPadding.PSS(mgf =asyPadding.MGF1(hashes.SHA256()), salt_length = asyPadding.PSS.MAX_LENGTH)
        self.receiptId = 0
        self.difficulty = random.randint(1, 2)
        p = Thread(target=self.backgroundChecker)
        p.start()

    def showActvAuct(self):
        auctions = {}
        
        for auctionId in self.activeAuctions:
            remaining_time = self.activeAuctions[auctionId].getEndTime() - datetime.now()
            remaining_time = int(remaining_time.seconds / 60) + (remaining_time.seconds % 60 > 0)
            auctions[auctionId] = { 'Type' : self.activeAuctions[auctionId].getType(), 'Remaining Time' : remaining_time }
        return json.dumps({ 'Id' : 17, 'Auctions' : auctions })

    def showFinAuct(self):
        auctions = {}
        for auctionId in self.finishedAuctions:
            auctions[auctionId] = { 'Type' : self.finishedAuctions[auctionId].getType() }
        return json.dumps({ 'Id' : 221, 'Auctions' : auctions })
            
    def showAuction(self, auctionId):
        if auctionId in self.activeAuctions: 
            return json.dumps( { 'Id' : 18, 'Chain' : self.activeAuctions[auctionId].getJson(), 'Status' : True })
        elif auctionId in self.finishedAuctions and self.finishedAuctions[auctionId].getWinner() != '':
            return json.dumps( { 'Id' : 18, 'Chain' : self.finishedAuctions[auctionId].getJson(), 'Status' : False, 'Winner' : self.finishedAuctions[auctionId].getWinner() })
        elif auctionId in self.finishedAuctions and self.finishedAuctions[auctionId].getWinner() == '':
            return json.dumps( { 'Id' : 18, 'Chain' : self.finishedAuctions[auctionId].getJson(), 'Status' : True })

        return json.dumps({ 'Id' : 111, 'Reason' : 'Auction does not exist' })

    def getFirstBlock(self, auctionId):
        if auctionId in self.activeAuctions:
            first_block = self.activeAuctions[auctionId].getFirstBlock()
            return json.dumps({ 'Id' : 220, 'FirstBlock' : first_block.getJson() })
        return json.dumps({ 'Id' : 120, 'Reason' : 'Invalid Auction!' })
        
    def showWinner(self, auctionId):
        if auctionId in self.finishedAuctions and not self.finishedAuctions[auctionId].getWinner() ==  "":
            return json.dumps({ 'Id':212, 'Winner': self.finishedAuctions[auctionId].getWinner() })
        return json.dumps({ 'Id':112, 'Reason':'Auction does not exist or it isnt finished'})

    def validateBid(self, auctionId, bid, owner):
        if auctionId in self.activeAuctions:
            return json.dumps({ 'Id' : 2, 'AuctionId' : auctionId, 'Bid' : bid, 'AuctionOwner' : owner })
        return json.dumps({ 'Id' : 102, 'Reason' : 'Invalid Auction!' })
            
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
                text_to_sign = base64.b64decode(bid['Signature']) + link + str(recvTime).encode() + json.dumps(challenge).encode()
                assin = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
                #Cria o bloco e adiciona à blockchain
                block = Block(bid, recvTime, link, challenge, assin)
                self.activeAuctions[auctionId].addToBlockChain(block)

                sendTime = datetime.now()
                #Cria a mensagem de resposta (com o receipt).
                text_to_sign = (str(recvTime) + str(sendTime) + "True" + str(self.activeAuctions[auctionId].getLastPosition())).encode()
                ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
                self.difficulty = random.randint(1, 2)
                return json.dumps({ 'Id' : 213 , 'AuctionId' : auctionId, 'ReceiptId' : self.receiptId, 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'True', 'Pos' : self.activeAuctions[auctionId].getLastPosition(), 'Sign' : base64.b64encode(ass).decode('utf-8') })

            #Se o desafio não for comprido
            sendTime = datetime.now()
            text_to_sign = (str(recvTime) + str(sendTime) + "False").encode()
            ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            return json.dumps({ 'Id' : 113, 'AuctionId' : auctionId, 'ReceiptId' : self.receiptId, 'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'False', 'Reason' : 'Wrong Answer to Challenge', 'Sign' : base64.b64encode(ass).decode('utf-8') })

        #Se o Auction já tiver acabado ou não existir
        sendTime = datetime.now()
        text_to_sign = (str(recvTime) + str(sendTime) + "False").encode()
        ass = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
        return json.dumps({'Id' : 113, 'AuctionId' : auctionId, 'ReceiptId' : self.receiptId,'TimestampRec' : str(recvTime), 'TimestampEnv' : str(sendTime), 'Success' : 'False', 'Reason' : 'Auction as ended or does not exist!', 'Sign' : base64.b64encode(ass).decode('utf-8') })

    def getChallenge(self, auctionId):
        if auctionId in self.activeAuctions:
            challenge = self.activeAuctions[auctionId].getLastBlock().getLink()
            nhash = "SHA256"

            return json.dumps({ 'Id' : 214, 'Difficulty' : self.difficulty, 'Challenge' :  base64.b64encode(challenge).decode('utf-8'), 'Hash' : nhash })
        
        return json.dumps({ 'Id' : 114, 'Reason' : 'Invalid Auction'}) 

    def closeAuction(self, requester, auctionId):
        if requester == "AuctionManagerCli": 
            if auctionId in self.activeAuctions:
                self.activeAuctions[auctionId].close()
                self.finishedAuctions[auctionId] = self.activeAuctions[auctionId]
                self.activeAuctions.pop(auctionId)
                return json.dumps({ 'Id' : 215 })
            return json.dumps({ 'Id' : 115, 'Reason' : 'Invalid Auction' })
        return json.dumps({ 'Id' : 115, 'Reason' : 'Invalid Requester' })

    def addKeys(self, auctionId, clientKey, auctionManagerKeys):
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
            chain = list(self.finishedAuctions[auctionId].getBlockChain())
            winValCode = base64.b64decode(self.finishedAuctions[auctionId].getFirstBlock().getContent()['WinValDin'])
            exec(winValCode, locals(), globals())
            self.finishedAuctions[auctionId].setWinner(winner.decode())
            return json.dumps({ 'Id' : 219 })
        else:
            return json.dumps({ 'Id' : 119, 'Reason' : 'Auction is not finnished!' })

    def createAuction(self, requester, name, auctionId, type, endTime, descr, verDin, encDin, key, decDin, winValDin):
        if auctionId in self.activeAuctions or auctionId in self.finishedAuctions:
            return json.dumps({ 'Id' : 116, 'Reason' : 'Invalid AuctionId' })
        
        if requester == "AuctionManager":
            auction = Auction(name, type, auctionId, datetime.strptime(endTime[:19], "%Y-%m-%d %H:%M:%S"), descr)
            self.activeAuctions[auctionId] = auction
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

            #Cria o link para os próximos blocos
            previousLink = secrets.token_bytes(16)
            digest.update(previousLink) 
            link =  digest.finalize()
            verDinDec = base64.b64decode(verDin)
            encDinDec = base64.b64decode(encDin)
            decDinDec = base64.b64decode(decDin)
            winValDinDec = base64.b64decode(winValDin)
            keyDec = base64.b64decode(key)
            text_to_sign = verDinDec + encDinDec + keyDec + decDinDec + winValDinDec + link
            assin = self.key.sign(text_to_sign, self.padding, hashes.SHA256())
            #Cria o bloco e adiciona à blockchain
            block = Block({'VerDin' : verDin, 'EncDin': encDin, 'PubKey' : key, 'DecDin' : decDin, 'WinValDin' : winValDin } , None, link, None, assin)
            auction.addToBlockChain(block)
            return json.dumps({ 'Id' : 216 })
        return json.dumps({ 'Id' : 116, 'Reason' : 'Invalid Requester' })

    def verifyChallenge(self, auctionId, bid):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        response = bid['CriptAnswer']
        nonce = base64.b64decode(response['Nonce'])
        digest.update(nonce + self.activeAuctions[auctionId].getLastBlock().getLink())
        result =  digest.finalize()
        
        if result[0:self.difficulty] == b'0'*self.difficulty and result == base64.b64decode(response['Response']):
            return True
        return False

    def backgroundChecker(self):
        aId = -1

        while True:
            for auctionId in self.activeAuctions:
                if self.activeAuctions[auctionId].hasEnded():
                    self.activeAuctions[auctionId].close()
                    aId = auctionId
            if aId != -1:
                self.finishedAuctions[aId] = self.activeAuctions[aId]
                self.activeAuctions.pop(aId)
                aId = -1
            time.sleep(5)
