import Block, json
from datetime import datetime

class Auction:
    def  __init__(self,name, type, auctionId, endTime, desc):
        self.name = name
        self.auctionId = auctionId
        self.endTime = endTime
        self.desc = desc
        self.blockchain = []
        self.winner = ''
        self.type = type

    def setWinner(self, winner):
        self.winner = winner

    def getFirstBlock(self):
        return self.blockchain[0]

    def close(self):
        self.endTime = datetime.now()

    def hasEnded(self):
        return self.endTime >= datetime.now()

    def getLastPosition(self):
        return len(self.blockchain)-1

    def addToBlockChain(self, block):
        self.blockchain.append(block)

    def getLastBlock(self):
        return self.blockchain[-1]
    
    def getBlockChain(self):
        return self.blockchain
'''----------------------------------------------------------------------------------------------------------------------------------------------'''    
    def getWinner(self):
        return winner
    
    def blockToJson(self):
        chain = []
        for i in self.blockchain:
            chain.append(i.getJson())
        return chain

    def getType(self):
        return self.type
    
    def getJson(self):
        return { 'AuctionId' : self.auctionId , 'Blockchain' : self.blockToJson() }
