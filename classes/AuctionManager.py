import socket, ssl, sys, traceback, secrets, json, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as syPadding
from Bid import Bid
from Auction import Auction

def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)

path = find('Projeto', '/') + "/sio2018-p1g20/classes/"
#path = find('sio2018-p1g20', '/') + "/classes/"

class AuctionManager:
    def __init__(self):
        self.auctions = {} #Contém o código a executar em cada auction (val, enc) e o dono do auction (owner)
        self.n_auction = -1
        self.standVer = [open('{}EnglishVal.py'.format(path)).read(), open('{}BlindVal.py'.format(path)).read()] #Contém o código de verificação standard
        self.standEnc = [open('{}EnglishEncrypt.py'.format(path)).read(), open('{}BlindEncrypt.py'.format(path)).read()] #Contém o código de encriptação standard
        self.standDec = [open('{}EnglishDecrypt.py'.format(path)).read(), open('{}BlindDecrypt.py'.format(path)).read()]
        self.standWinVal = [open('{}EnglishWinVal.py'.format(path)).read(), open('{}BlindWinVal.py'.format(path)).read()]
        self.auction_keys = {} #Contém as chaves de encriptação para cada auction {id : []}
        self.bids_made = {}
        self.last_bid = {}
        self.min_value = 1
        self.max_value = -1
        self.possible_bids = -1
        self.pubKey = b''
        self.key = b''

    def createAuction(self, name, type, time_to_end, owner, description, pubKey, customVal='None', customEncryp='None', customDecryp='None', customWinVal='None'):
        customEncryp = base64.b64decode(customEncryp).decode()
        customDecryp = base64.b64decode(customDecryp).decode()
        customVal = base64.b64decode(customVal).decode()
        customWinVal = base64.b64decode(customWinVal).decode()
        if customEncryp != 'None' and customDecryp != 'None':
            self.auctions[self.n_auction+1] = open(path + customEncryp).read(), open(path + customDecryp).read()
        else:
            self.auctions[self.n_auction+1] = self.standEnc[type], self.standDec[type]
        if customVal != 'None':
            self.auctions[self.n_auction+1] += open(path + customVal).read(),
        else:
            self.auctions[self.n_auction+1] += self.standVer[type],
        if customWinVal != 'None':
            self.auctions[self.n_auction+1] += open(path + customWinVal).read(), owner
        else:
            self.auctions[self.n_auction+1] += self.standWinVal[type], owner
        self.n_auction += 1
        self.auction_keys[self.n_auction] = [pubKey,]
        encryptCode = bytes(self.auctions[self.n_auction][0], 'utf-8')
        decryptCode = bytes(self.auctions[self.n_auction][1], 'utf-8')
        valCode = bytes(self.auctions[self.n_auction][2], 'utf-8')
        winValCode = bytes(self.auctions[self.n_auction][3], 'utf-8')
        return json.dumps({ 'Id' : 16, 'AuctionId' : self.n_auction, 'Name' : name, 'Type' : type, 'Dynamic_val' : base64.b64encode(valCode).decode('utf-8'), 'Dynamic_encryp' : base64.b64encode(encryptCode).decode('utf-8'), 'Dynamic_decryp' : base64.b64encode(decryptCode).decode('utf-8'), 'Dynamic_winVal' : base64.b64encode(winValCode).decode('utf-8'), 'Time_to_end' : str(time_to_end), 'Descr' : description, 'Requester' : "AuctionManager", 'PubKey' : self.auction_keys[self.n_auction][0], 'Owner' : owner })
    
    def endAuction(self, auctionId, owner):
        if auctionId in self.auctions:
            if self.auctions[auctionId][4] == owner:
                return json.dumps({ 'Id' : 15, 'AuctionId' : auctionId, 'Requester' : 'AuctionManager' })
            return json.dumps({ 'Id' : 101, 'Reason' : 'No permissions!' })
        return json.dumps({ 'Id' : 101, 'Reason' : 'Invalid Auction!' })

    def validateBid(self, auctionId, bid, owner):
        exec(self.auctions[auctionId][2], locals(), globals())
        self.last_bid = bid
        return payload

    def ownersKey(self, auctionId, privKey, owner):
        if owner == self.auctions[auctionId][4]:
            self.auction_keys[auctionId].append((privKey,))
            return json.dumps({ 'Id' : 219 })
        return json.dumps({ 'Id' : 119, 'Reason' : 'No permissions!' })

    def clear(self):
        self.last_bid = {}
        self.auctions.pop(self.n_auction, None)

    def encrypt(self, auctionId, bid):
        exec(self.auctions[auctionId][0], locals(), globals())
        self.auction_keys[auctionId].append((key, iv_list,))
        return bid
        
    def decrypt(self, auctionId):
        if auctionId in self.auction_keys.keys():
            return json.dumps({ 'Id' : 221, 'AuctionKeys' : base64.b64encode(self.auction_keys).decode('utf-8') })
        return json.dumps({ 'Id' : 121, 'Reason' : 'Auction Invalid!' })
