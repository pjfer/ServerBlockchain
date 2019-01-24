import socket, ssl, sys, traceback, secrets, json, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Bid import Bid
from Auction import Auction

def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in dirs:
            return os.path.join(root, name)

path = find('Projeto', '/') + "/sio-1819-g84735-84746/classes/"
#path = find('sio-1819-g84735-84746', '/') + "/classes/"

class AuctionManager:
    def __init__(self):
        self.auctions = {} #Contém o código a executar em cada auction (val, enc) e o dono do auction (owner)
        self.n_auction = -1
        self.standVer = [open(path + 'EnglishVal.py').read(), open(path + 'BlindVal.py').read()] #Contém o código de verificação standard
        self.standEnc = [open(path + 'EnglishEncrypt.py').read(), open(path + 'BlindEncrypt.py').read()] #Contém o código de encriptação standard
        self.auction_keys = {} #Contém as chaves de encriptação para cada auction {id, []}

    def createAuction(self, type, time_to_end, owner, description, costumVal=None, costumEncryp=None):
        if type == 0 and costumVal != None and customEncryp != None:
            self.auctions[self.n_auction+1] = (costumVal, costumEncryp, owner)
        else:
            self.auctions[self.n_auction+1] = (self.standVer[type], self.standEnc[type], owner)
        self.n_auction += 1
        return json.dumps({ 'Id' : 16, 'AuctionId' : self.n_auction, 'Auction_type' : type, 'Dynamic_val' : self.auctions[self.n_auction][0], 'Dynamic_encryp' : self.auctions[self.n_auction][1], 'Time_to_end' : str(time_to_end), 'Descr' : description})
    
    def endAuction(self, auctionId, owner):
        if auctionId in self.auctions:
            if self.auctions[auctionId][2] == owner:
                return json.dumps({ 'Id':15, 'N_auction': auctionId})
            return json.dumps({ 'Id':101, 'Reason':'No permissions!' })
        return json.dumps({ 'Id': 101, 'Reason' : 'Invalid Auction'})

    def validateBid(self, auctionId, bid):
        exec(self.auctions[auctionId][0])
        if auctionId in self.auctions: 
	    #if auctions[auctionId][0](bid):
            if True: 
                #bid = self.encrypt(auctionId, bid)
                #enc dinâmica bid = auctions[acutionId][1](bid, key)
                return json.dumps({ 'Id' : 202, 'N_auction' : auctionId, 'Bid' :  bid.getJson()})
            return json.dumps({ 'Id':102, 'Reason':'Invalid bid!' })
        return json.dumps({ 'Id': 101, 'Reason' : 'Invalid Auction!'})

    def ownerAsks(self, auctionId, privKey):
        return

    def encrypt(self, auctionId, bid):
        exec(self.auctions[auctionId][1])
    	#Seguir este exemplo
        key = secrets.token_bytes(32)
        backend = default_backend()
        algorithm = algorithms.AES(key)
        iv_list = []
        
        '''Para cada Campo a Encriptar
        iv = secrets.token_bytes(16)
        iv_list.append(iv)
        mode = modes.CBC(iv)
        cipher = Cipher(algorithm, mode, backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bid.getAuthor()) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        bid.setAuthor(ct)

        self.auction_keys[auctionId] = (key, iv_list)
        return bid
        '''
        
        '''Como Funciona a Desencriptação
        unpadder = padding.PKCS7(128).unpadder()
        cipher = Cipher(algorithms.AES(self.auction_keys[auctionId][0]), modes.CBC(self.auction_keys[auctionId][1][0]), backend)
        decryptor = cipher.decryptor()
        print(unpadder.update(decryptor.update(base64.b64decode(bid.getJson()['Author'])) + decryptor.finalize()) + unpadder.finalize())
	'''
