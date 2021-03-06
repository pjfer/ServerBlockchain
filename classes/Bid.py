import base64, json

class Bid:
    def __init__(self, author, value, timestamp, criptAnswer, cert, key, signature):
        self.author = author
        self.value = value
        self.timestamp = timestamp
        self.criptAnswer = criptAnswer
        self.cert = cert
        self.key = key
        self.signature = signature

    def setAuthor(self, author):
        self.author = author

    def setValue(self, value):
        self.value = value
    
    def getAuthor(self):
    	return self.author

    def getValue(self):
    	return self.value

    def getTimestamp(self):
    	return self.timestamp

    def getCriptAnswer(self):
    	return self.criptAnswer

    def getCert(self):
        return self.cert 

    def getKey(self):
        return self.key

    def getSignature(self):
    	return self.signature

    def criptAnswerJson(self):
        return { 'Response' : base64.b64encode(self.criptAnswer['Response']).decode('utf-8') , 'Nonce' : base64.b64encode(self.criptAnswer['Nonce']).decode('utf-8'), 'Difficulty' : self.criptAnswer['Difficulty'] }

    def getJson(self):
        return { 'Author' : base64.b64encode(self.author).decode('utf-8'), 'Value' : self.value, 'Timestamp' : str(self.timestamp), 'CriptAnswer' : self.criptAnswerJson(), 'PubKey' : base64.b64encode(self.key).decode('utf-8'), 'Cert' : base64.b64encode(self.cert).decode('utf-8'), 'Signature' : base64.b64encode(self.signature).decode('utf-8') }
