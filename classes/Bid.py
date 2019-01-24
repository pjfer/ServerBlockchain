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
        return { 'Nonce' : base64.b64encode(self.criptAnswer['Nonce']).decode('utf-8'), 'Response' : base64.b64encode(self.criptAnswer['Response']).decode('utf-8'), 'Difficulty' : self.criptAnswer['Difficulty'] }


    def getJson(self):
        return json.dumps({ 'Author' : base64.b64encode(self.author).decode('utf-8'), 'Value' : base64.b64encode(self.value).decode('utf-8'), 'Timestamp' : str(self.timestamp), 'CriptAnswer' : self.criptAnswerJson(), 'Key' : base64.b64encode(self.key).decode('utf-8') , 'Signature' : base64.b64encode(self.signature).decode('utf-8') })
