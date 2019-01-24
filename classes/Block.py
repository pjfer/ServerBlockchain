import base64, json
from Bid import Bid

class Block:
    def __init__(self, content, timestamp, link, challenge, repSign):
        self.content = content
        self.timestamp = timestamp
        self.link = link
        self.challenge = challenge
        self.repSign = repSign

    def getContent(self):
        return self.content

    def getTimestamp(self):
        return self.timestamp

    def getLink(self):
        return self.link

    def getChallenge(self):
        return self.challenge

    def getRepSign(self):
        return self.repSign

    def getJson(self):
        if isinstance(self.content, Bid):
            return { 'Content' : self.content.getJson(), 'Timestamp' : str(self.timestamp), 'Link' : base64.b64encode(self.link).decode('utf-8'), 'Challenge' : self.challenge, 'RepSign' : base64.b64encode(self.repSign).decode('utf-8') }
        return {'Content' : self.content, 'Timestamp' : None, 'Link' : base64.b64encode(self.link).decode('utf-8'), 'Challenge' : None, 'RepSign' : base64.b64encode(self.repSign).decode('utf-8') }
