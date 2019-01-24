class Receipt:
    def __init__(self, recTimeStamp, sendTimeStamp, status, chainPosition, repSign):
        self.recTimeStamp = recTimeStamp
        self.sendTimeStamp = sendTimeStamp
        self.status = status
        self.chainPosition = chainPosition
        self.repSign = repSign

    def getRecTS(self):
        return self.recTimeStamp

    def getSendTS(self):
        return self.sendTimeStamp

    def getStatus(self):
        return self.status

    def getChainPosition(self):
        return self.chainPosition

    def getRepSign(self):
        return self.repSign
