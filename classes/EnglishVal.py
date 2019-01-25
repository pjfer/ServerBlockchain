if auctionId in self.auctions.keys():
    bid_value = bid['Value']
    if bid_value > self.last_value and (bid_value - self.last_value) >= self.min_value:
        self.last_value = bid_value
        bid = self.encrypt(auctionId, bid)
        payload = json.dumps({ 'Id' : 202, 'AuctionId' : auctionId, 'Bid' :  bid })
    else:
        payload = json.dumps({ 'Id' : 102, 'Reason' : 'Invalid bid!' })
else:
    payload = json.dumps({ 'Id' : 102, 'Reason' : 'Invalid Auction!' })
