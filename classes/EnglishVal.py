if auctionId in self.auctions.keys() and owner != self.auctions[auctionId][4]:
    bid_value = bid['Value']
    if self.last_bid != {} and bid_value > self.last_bid['Value'] and (bid_value - self.last_bid['Value']) >= self.min_value:
        bid = self.encrypt(auctionId, bid)
        payload = json.dumps({ 'Id' : 202, 'AuctionId' : auctionId, 'Bid' :  bid })
    elif self.last_bid == {} and bid_value >= self.min_value:
        bid = self.encrypt(auctionId, bid)
        payload = json.dumps({ 'Id' : 202, 'AuctionId' : auctionId, 'Bid' :  bid })
    else:
        payload = json.dumps({ 'Id' : 102, 'Reason' : 'Invalid bid!' })
else:
    payload = json.dumps({ 'Id' : 102, 'Reason' : 'Invalid Auction or you are the owner of the Auction!' })
