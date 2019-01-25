self.possible_bids = 3

if auctionId in self.auctions.keys():
    if auctionId in self.bids_made.keys():
        self.bids_made[auctionId] += 1
    else:
        self.bids_made[auctionId] = 1
    if self.bids_made[auctionId] <= self.possible_bids:
        bid = self.encrypt(auctionId, bid)
        payload = json.dumps({ 'Id' : 202, 'AuctionId' : auctionId, 'Bid' :  bid })
    else:
        payload = json.dumps({ 'Id' : 102, 'Reason' : 'Invalid bid!' })
else:
    payload = json.dumps({ 'Id' : 102, 'Reason' : 'Invalid Auction!' })
