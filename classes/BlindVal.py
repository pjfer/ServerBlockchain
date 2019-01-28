self.possible_bids = 5

if auctionId in self.bids_made.keys():
    self.bids_made[auctionId] += 1
else:
    self.bids_made[auctionId] = 1
if self.bids_made[auctionId] <= self.possible_bids:
    validBid = True
else:
    validBid = False
