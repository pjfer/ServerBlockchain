bid_value = bid['Value']
if self.last_bid != {} and bid_value > self.last_bid['Value'] and (bid_value - self.last_bid['Value']) >= self.min_value:
    validBid = True
elif self.last_bid == {} and bid_value >= self.min_value:
    validBid = True
else:
    validBid = False
