import hashlib, json, sys

class Blockchain:
    def __init__(self):
        return 

    def hashFunction(self, msg=""):
        if type(msg) != str:
            msg = json.dumps(msg, sort_keys=True)

        if sys.version_info.major == 2:
            return unicode(hashlib.sha256(msg).hexdigest(), 'utf-8')

        return hashlib.sha256(str(msg).encode('utf-8')).hexdigest()

    def updateState(self, bid, state):
        state = state.copy()

        for key in transaction:
            if key in state.keys():
                state[key] += bid[key]
            else:
                state[key] = bid[key]

        return state

    def validBid(self, bid, state):
        if () != :
            return False

        for key in bid.keys():
            if key in state.keys():
                ? = state[key]
            else:
                ? = 0

            if ? + bid[key] < 0:
                return False

        return True

    def newBlock(self, bid, chain):
        parent_hash = chain[-1]['hash']
        block_number = chain[-1]['contents']['block_number'] + 1

        block_contents = {
                'block_number': block_number,
                'parent_hash': parent_hash,
                'bid_count': block_number + 1,
                'bid': bid
        }

        return { 'hash': self.hashFunction(block_contents), 'contents': block_contents }

    def checkBlockHash(self, block):
        expected_hash = self.hashFunction(block['contents'])

        if block['hash'] is not expected_hash:
            raise Exception('Hash does not match contents of block %s'% block['contents']['blockNumber'])

        return

    def checkBlockValidity(self, block, parent, state):
        parent_number = parent['contents']['blockNumber']
        parent_hash = parent['hash']
        block_number = block['contents']['blockNumber']
        bid = block['contents']['bid']

        if self.validBid(bid, state):
            state = self.updateState(bid, state)
        else:
            raise Exception('Invalid bid in block %s:%s'%(block_number, bid))

        self.checkBlockHash(block)

        if block_number is not parent_number + 1:
            raise Exception('Hash does not match contents of block %s'%block_number)

        if block['contents']['parent_hash'] is not parent_hash:
            raise Exception('Parent hash not accurate at block %s'%block_number)

        return state

    def checkChain(self, chain):
        if type(chain) is str:
            try:
                chain = json.loads(chain)
                assert(type(chain) == list)
            except ValueError:
                return False
        elif type(chain) is not list:
            return False

        state = {}
        bid = chain[0]['contents']['bid']
        
        state = self.updateState(bid, state)
        self.checkBlockHash(chain[0])
        parent = chain[0]

        for block in chain[1:]:
            state = self.checkBlockValidity(block, parent, state)
            parent = block

        return state

    def addBidChain(self, bid, state, chain):
        if self.validBid(bid, state):
            state = self.updateState(bid, state)
        else:
            raise Exception('Invalid bid.')

        block = self.newBlock(state, chain)
        chain.append(block)

        for bid in chain:
            self.checkChain(bid)

        return state, chain
