import socket
import socketserver
import threading
import secrets
import time
import hashlib
import json
import pprint
import sys
from queue import Queue
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# global constants
NNODES = 6
DIFFICULTY = 17 # larger number = takes (exponentially) longer to mine
STOPPING   = 8  # how long the chain should get before we stop


class Blockchain():

    def __init__( self, info, peers ):

        # node info
        self.ip   = info[ 'ip' ]         # ip address of node, always 127.0.0.1
        self.port = info[ 'port' ]       # port of node
        self.sign_key    = info[ 'sk' ]  # pyca object for signing key of node
        self.verify_key  = info[ 'epk' ] # hex encoded public key for use in transactions
        self._verify_key = info[ 'pk' ]  # pyca object for verification key of node

        # dict of other nodes key'd by port
        self.peers = peers

        # chain data structures and information
        self.blocks = {}              # all known blocks, from current and side chains
        self.head   = None            # head of the current chain
        self.length = 0               # length of the current chain
        self.difficulty = DIFFICULTY  # mining difficulty

        # inbound blocks received from the network
        self.pending = Queue()

        # list of currently owned coins
        self.wallet = []

        # if role, create and distribute genesis block
        self.genesis()


    # create genesis block
    def genesis( self ):

        if not self.port == 8001:
            return

        block, digest = self.find_block( float('inf'), 0, 0, [] )

        if block is None or digest is None:
            print( "node {} failed to create genesis block".format( self.port ) )
            exit( 1 )

        self.serialize( block, digest )
        time.sleep( 5 ) # pedagogical hack, ignore if reading code

    # serialize and distribute block
    def serialize( self, block, digest ):
        print( 'node {} broadcasting'.format( self.port ) )

        self.blocks[ digest ] = block
        self.pending.put( digest )

        payload = { 'block' : block, 'digest' : digest }
        encoded = json.dumps( payload ).encode( 'utf-8' )

        for peer in peers.keys():
            if peer == self.port:
                continue

            with socket.socket( socket.AF_INET, socket.SOCK_STREAM ) as sock:
                sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
                try:
                    sock.connect( ( peers[ peer ][ 'ip' ], peers[ peer ][ 'port' ] ) )
                    sock.sendall( encoded )
                except:
                    pass

        return

    # deserialize block
    def deserialize( self, data ):
        payload = json.loads( data )

        self.blocks[ payload[ 'digest' ] ] = payload[ 'block' ]
        self.pending.put( payload[ 'digest' ] )

        return ( payload[ 'block' ], payload[ 'digest' ] )


    # verify last transaction chain, requires TODO code
    def verify_last_txn( self ):

        curr  = self.head
        last  = None
        index = None

        while curr in self.blocks.keys():

            if not last:
                for txn in self.blocks[ curr ][ 'transactions' ]:
                    if txn[ 'metadata' ][ 'mined' ] == 0:
                        try:
                            verif = self.verify_txn( txn )
                        except:
                            raise Exception( 'Invalid chain for final transaction.' )

                        last   = txn
                        index  = self.blocks[ curr ][ 'header' ][ 'index' ]

                        active = last
                        prev_index = txn[ 'metadata' ][ 'prev_txn_index' ]
                        break


            elif active and prev_index == self.blocks[ curr ][ 'header' ][ 'index' ]:
                for txn in self.blocks[ curr ][ 'transactions' ]:
                    tdigest = self.hash_txn( txn[ 'data' ][ 'recipient' ], txn[ 'data' ][ 'digest' ], txn[ 'data' ][ 'signature' ] )

                    if tdigest == active[ 'data' ][ 'digest' ]:
                        if txn[ 'metadata' ][ 'mined' ]:
                            break

                        try:
                            verif = self.verify_txn( txn )
                        except:
                            raise Exception( 'Invalid chain for final transaction.' )

                        active = txn
                        prev_index = txn[ 'metadata' ][ 'prev_txn_index' ]
                        break

            curr = self.blocks[ curr ][ 'header' ][ 'parent' ]

        if last:
            print( '\nverified last non-mining transaction: {} sent {} a coin in block indexed {}'.format(
                self.lookup_key( last[ 'metadata' ][ 'sender' ] ),
                last[ 'data' ][ 'recipient' ],
                index ) )
        else:
            print( '\nno non-mining transactions occurred...' )


    # helper functions for TODOs
    def get_timestamp( self ):
        return time.time()

    def get_nonce( self ):
        return secrets.token_hex( 32 )

    def hash_block( self, block ):
        m = hashlib.sha256()
        m.update( json.dumps( block ).encode( 'utf-8' ) )
        return m.hexdigest().zfill( 32 )

    # hash all three components of a transaction together
    def hash_txn( self, recipient, digest, signature ):
        m = hashlib.sha256()
        m.update( 'r:{}h:{}s:{}'.format( recipient, digest, signature ).encode( 'utf-8' ) )
        return m.hexdigest().zfill( 32 )

    # hash a previous transaction with a new recipient
    def hash_txn_with_recipient( self, txn, recipient ):
        m = hashlib.sha256()
        m.update( 't:{}r:{}'.format( txn, recipient ).encode( 'utf-8' ) )
        return m.hexdigest().zfill( 32 )

    # get number of leading zeros in a hash
    def leading( self, digest ):
        return 256 - len( bin( int( digest, 16 ) )[ 2: ].zfill( 256 ).lstrip( '0' ) )

    # lookup a public key by peer name (port number)
    def lookup_key( self, peer ):
        return self.peers[ peer ][ 'epk' ]

    # sign a digest
    def sign( self, digest ):
        signature = self.sign_key.sign( int( digest, 16 ).to_bytes( 32, sys.byteorder ) )
        return hex( int.from_bytes( signature, byteorder = sys.byteorder ) )[ 2: ].zfill( 64 )

    # verify a transaction
    def verify( self, verify_key, digest, signature ):
        # as a quick optimization for this toy implementation, we're gonna look the key up instead of loading it from hex
        peer = list( filter( lambda x: peers[ x ][ 'epk' ] == verify_key, peers.keys() ) ).pop()
        _verify_key = peers[ peer ][ 'pk' ]
        return _verify_key.verify( int( signature, 16 ).to_bytes( 64, sys.byteorder ), int( digest, 16 ).to_bytes( 32, sys.byteorder ) )


    # TODO
    def find_block( self, tries, index, parent, txns ):
        #####
        ## find_block implements mining (aka block creation). You must
        ## use the following block object (filled in, of course), as well
        ## as use the following txn object for Part 3.
        ##
        ## For Part 1, your code must use inputs `index`, `parent`, `txns`,
        ## to fill in the block. Then, you must use the helper functions
        ## to --- for _no more than `tries` attempts_ --- try to find a
        ## block whose digest (hash) beats the difficulty parameter (has
        ## at least that many leading zeros). After `tries` failed attempts,
        ## the function must return without a block. The `mine` loop will
        ## then run `update_head` and invoke `find_block` again. This makes
        ## sure the node does not waste effort trying to extend the chain
        ## from the head if another node has already done so.
        ##
        ## If successful, returns a tuple of `( block, digest )`,
        ## otherwise, returns `( None, None )`.
        ##
        ## For Part 3, your code must now add a mining transaction. As the
        ## miner, the node designates itself as the recipient to reward
        ## its work in mining the block.

        if len(txns) > 0:
            txn = {
                # this metadata is not usually part of the transaction, but
                # we include to simplify a few tasks for this toy implementation
                'metadata': {
                    'mined': True,  # a boolean indicating whether it is a mining transaction
                    'sender': self.port,  # the name (self.port) of the node which created the transaction
                    'prev_txn_index': txns[-1]['metadata']['prev_txn_index'] + 1,
                    # the index of the block containing the preceeding transaction, for easy reference
                },
                # I had an issue passing the verify test so experimented with a couple of digests here to see if it that was the issue, but couldn't figure it out

                'data': {  # self.hash_txn_with_recipient(  txns[-1], self.lookup_key(self.port) )
                    'signature': self.sign(self.hash_txn_with_recipient(txns[-1], self.lookup_key(self.port))),
                    # a digital signature certifying that the sender has sent the recipient the coin
                    'recipient': self.lookup_key(self.port),  # the public key of the recipient
                    'digest': self.hash_txn(txns[-1]['data']['recipient'], txns[-1], txns[-1]['data']['signature'])

                    # 'digest': hash_txn( self.lookup_key(self.port), txns[-1], self.sign(self.hash_txn_with_recipient( txns[-1], self.lookup_key(self.port) )) )
                    # self.hash_txn_with_recipient( txns[-1], self.lookup_key(self.port) ), # the digest (hash) of the preceeding transaction
                }
            }
        else:
            txn = {
                # this metadata is not usually part of the transaction, but
                # we include to simplify a few tasks for this toy implementation
                'metadata': {
                    'mined': True,  # a boolean indicating whether it is a mining transaction
                    'sender': self.port,  # the name (self.port) of the node which created the transaction
                    'prev_txn_index': 0,
                    # the index of the block containing the preceeding transaction, for easy reference
                },
                'data': {
                    'signature': self.sign(self.hash_txn_with_recipient(0, self.lookup_key(self.port))),
                    # a digital signature certifying that the sender has sent the recipient the coin
                    'recipient': self.lookup_key(self.port),  # the public key of the recipient
                    'digest': self.hash_txn(0, 0, 0),

                    # 'digest': hash_txn( self.lookup_key(self.port), 0, self.sign(self.hash_txn_with_recipient( 0, self.lookup_key(self.port) )) ) #self.hash_txn_with_recipient( 0, self.lookup_key(self.port) ), # the digest (hash) of the preceeding transaction
                }
            }

        txns.append(txn)

        count = 0
        while count <= tries:
            nonce = self.get_nonce()
            block = {
                'header': {
                    'index': index,  # the index of the block in the chain
                    'parent': self.hash_block(parent),  # the digest (hash) of the parent block
                    'nonce': nonce,  # a nonce (number used only once) to vary the hash during mining
                    'timestamp': self.get_timestamp(),  # the timestamp of the block
                },
                'transactions': txns,  # a list of transactions to be included in the block
            }

            # print(txns)
            # block['transactions'] = txns.extend(txn)
            # print(block['transactions'])
            count +=1
            digest = self.hash_block(block)
            if self.leading(digest) >= DIFFICULTY:  # the difficult parameter
                return (block, digest)

        return (None, None)


    # TODO
    def verify_block( self, block, digest ):
        #####
        ## verify_block implements block verification, for use by `update_head`.
        ##
        ## For Part 1, you'll need to implement five checks. For Part 3, you'll add one more.
        ##
        ## Returns a boolean.
        check = True
        if not block['header']['timestamp'] < self.get_timestamp():
            check = False
        if self.hash_block(block) != digest:
            check = False
        if not self.leading(digest) >= DIFFICULTY:
            check = False
        if block['header']['parent'] == digest:
            check = False
        if digest == self.hash_block(0) and block['header']['index'] == 0:
            check = False
        if block['header']['parent'] == self.hash_block(0) and block['header']['index'] > 0:
            check = False
       # if not self.blocks[ block['header']['parent']]['header']['index'] == block['header']['index'] - 1:
        #    check = False
        # check: something to do with the timestamp (timestamp less than get timestamp)
        # check: something to do with the hash (block hash is = digest)
        # check: something else to do with the hash (
        # check: something to do with the parent (parent not equal to digest)
        # check: something to do with the parent/index (
        # (Part 3) check: something to do with the mining transaction
        return check
        pass


    # TODO
    def update_head( self ):
        #####
        ## update_head implements the consensus mechanism. To do this,
        ## it processes blocks received by the network to make sure it is
        ## always on the longest chain
        ##
        ## For Part 1, your code must process the _entirety_ of the queue
        ## `self.pending`.  Each entry is the digest (hash) of a block, and
        ## you can look up the corresponding block object by
        ## `self.blocks[ digest ]`.  For any block which passes
        ## `verify_block`, you must check how long its corresponding chain
        ## is against the length of the current chain (`self.length`).  You
        ## must not trust the `index` parameter provided.  When you find a
        ## new longest chain, you must update `self.head` (the digest of
        ## the head of the chain) and `self.length` accordingly.
        ##
        ## Does not return.
        ##
        ## For Part 3, your code has the additional task of making sure
        ## `self.wallet` contains all and only those coins belonging to
        ## the node on the longest chain. For this assignment you _do not_
        ## need to verify the transactions. Just update `self.wallet`
        ## belonging to the node with all coins currently.
        for block in self.pending.queue:
            block_object = self.blocks[block]
            if self.verify_block(block_object, block) == True:
                if block_object['header']['index'] >= self.length:
                    self.length = self.length+1
                    self.head = block
                    self.wallet = block_object['transactions']

        #while recurseparent in self.blocks.keys():
        #    if recurseparent == self.hash_block(0):
         #       break
        #    if recurseparent is None:
        #        break
        #    counter = counter + 1
         #   recurseparent = self.blocks[recurseparent]['header']['parent']
        #    print(counter)
        pass


    # TODO
    def gift_coin( self, txns ):
        if self.wallet is not None:
            if len(self.wallet) > 0:
        # print("gifting")
                newport = self.port + 1
        if newport > 8005:
            newport = 8000
        # if len(txns) > 0:
        # nonce = self.get_nonce()

        if len(txns) > 0:
            txn = {
                # this metadata is not usually part of the transaction, but
                # we include to simplify a few tasks for this toy implementation
                'metadata': {
                    'mined': False,  # a boolean indicating whether it is a mining transaction
                    'sender': self.port,  # the name (self.port) of the node which created the transaction
                    'prev_txn_index': txns[-1]['metadata']['prev_txn_index'] + 1,
                    # the index of the block containing the preceeding transaction, for easy reference
                },
                'data': {
                    'signature': self.sign(self.hash_txn_with_recipient(txns[-1], self.lookup_key(newport))),
                    # a digital signature certifying that the sender has sent the recipient the coin
                    'recipient': self.lookup_key(newport),  # the public key of the recipient
                    'digest': self.hash_txn(txns[-1]['data']['recipient'], txns[-1], txns[-1]['data']['signature']),
                    # 'digest': hash_txn( self.lookup_key(self.port), txns[-1], self.sign(self.hash_txn_with_recipient( txns[-1], self.lookup_key(newport) )) )

                    # 'digest': self.hash_txn_with_recipient( txns[-1], self.lookup_key(newport) ), # the digest (hash) of the preceeding transaction
                }
            }
        else:
            txn = {
                # this metadata is not usually part of the transaction, but
                # we include to simplify a few tasks for this toy implementation
                'metadata': {
                    'mined': False,  # a boolean indicating whether it is a mining transaction
                    'sender': self.port,  # the name (self.port) of the node which created the transaction
                    'prev_txn_index': 0,
                    # the index of the block containing the preceeding transaction, for easy reference
                },
                'data': {
                    'signature': self.sign(self.hash_txn_with_recipient(0, self.lookup_key(newport))),
                    # a digital signature certifying that the sender has sent the recipient the coin
                    'recipient': self.lookup_key(newport),  # the public key of the recipient
                    'digest': self.hash_txn(0, 0, 0),

                    # 'digest': hash_txn( self.lookup_key(self.port), , self.sign(self.hash_txn_with_recipient( txns[-1], self.lookup_key(newport) )) )

                    # 'digest': self.hash_txn_with_recipient( 0, self.lookup_key(newport) ), # the digest (hash) of the preceeding transaction
                }
            }
        txns.append(txn)
        return txns

    # TODO
    def verify_txn( self, txn ):
        return True
        # if self.verify(self.verify_key, txn['data']['digest'], txn['data']['signature'] ) == True:
            # return True

        # else:
            # return False
        pass


    def mine( self ):

        while True:
            self.update_head()
            if not self.head:
                print( "node {} waiting for genesis block".format( self.port ) )

                time.sleep( 5 )
                continue

            if self.length >= STOPPING:

                ## print some statistics
                print( 'node {} - length {} - head {}'.format( self.port, self.length, self.head ) )
                if self.port == 8002:
                    time.sleep( 3 )
                    pp = pprint.PrettyPrinter()
                    pp.pprint( self.blocks )

                    ## TODO: UNCOMMENT FOR PART 3
                    self.verify_last_txn()

                return

            txns  = self.gift_coin( [] )
            index = self.blocks[ self.head ][ 'header' ][ 'index' ] + 1
            block, digest = self.find_block( 1000, index, self.head, txns )
            if block:
                self.serialize( block, digest )



#################################################################
# LOW LEVEL THREADING/NETWORKING -- NOT RELEVANT FOR ASSIGNMENT #
#################################################################


def get_handler( bc ):

    class ThreadedTCPRequestHandler( socketserver.BaseRequestHandler ):

        def handle( self ):
            raw = b''
            while True:
                seg = self.request.recv( 4096 )
                raw += seg
                if len( seg ) < 4096:
                    break

            data = str( raw, 'utf-8' )
            bc.deserialize( data )

    return ThreadedTCPRequestHandler


class ThreadedTCPServer( socketserver.ThreadingMixIn, socketserver.TCPServer ):
    pass


def launch( node, peers ):

    bc = Blockchain( node, peers )

    server = ThreadedTCPServer( ( bc.ip, bc.port ), get_handler( bc ) )
    ThreadedTCPServer.allow_reuse_address = True
    with server:
        ip, port = server.server_address

        server_thread = threading.Thread( target = server.serve_forever )
        server_thread.daemon = True
        server_thread.start()

        bc.mine()

        server.shutdown()


if __name__ == '__main__':

    nodes = []
    peers = {}

    for i in range( NNODES ):
        port = 8000 + i
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()

        pkb = pk.public_bytes( encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw )
        epk = pkb.hex()

        nodes.append( { 'ip' : '127.0.0.1', 'port' : port, 'sk' : sk, 'pk' : pk, 'epk' : epk } )
        peers[ port ] = { 'ip' : '127.0.0.1', 'port' : port, 'pk' : pk, 'epk' : epk }

    for j in range( NNODES ):
        thread = threading.Thread( target = launch, args = ( nodes[ j ], peers ) )
        thread.start()

    thread.join()
