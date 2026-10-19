#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the requests for a block that the node announced before validation was done with it.

The node announces a block that builds on its tip by compact block to the peers that asked for that (BIP 152
high-bandwidth mode) before it is connected, and does not wait for validation to handle the messages of the other
peers. BIP 152 says that "nodes SHOULD delay responding to GETDATA requests for the block until validation has
completed": a peer that asks for the block at once gets it once validation is done with it, and not nothing.

- A block that a peer sends is validated by a job of the validation thread. The node runs with the option that delays
  the jobs, so that the request nearly always comes while the job waits. That holds as well for a block that the node
  did not announce yet, because it builds on one that is not connected yet: a peer can know of it from another node.
- A block that is submitted (submitblock) is validated by the thread that submits it, and has no job. The block spends
  thousands of inputs whose signatures the node checks one after the other (-par=1), so that the request comes while
  the block is connected. All the inputs but the first are signed with the same signature: with SIGHASH_SINGLE and no
  output of their index, they all sign the same hash, and the node checks each of them, as it does not store the
  signatures of a block in its cache.

In both cases the delay is a matter of timing, so the test checks that the requests were held at least once, and that
each one was served.
"""
from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import ECKey
from test_framework.messages import (
    COutPoint,
    CBlockHeader,
    CInv,
    CTransaction,
    CTxIn,
    CTxOut,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    from_hex,
    msg_block,
    msg_getdata,
    msg_headers,
    msg_sendcmpct,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.script import (
    CScript,
    LegacySignatureHash,
    OP_TRUE,
    SIGHASH_SINGLE,
)
from test_framework.script_util import key_to_p2pk_script
from test_framework.test_framework import BitcoinTestFramework

NUM_BLOCKS = 10
NUM_INPUTS = 4000
HELD_LOG = "Holding the request for block"


class AskAtOncePeer(P2PInterface):
    """A high-bandwidth peer that asks for the block of each compact block it receives as soon as it receives it."""
    def __init__(self):
        super().__init__()
        self.blocks = set()

    def on_cmpctblock(self, message):
        block_hash = message.header_and_shortids.header.hash_int
        self.send_without_ping(msg_getdata([CInv(MSG_BLOCK | MSG_WITNESS_FLAG, block_hash)]))

    def on_block(self, message):
        self.blocks.add(message.block.hash_int)


class CompactBlockGetdataHeldTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-test=validation_delay", "-par=1"]]

    def make_block(self, txs=(), *, parent=None):
        """Make a block on the tip, or on the child of the tip that was made by this and is not connected yet."""
        node = self.nodes[0]
        tip = node.getblock(node.getbestblockhash())
        parent_hash, height, time = int(tip["hash"], 16), tip["height"], tip["time"]
        if parent is not None:
            parent_hash, height, time = parent.hash_int, height + 1, parent.nTime
        block = create_block(parent_hash, create_coinbase(height + 1), ntime=time + 1, txlist=list(txs))
        add_witness_commitment(block)
        block.solve()
        return block

    def ask_peer(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(AskAtOncePeer())
        peer.send_and_ping(msg_sendcmpct(announce=True, version=2))
        # A block is only announced to a peer that is known to have its parent.
        peer.send_and_ping(msg_headers([from_hex(CBlockHeader(), node.getblockheader(node.getbestblockhash(), False))]))
        return peer

    def wait_for_block(self, peer, block):
        def served():
            with p2p_lock:
                return block.hash_int in peer.blocks
        self.wait_until(served)

    def test_block_from_peer(self):
        self.log.info("A request for a block that a peer sent is held until the job of the block is done")
        node = self.nodes[0]
        asker = self.ask_peer()
        sender = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log([HELD_LOG]):
            for _ in range(NUM_BLOCKS):
                block = self.make_block()
                sender.send_without_ping(msg_block(block))
                self.wait_for_block(asker, block)
                assert block.hash_int in asker.blocks
                self.wait_until(lambda: node.getbestblockhash() == block.hash_hex)
        node.disconnect_p2ps()

    def test_block_not_announced(self):
        self.log.info("A request for a block that a peer sent and that was not announced is held until its job is done")
        node = self.nodes[0]
        # A block that builds on one that is not connected yet is not announced until its parent is. Another peer
        # sends it, as a peer is not asked for its next message while its block is with validation.
        sender = node.add_p2p_connection(P2PInterface())
        sender2 = node.add_p2p_connection(P2PInterface())
        asker = node.add_p2p_connection(AskAtOncePeer())
        with node.assert_debug_log([HELD_LOG]):
            for _ in range(NUM_BLOCKS):
                first = self.make_block()
                second = self.make_block(parent=first)
                sender.send_without_ping(msg_block(first))
                self.wait_until(lambda: self.is_stored(first), check_interval=0.001)
                sender2.send_without_ping(msg_block(second))
                # Ask as soon as the node can serve the block once it is connected.
                self.wait_until(lambda: self.is_stored(second), check_interval=0.001)
                asker.send_without_ping(msg_getdata([CInv(MSG_BLOCK | MSG_WITNESS_FLAG, second.hash_int)]))
                self.wait_for_block(asker, second)
                self.wait_until(lambda: node.getbestblockhash() == second.hash_hex)
        node.disconnect_p2ps()

    def is_stored(self, block):
        try:
            self.nodes[0].getblock(block.hash_hex)
        except JSONRPCException:
            return False
        return True

    def test_submitted_block(self):
        self.log.info("A request for a submitted block is held until it is connected")
        node = self.nodes[0]
        key = ECKey()
        key.generate()
        p2pk = key_to_p2pk_script(key.get_pubkey().get_bytes())

        # A coinbase that anyone can spend, made mature, pays for the outputs that the block spends.
        funding_block = self.make_block()
        node.submitblock(funding_block.serialize().hex())
        self.generate(node, 100)
        coinbase = funding_block.vtx[0]
        funding = CTransaction()
        funding.vin = [CTxIn(COutPoint(coinbase.txid_int, 0))]
        value = (coinbase.vout[0].nValue - 100000) // NUM_INPUTS
        funding.vout = [CTxOut(value, p2pk) for _ in range(NUM_INPUTS)]
        node.submitblock(self.make_block([funding]).serialize().hex())

        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.txid_int, i)) for i in range(NUM_INPUTS)]
        spend.vout = [CTxOut(value * NUM_INPUTS - 100000, CScript([OP_TRUE]))]
        for i in range(2):
            sighash, _ = LegacySignatureHash(p2pk, spend, i, SIGHASH_SINGLE)
            spend.vin[i].scriptSig = CScript([key.sign_ecdsa(sighash) + bytes([SIGHASH_SINGLE])])
        for txin in spend.vin[2:]:
            txin.scriptSig = spend.vin[1].scriptSig

        asker = self.ask_peer()
        block = self.make_block([spend])
        with node.assert_debug_log([HELD_LOG]):
            assert node.submitblock(block.serialize().hex()) is None
            self.wait_for_block(asker, block)
        assert node.getbestblockhash() == block.hash_hex

    def run_test(self):
        # The announcement of blocks is for nodes that are not in IBD.
        self.generate(self.nodes[0], 1)
        self.test_block_from_peer()
        self.test_block_not_announced()
        self.test_submitted_block()


if __name__ == '__main__':
    CompactBlockGetdataHeldTest(__file__).main()
