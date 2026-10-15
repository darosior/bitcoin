#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the announcement of a block that builds on a block that is not connected yet.

The node does not wait for validation to connect a block before it handles the messages of the other peers. A block
that builds on one that is stored and not connected is announced by compact block to the peers that asked for that
(BIP 152 high-bandwidth mode) as soon as its parent is connected, and never before that: the parent has to be
validated by then.

The node runs with the option that delays the jobs of the validation thread, so that the second block, which another
peer sends, is nearly always received while the first one is not connected. If the second one is connected by the time
the node handles the connection of the first one, it is relayed as any other block: so the test checks the order of
the announcements, and that they were made by compact block only as it expects, not that each one was.
"""
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    CBlockHeader,
    MSG_BLOCK,
    from_hex,
    msg_block,
    msg_headers,
    msg_sendcmpct,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

NUM_PAIRS = 10


class HighBandwidthPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        # The blocks that were announced, in order, by whatever means.
        self.announced = []
        self.cmpctblock_hashes = []

    def on_cmpctblock(self, message):
        block_hash = message.header_and_shortids.header.hash_int
        self.cmpctblock_hashes.append(block_hash)
        self.announced.append(block_hash)

    def on_inv(self, message):
        self.announced.extend(inv.hash for inv in message.inv if inv.type == MSG_BLOCK)

    def on_headers(self, message):
        self.announced.extend(header.hash_int for header in message.headers)


class CompactBlockUnconnectedParentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-test=validation_delay"]]

    def make_block(self, parent_hash, height, time):
        block = create_block(hashprev=int(parent_hash, 16), height=height, ntime=time)
        add_witness_commitment(block)
        block.solve()
        return block

    @staticmethod
    def is_stored(node, block_hash):
        try:
            node.getblock(block_hash)
        except JSONRPCException:
            return False
        return True

    def run_test(self):
        node = self.nodes[0]
        # The announcement of blocks is for nodes that are not in IBD.
        self.generate(node, 1)

        hb_peer = node.add_p2p_connection(HighBandwidthPeer())
        # Ask for the announcement of new blocks by compact block as soon as they are validated.
        hb_peer.send_and_ping(msg_sendcmpct(announce=True, version=2))
        sender = node.add_p2p_connection(P2PInterface())
        sender2 = node.add_p2p_connection(P2PInterface())

        tip_hash = node.getbestblockhash()
        # A block is only announced to a peer that is known to have its parent.
        hb_peer.send_and_ping(msg_headers([from_hex(CBlockHeader(), node.getblockheader(tip_hash, False))]))
        height = node.getblockcount()
        time = node.getblock(tip_hash)["time"]
        # The delay of the jobs is random: the second block is not received while the first one is not connected every
        # time, but it is at least once.
        with node.assert_debug_log(["Holding the announcement of block"]):
            for i in range(NUM_PAIRS):
                first = self.make_block(tip_hash, height + 1, time + 1)
                second = self.make_block(first.hash_hex, height + 2, time + 2)
                # Back to back: the second one is handled by the node while the first one waits for validation. A peer is
                # not asked for its next message while its block is with validation, so another one sends the second.
                sender.send_without_ping(msg_block(first))
                self.wait_until(lambda: self.is_stored(node, first.hash_hex))
                sender2.send_without_ping(msg_block(second))
                self.wait_until(lambda: node.getbestblockhash() == second.hash_hex)
                tip_hash, height, time = second.hash_hex, height + 2, time + 2

                # Both blocks are announced, and in the order of the chain.
                self.wait_until(lambda: second.hash_int in hb_peer.announced)
                with p2p_lock:
                    announced = [h for h in hb_peer.announced if h in (first.hash_int, second.hash_int)]
                assert_equal(announced[:2], [first.hash_int, second.hash_int])
                # The first one is announced by compact block at once, as it builds on the tip.
                assert first.hash_int in hb_peer.cmpctblock_hashes


if __name__ == '__main__':
    CompactBlockUnconnectedParentTest(__file__).main()
