#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a shutdown while the validation thread still has blocks to process.

The node stores a block that a peer sends before validation processes it, in a job of the validation thread. The jobs
that are left at shutdown are dropped: the blocks are on disk, and when the node starts again it loads them as any
other block it has the data of, and connects them, without any peer.

The node runs with the option that delays the jobs of the validation thread, and each block is sent by a peer of its
own (a peer is not asked for its next message while its block is with validation), so that jobs are queued when the
node stops. The test checks that this happened at least once (the tip that the node loads is behind the blocks it
stored), and that the node connects all the blocks each time.
"""
import re

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.authproxy import JSONRPCException
from test_framework.messages import (
    CBlockHeader,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

NUM_BLOCKS = 20
NUM_ROUNDS = 5


class ShutdownQueuedBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-test=validation_delay"]]

    def is_stored(self, block_hash):
        try:
            self.nodes[0].getblock(block_hash)
        except JSONRPCException:
            return False
        return True

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 1)
        stopped_with_jobs = False
        for _ in range(NUM_ROUNDS):
            tip = node.getblock(node.getbestblockhash())
            blocks = []
            parent, height, time = int(tip["hash"], 16), tip["height"], tip["time"]
            for _ in range(NUM_BLOCKS):
                height += 1
                time += 1
                block = create_block(parent, create_coinbase(height), ntime=time)
                add_witness_commitment(block)
                block.solve()
                blocks.append(block)
                parent = block.hash_int

            # The headers come first, so that the blocks can be stored in any order.
            peers = [node.add_p2p_connection(P2PInterface()) for _ in range(NUM_BLOCKS)]
            peers[0].send_and_ping(msg_headers([CBlockHeader(b) for b in blocks]))
            for peer, block in zip(peers, blocks):
                peer.send_without_ping(msg_block(block))
            for block in blocks:
                self.wait_until(lambda: self.is_stored(block.hash_hex), check_interval=0.001)
            self.stop_node(0)

            # The tip that the node loads is the one it had at shutdown.
            log_size = node.debug_log_size()
            self.start_node(0)
            self.wait_until(lambda: node.getblockcount() == height)
            assert_equal(node.getbestblockhash(), blocks[-1].hash_hex)
            with open(node.debug_log_path, encoding="utf-8") as log:
                log.seek(log_size)
                loaded = re.search(r"Loaded best chain: hashBestChain=\w+ height=(\d+)", log.read())
            assert loaded
            if int(loaded.group(1)) < height:
                stopped_with_jobs = True
        assert stopped_with_jobs


if __name__ == '__main__':
    ShutdownQueuedBlocksTest(__file__).main()
