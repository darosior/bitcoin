#!/usr/bin/env python3
# Copyright (c) 2014-2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the fixes for the timewarp and negative interval duration vulnerabilities."""

from test_framework.blocktools import (
    create_coinbase,
    NORMAL_GBT_REQUEST_PARAMS,
)
from test_framework.messages import (
    CBlock,
    CBlockHeader,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


MAX_TIMEWARP = 600 * 12


class TimewarpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        """Check the bounds of the timewarp and negative interval duration fixes."""
        self.log.info("Test timewarp attack mitigation (mainnet).")
        node = self.nodes[0]

        # We hold timestamps of all blocks but the last in the past to hit the timewarp check
        # and not MTP below.
        self.log.info("Mine all blocks in this retarget period.")
        header = node.getblockheader(node.getbestblockhash())
        assert header["height"] == 0
        node.setmocktime(header["time"])
        self.generate(node, 142)
        node.setmocktime(0)
        self.generate(node, 1)

        # A block with a timestamp strictly inferior to 2h before will fail. Chain looks like:
        # height: 0  --  1  --  2  --  3  --  ...  --  142  --  143  --  144
        # time:  old    old    old    old              old      now      now - 2h - 1s
        self.log.info("Mine first block of next retarget period 2 hours and one second before the last block.")
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        prev_header = node.getblockheader(tmpl["previousblockhash"])
        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = prev_header["time"] - MAX_TIMEWARP - 1
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(tmpl["height"]))]
        block.solve()
        assert_raises_rpc_error(-25, 'time-timewarp-attack', lambda: node.submitheader(hexdata=CBlockHeader(block).serialize().hex()))

        # One second later will succeed. Chain looks like:
        # height: 0  --  1  --  2  --  3  --  ...  --  142  --  143  --  144
        # time:  old    old    old    old              old      now      now - 2h
        self.log.info("Mine first block of next retarget period exactly 2 hours before previous block.")
        block.nTime += 1
        block.solve()
        node.submitheader(hexdata=CBlockHeader(block).serialize().hex())

        # Move on to test the Murch-Zawy attack fix.
        self.log.info("Mine the first block of next period 2h in the future. All other but last of period with normal timestamps.")
        header = node.getblockheader(node.getbestblockhash())
        assert header["height"] == 143
        node.setmocktime(header["time"] + 2 * 60 * 60)
        self.generate(node, 1)
        header = node.getblockheader(node.getbestblockhash())
        assert header["height"] == 144
        int_start_time = header["time"]
        node.setmocktime(0)
        self.generate(node, 142)

        # Strictly before is invalid. Chain looks like:
        # height: 144  --  145  --  146  --  147  --  ...  --  286  --  287  --  288
        # time:  now + 2h  now      now      now               now      now    now + 2h - 1s
        self.log.info("Mine the last block of this period with a timestamp just lower than that of the first block.")
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        prev_header = node.getblockheader(tmpl["previousblockhash"])
        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = int_start_time - 1
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(tmpl["height"]))]
        block.solve()
        assert_raises_rpc_error(-25, 'time-negative-interval', lambda: node.submitheader(hexdata=CBlockHeader(block).serialize().hex()))

        # Equal is valid. Chain looks like:
        # height: 144  --  145  --  146  --  147  --  ...  --  286  --  287  --  288
        # time:  now + 2h  now      now      now               now      now    now + 2h
        self.log.info("Mine the last block of this period with a timestamp equal to that of the first block.")
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        prev_header = node.getblockheader(tmpl["previousblockhash"])
        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = int_start_time
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(tmpl["height"]))]
        block.solve()
        node.submitheader(hexdata=CBlockHeader(block).serialize().hex())


if __name__ == '__main__':
    TimewarpTest(__file__).main()
