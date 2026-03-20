#!/usr/bin/env python3
import os
import time

from test_framework.blocktools import create_block, script_BIP34_coinbase_height
from test_framework.key import ECKey
from test_framework.messages import CTransaction, CTxIn, COutPoint, CTxOut
from test_framework.p2p import P2PInterface, msg_block, msg_ping
from test_framework.script import CScript, OP_CHECKSIG, OP_2DUP, OP_DROP, OP_CODESEPARATOR
from test_framework.script_util import script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework


NULL_INDEX = 0xFF_FF_FF_FF
MAX_LEGACY_SIGOPS_BLK = 20_000
MAX_LEGACY_BLOCK_SIZE = 1_000_000
MIN_DER_SIG = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])


def dummy_pubkey():
    privkey = ECKey()
    privkey.generate()
    return privkey.get_pubkey().get_bytes()


def create_prep_coinbase(height, prep_spks):
    """Create a coinbase transaction which fans out preparation outputs."""
    cb = CTransaction()
    cb.vin.append(CTxIn(COutPoint(0, NULL_INDEX), script_BIP34_coinbase_height(height)))
    cb.vout = [CTxOut(nValue=0, scriptPubKey=spk) for spk in prep_spks]
    return cb


class ExpensiveBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-par={os.cpu_count()}"]]

    def create_prep_block(self, prev_hash, height, prep_spks):
        """Create and submit a block at the given height which fans out that many outputs in the coinbase tx."""
        cb = create_prep_coinbase(height, prep_spks)
        block = create_block(hashprev=prev_hash, coinbase=cb)
        block.solve()
        res = self.nodes[0].submitblock(block.serialize().hex())
        assert res is None, res
        return block

    def create_prep_txos(self, prep_spks):
        """Fan-out the outputs to be spent by the attack transaction. Returns the list of outpoints."""
        self.log.info(f"    Generating preparation block with {len(prep_spks)} preparation outputs.")

        prev_hash = self.nodes[0].getbestblockhash()
        prev_header = self.nodes[0].getblockheader(prev_hash)
        block_height = prev_header["height"] + 1
        prev_hash = int(self.nodes[0].getbestblockhash(), 16)
        block = self.create_prep_block(prev_hash, block_height, prep_spks)

        cb_txid = block.vtx[0].txid_int
        prep_txos = []
        for i, _ in enumerate(block.vtx[0].vout):
            prep_txos.append(COutPoint(cb_txid, i))

        self.log.info("    Mining 100 blocks to mature the prep outputs.")
        self.generate(self.nodes[0], 100)

        return prep_txos

    def create_attack_block(self, attack_txs):
        """Create, the block which contains the expensive to validate transaction."""
        self.log.info("    Creating attack block.")
        prev_hash = self.nodes[0].getbestblockhash()
        prev_header = self.nodes[0].getblockheader(prev_hash)
        height = prev_header["height"] + 1
        time = prev_header["time"] + 1
        block = create_block(hashprev=int(prev_hash, 16), txlist=attack_txs, ntime=time, tmpl={"height": height})
        assert len(block.serialize()) <= MAX_LEGACY_BLOCK_SIZE
        return block

    def publish_attack_block(self, block):
        """Publish attack block on P2P interface and monitor how long it takes to validate."""
        self.log.info(f"    Publishing attack block (hash: {block.hash_hex}, size: {len(block.serialize())}).")

        conn = self.nodes[0].add_p2p_connection(P2PInterface())
        time_before = time.time()
        conn.send_without_ping(msg_block(block))

        # This replicates `sync_with_ping` but without the annoying error log, since we
        # expect it to time out in this case.
        self.log.info("    Sending a ping to bitcoind to estimate validation time.")
        conn.send_without_ping(msg_ping(nonce=0))
        conn.send_without_ping(msg_ping(nonce=conn.ping_counter))
        last_log = time.time()
        while True:
            pong = conn.last_message.get("pong")
            if pong is not None and pong.nonce == conn.ping_counter:
                self.log.info("    Bitcoind responded to our ping.")
                break
            since_last_log = int(time.time() - last_log)
            if since_last_log > 10:
                last_log = time.time()
                self.log.info(f"    Still validating after {int(time.time() - time_before)} seconds..")
            time.sleep(0.1)

        time_after = time.time()
        duration = int(time_after - time_before)
        self.log.info(f"    Validating block took {duration} seconds.")

    def run_test(self):
        self.log.info("Creating a block that takes a long time to verify, but is still far from the worst case.")

        dummy_pk = dummy_pubkey()
        max_redeem_script = [MIN_DER_SIG, dummy_pk]
        max_redeem_script += [OP_2DUP, OP_CHECKSIG, OP_CODESEPARATOR, OP_DROP] * 50
        max_prep_spk = script_to_p2sh_script(CScript(max_redeem_script))
        prep_spks = [max_prep_spk] * int(MAX_LEGACY_SIGOPS_BLK / 50)
        redeem_scripts = [max_redeem_script] * len(prep_spks)

        remaining_sigops = MAX_LEGACY_SIGOPS_BLK % 50
        last_redeem_script = [MIN_DER_SIG, dummy_pk]
        last_redeem_script += [OP_2DUP, OP_CHECKSIG, OP_CODESEPARATOR, OP_DROP] * remaining_sigops
        last_prep_spk = script_to_p2sh_script(CScript(last_redeem_script))
        prep_spks.append(last_prep_spk)
        redeem_scripts.append(last_redeem_script)

        prep_ops = self.create_prep_txos(prep_spks)
        attack_tx = CTransaction()
        assert len(prep_ops) == len(redeem_scripts)
        for op, redeem_script in zip(prep_ops, redeem_scripts):
            attack_tx.vin.append(CTxIn(op, scriptSig=CScript([CScript(redeem_script)])))

        dummy_txo = CTxOut(nValue=0, scriptPubKey=CScript())
        dummy_txo_size = len(dummy_txo.serialize())
        attack_tx.vout.append(dummy_txo)
        block = self.create_attack_block([attack_tx])
        available_space = MAX_LEGACY_BLOCK_SIZE - len(block.serialize()) - 2  # -2 for the vout size serialization
        dummy_txo_count = int(available_space / dummy_txo_size)

        block.vtx[1].vout = [dummy_txo] * dummy_txo_count
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        self.publish_attack_block(block)


if __name__ == '__main__':
    ExpensiveBlockTest(__file__).main()
