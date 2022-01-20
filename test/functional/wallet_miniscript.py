#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Miniscript descriptors integration in the wallet."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


MINISCRIPTS = [
    # One of two keys
    "or_b(pk(tpubD6NzVbkrYhZ4XRMcMFMMFvzVt6jaDAtjZhD7JLwdPdMm9xa76DnxYYP7w9TZGJDVFkek3ArwVsuacheqqPog8TH5iBCX1wuig8PLXim4n9a/*),s:pk(tpubD6NzVbkrYhZ4WsqRzDmkL82SWcu42JzUvKWzrJHQ8EC2vEHRHkXj1De93sD3biLrKd8XGnamXURGjMbYavbszVDXpjXV2cGUERucLJkE6cy/*))",
    # A script similar (same spending policy) to BOLT3's offered HTLC (with anchor outputs)
    "or_d(pk(tpubD6NzVbkrYhZ4XRMcMFMMFvzVt6jaDAtjZhD7JLwdPdMm9xa76DnxYYP7w9TZGJDVFkek3ArwVsuacheqqPog8TH5iBCX1wuig8PLXim4n9a/*),and_v(and_v(v:pk(tpubD6NzVbkrYhZ4WsqRzDmkL82SWcu42JzUvKWzrJHQ8EC2vEHRHkXj1De93sD3biLrKd8XGnamXURGjMbYavbszVDXpjXV2cGUERucLJkE6cy/*),or_c(pk(tpubD6NzVbkrYhZ4YNwtTWrKRJQzQX3PjPKeUQg1gYh1hiLMkk1cw8SRLgB1yb7JzE8bHKNt6EcZXkJ6AqpCZL1aaRSjnG36mLgbQvJZBNsjWnG/*),v:hash160(7f999c905d5e35cefd0a37673f746eb13fba3640))),older(1)))",
    # A Revault Unvault policy with the older() replaced by an after()
    "andor(multi(2,tpubD6NzVbkrYhZ4YMQC15JS7QcrsAyfGrGiykweqMmPxTkEVScu7vCZLNpPXW1XphHwzsgmqdHWDQAfucbM72EEB1ZEyfgZxYvkZjYVXx1xS9p/*,tpubD6NzVbkrYhZ4WkCyc7E3z6g6NkypHMiecnwc4DpWHTPqFdteRGkEKukdrSSyJGNnGrHNMfy4BCw2UXo5soYRCtCDDfy4q8pc8oyB7RgTFv8/*),and_v(v:multi(4,030f64b922aee2fd597f104bc6cb3b670f1ca2c6c49b1071a1a6c010575d94fe5a,02abe475b199ec3d62fa576faee16a334fdb86ffb26dce75becebaaedf328ac3fe,0314f3dc33595b0d016bb522f6fe3a67680723d842c1b9b8ae6b59fdd8ab5cccb4,025eba3305bd3c829e4e1551aac7358e4178832c739e4fc4729effe428de0398ab),after(424242)),thresh(4,pkh(tpubD6NzVbkrYhZ4YVrNggiT2ptVHwnFbLBqDkCtV5HkxR4WtcRLAQReKTkqZGNcV6GE7cQsmpBzzSzhk16DUwB1gn1L7ZPnJF2dnNePP1uMBCY/*),a:pkh(tpubD6NzVbkrYhZ4YU9vM1s53UhD75UyJatx8EMzMZ3VUjR2FciNfLLkAw6a4pWACChzobTseNqdWk4G7ZdBqRDLtLSACKykTScmqibb1ZrCvJu/*),a:pkh(tpubD6NzVbkrYhZ4YUHcFfuH9iEBLiH8CBRJTpS7X3qjHmh82m1KCNbzs6w9gyK8oWHSZmKHWcakAXCGfbKg6xoCvKzQCWAHyxaC7QcWfmzyBf4/*),a:pkh(tpubD6NzVbkrYhZ4XXEmQtS3sgxpJbMyMg4McqRR1Af6ULzyrTRnhwjyr1etPD7svap9oFtJf4MM72brUb5o7uvF2Jyszc5c1t836fJW7SX2e8D/*)))",
    # Liquid-like federated pegin with emergency recovery keys
    "or_i(and_b(pk(029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0),a:and_b(pk(025f05815e3a1a8a83bfbb03ce016c9a2ee31066b98f567f6227df1d76ec4bd143),a:and_b(pk(025625f41e4a065efc06d5019cbbd56fe8c07595af1231e7cbc03fafb87ebb71ec),a:and_b(pk(02a27c8b850a00f67da3499b60562673dcf5fdfb82b7e17652a7ac54416812aefd),s:pk(03e618ec5f384d6e19ca9ebdb8e2119e5bef978285076828ce054e55c4daf473e2))))),and_v(v:thresh(2,pkh(tpubD6NzVbkrYhZ4YK67cd5fDe4fBVmGB2waTDrAt1q4ey9HPq9veHjWkw3VpbaCHCcWozjkhgAkWpFrxuPMUrmXVrLHMfEJ9auoZA6AS1g3grC/*),a:pkh(033841045a531e1adf9910a6ec279589a90b3b8a904ee64ffd692bd08a8996c1aa),a:pkh(02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068)),older(4209713)))",
]

MINISCRIPTS_PRIV = [
    # One of two keys, of which one private key is known
    {
        "ms": "or_i(pk(tprv8ZgxMBicQKsPerQj6m35no46amfKQdjY7AhLnmatHYXs8S4MTgeZYkWAn4edSGwwL3vkSiiGqSZQrmy5D3P5gBoqgvYP2fCUpBwbKTMTAkL/*),pk(tpubD6NzVbkrYhZ4YPAbyf6urxqqnmJF79PzQtyERAmvkSVS9fweCTjxjDh22Z5St9fGb1a5DUCv8G27nYupKP1Ctr1pkamJossoetzws1moNRn/*))",
        "sequence": None,
        "locktime": None,
    },
    # A more complex policy, that can't be satisfied through the first branch (need for a preimage)
    {
        "ms": "andor(dv:older(2),and_v(v:pk(tprv8ZgxMBicQKsPdZFz4VVtpR8NZrjL4LpuLcfVB8oK9evqe6gkYB8GMZ2nf9SQGhVDZpWCpQpEmPckToyTja8R4xSoMMvwYRG4T4uvwhbrNWh),sha256(2a8ce30189b2ec3200b47aeb4feaac8fcad7c0ba170389729f4898b0b7933bcb)),and_v(v:pkh(tprv8ZgxMBicQKsPd3cbrKjE5GKKJLDEidhtzSSmPVtSPyoHQGL2LZw49yt9foZsN9BeiC5VqRaESUSDV2PS9w7zAVBSK6EQH3CZW9sMKxSKDwD),pk(tprv8ZgxMBicQKsPd7T1sTsZdJo7EJm5bD8SKQUHWqivT8r5GCH13wzS1QspAgSnCeoy7fdSUQs7nxZdTVchxQuHxWWNHL4D4pdD67oq6khhX49/*)))",
        "sequence": 2,
        "locktime": None,
    },
    # Signature with a relative timelock
    {
        "ms": "and_v(v:older(2),pk(tprv8ZgxMBicQKsPdZFz4VVtpR8NZrjL4LpuLcfVB8oK9evqe6gkYB8GMZ2nf9SQGhVDZpWCpQpEmPckToyTja8R4xSoMMvwYRG4T4uvwhbrNWh/*))",
        "sequence": 2,
        "locktime": None,
    },
    # Signature with an absolute timelock
    {
        "ms": "and_v(v:after(20),pk(tprv8ZgxMBicQKsPdZFz4VVtpR8NZrjL4LpuLcfVB8oK9evqe6gkYB8GMZ2nf9SQGhVDZpWCpQpEmPckToyTja8R4xSoMMvwYRG4T4uvwhbrNWh/*))",
        "sequence": None,
        "locktime": 20,
    },
    # Signature with both
    {
        "ms": "and_v(v:older(4),and_v(v:after(30),pk(tprv8ZgxMBicQKsPdZFz4VVtpR8NZrjL4LpuLcfVB8oK9evqe6gkYB8GMZ2nf9SQGhVDZpWCpQpEmPckToyTja8R4xSoMMvwYRG4T4uvwhbrNWh/*)))",
        "sequence": 4,
        "locktime": 30,
    },
]


class WalletMiniscriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def watchonly_test(self, ms):
        self.log.info(f"Importing Miniscript '{ms}'")
        desc = descsum_create(f"wsh({ms})")
        assert self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": desc,
                    "active": True,
                    "range": 2,
                    "next_index": 0,
                    "timestamp": "now",
                }
            ]
        )[0]["success"]

        self.log.info("Testing we derive new addresses for it")
        assert_equal(
            self.ms_wo_wallet.getnewaddress(), self.funder.deriveaddresses(desc, 0)[0]
        )
        assert_equal(
            self.ms_wo_wallet.getnewaddress(), self.funder.deriveaddresses(desc, 1)[1]
        )

        self.log.info("Testing we detect funds sent to one of them")
        addr = self.ms_wo_wallet.getnewaddress()
        txid = self.funder.sendtoaddress(addr, 0.01)
        self.wait_until(
            lambda: len(self.ms_wo_wallet.listunspent(minconf=0, addresses=[addr])) == 1
        )
        utxo = self.ms_wo_wallet.listunspent(minconf=0, addresses=[addr])[0]
        assert utxo["txid"] == txid and utxo["solvable"]

    def signing_test(self, ms, sequence, locktime):
        self.log.info(f"Importing private Miniscript '{ms}'")
        desc = descsum_create(f"wsh({ms})")
        assert self.ms_sig_wallet.importdescriptors(
            [
                {
                    "desc": desc,
                    "active": True,
                    "range": 0,
                    "next_index": 0,
                    "timestamp": "now",
                }
            ]
        )[0]["success"]

        self.log.info("Generating an address for it and testing it detects funds")
        addr = self.ms_sig_wallet.getnewaddress()
        txid = self.funder.sendtoaddress(addr, 0.01)
        self.wait_until(lambda: txid in self.funder.getrawmempool())
        self.funder.generatetoaddress(1, self.funder.getnewaddress())
        utxo = self.ms_sig_wallet.listunspent(addresses=[addr])[0]
        assert txid == utxo["txid"] and utxo["solvable"]

        self.log.info(
            "Creating, signing, and broadcasting a transaction spending these funds"
        )
        dest_addr = self.funder.getnewaddress()
        seq = sequence if sequence is not None else 0xFFFFFFFF - 2
        lt = locktime if locktime is not None else 0
        psbt = self.ms_sig_wallet.createpsbt(
            [
                {
                    "txid": txid,
                    "vout": utxo["vout"],
                    "sequence": seq,
                }
            ],
            [{dest_addr: 0.009}],
            lt,
        )
        res = self.ms_sig_wallet.walletprocesspsbt(psbt)
        assert res["complete"]
        res = self.ms_sig_wallet.finalizepsbt(res["psbt"])
        assert res["complete"]
        # If necessary, satisfy a relative timelock
        if sequence is not None:
            self.funder.generatetoaddress(sequence, self.funder.getnewaddress())
        # If necessary, satisfy an absolute timelock
        height = self.funder.getblockcount()
        if locktime is not None and height < locktime:
            self.funder.generatetoaddress(
                locktime - height, self.funder.getnewaddress()
            )
        self.ms_sig_wallet.sendrawtransaction(res["hex"])

    def run_test(self):
        self.log.info("Making a descriptor wallet")
        self.funder = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet(
            wallet_name="ms_wo", descriptors=True, disable_private_keys=True
        )
        self.ms_wo_wallet = self.nodes[0].get_wallet_rpc("ms_wo")
        self.nodes[0].createwallet(wallet_name="ms_sig", descriptors=True)
        self.ms_sig_wallet = self.nodes[0].get_wallet_rpc("ms_sig")

        # Sanity check we wouldn't let an insane Miniscript descriptor in
        res = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create(
                        "wsh(and_b(ripemd160(1fd9b55a054a2b3f658d97e6b84cf3ee00be429a),a:1))"
                    ),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not res["success"]
        assert "is insecure: witnesses without signature exist" in res["error"]["message"]

        # Test we can track any type of Miniscript
        for ms in MINISCRIPTS:
            self.watchonly_test(ms)

        # Test we can sign most Miniscript (all but ones requiring preimages, for now)
        for ms in MINISCRIPTS_PRIV:
            self.signing_test(ms["ms"], ms["sequence"], ms["locktime"])


if __name__ == "__main__":
    WalletMiniscriptTest().main()
