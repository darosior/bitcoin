// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/tx_verify.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>

/** Check the BIP54 sigops limit for a transaction spending a fuzzer-provided list of legacy inputs. */
FUZZ_TARGET(bip54_sigops)
{
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy, /*deterministic=*/true);
    CMutableTransaction tx;
    Txid dummy_txid;

    // Use a DataStream in place of the usual FuzzedDataProvider in order to be able
    // to seed the corpus from the unit tests.
    if (buffer.empty()) return;
    DataStream buf{buffer};

    // Deserialize a list of legacy inputs spent by a transaction.
    try {
        uint16_t inputs_count;
        buf >> inputs_count;
        for (uint32_t i{0}; i < inputs_count; ++i) {
            tx.vin.emplace_back(dummy_txid, i);
            buf >> tx.vin.back().scriptSig;

            // Either the scriptPubKey (bare) or the redeemScript (P2SH).
            CScript spent_script;
            buf >> spent_script;

            // If it's P2SH, make sure to append the correct redeem script to the scriptSig.
            bool is_p2sh;
            buf >> is_p2sh;
            if (is_p2sh) {
                tx.vin.back().scriptSig << ToByteVector(spent_script);
            }

            // If it's P2SH, wrap the redeemScript in a P2SH scriptPubKey.
            auto prev_txo{[&](){
                if (is_p2sh) return CTxOut{0, CScript{} << OP_HASH160 << Hash160(spent_script) << OP_EQUALVERIFY};
                return CTxOut{0, std::move(spent_script)};
            }()};
            coins.AddCoin(tx.vin.back().prevout, Coin(prev_txo, 0, false), false);
        }
    } catch (const std::ios_base::failure& e) {
        return;
    }

    (void)Consensus::CheckSigopsBIP54(CTransaction(tx), coins);
}
