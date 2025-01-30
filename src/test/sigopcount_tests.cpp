// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript& s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(sigopcount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetSigOpCount)
{
    // Test CScript::GetSigOpCount()
    CScript s1;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0U);

    uint160 dummy;
    s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 2U);
    s1 << OP_IF << OP_CHECKSIG << OP_ENDIF;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 21U);

    CScript p2sh = GetScriptForDestination(ScriptHash(s1));
    CScript scriptSig;
    scriptSig << OP_0 << Serialize(s1);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

    std::vector<CPubKey> keys;
    for (int i = 0; i < 3; i++)
    {
        CKey k = GenerateRandomKey();
        keys.push_back(k.GetPubKey());
    }
    CScript s2 = GetScriptForMultisig(1, keys);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);

    p2sh = GetScriptForDestination(ScriptHash(s2));
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(true), 0U);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(false), 0U);
    CScript scriptSig2;
    scriptSig2 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << Serialize(s2);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig2), 3U);
}

/**
 * Verifies script execution of the zeroth scriptPubKey of tx output and
 * zeroth scriptSig and witness of tx input.
 */
static ScriptError VerifyWithFlag(const CTransaction& output, const CMutableTransaction& input, uint32_t flags)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &error);
    BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

    return error;
}

/**
 * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
 * and witness such that spendingTx spends output zero of creationTx.
 * Also inserts creationTx's output into the coins view.
 */
static void BuildTxs(CMutableTransaction& spendingTx, CCoinsViewCache& coins, CMutableTransaction& creationTx, const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& witness)
{
    creationTx.version = 1;
    creationTx.vin.resize(1);
    creationTx.vin[0].prevout.SetNull();
    creationTx.vin[0].scriptSig = CScript();
    creationTx.vout.resize(1);
    creationTx.vout[0].nValue = 1;
    creationTx.vout[0].scriptPubKey = scriptPubKey;

    spendingTx.version = 1;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = creationTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vin[0].scriptSig = scriptSig;
    spendingTx.vin[0].scriptWitness = witness;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = 1;
    spendingTx.vout[0].scriptPubKey = CScript();

    AddCoins(coins, CTransaction(creationTx), 0);
}

BOOST_AUTO_TEST_CASE(GetTxSigOpCost)
{
    // Transaction creates outputs
    CMutableTransaction creationTx;
    // Transaction that spends outputs and whose
    // sig op cost is going to be tested
    CMutableTransaction spendingTx;

    // Create utxo set
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Create key
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();
    // Default flags
    const uint32_t flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH};

    // Multisig script (legacy counting)
    {
        CScript scriptPubKey = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        // Do not use a valid signature to avoid using wallet operations.
        CScript scriptSig = CScript() << OP_0 << OP_0;

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        // Legacy counting only includes signature operations in scriptSigs and scriptPubKeys
        // of a transaction and does not take the actual executed sig operations into account.
        // spendingTx in itself does not contain a signature operation.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        // creationTx contains two signature operations in its scriptPubKey, but legacy counting
        // is not accurate.
        assert(GetTransactionSigOpCost(CTransaction(creationTx), coins, flags) == MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR);
        // Sanity check: script verification fails because of an invalid signature.
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // Multisig nested in P2SH
    {
        CScript redeemScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
        CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2 * WITNESS_SCALE_FACTOR);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WPKH witness program
    {
        CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);


        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        // No signature operations if we don't verify the witness.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);

        // The sig op cost for witness version != 0 is zero.
        assert(scriptPubKey[0] == 0x00);
        scriptPubKey[0] = 0x51;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        scriptPubKey[0] = 0x00;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);

        // The witness of a coinbase transaction is not taken into account.
        spendingTx.vin[0].prevout.SetNull();
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
    }

    // P2WPKH nested in P2SH
    {
        CScript scriptSig = GetScriptForDestination(WitnessV0KeyHash(pubkey));
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(scriptSig));
        scriptSig = CScript() << ToByteVector(scriptSig);
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);
    }

    // P2WSH witness program
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(witnessScript.begin(), witnessScript.end());

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WSH nested in P2SH
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript redeemScript = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
        CScript scriptSig = CScript() << ToByteVector(redeemScript);
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(witnessScript.begin(), witnessScript.end());

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }
}

BOOST_AUTO_TEST_CASE(legacysigops)
{
    CMutableTransaction tx;
    CCoinsView coins;
    CCoinsViewCache coins_cache{&coins};

    // An empty transaction has no potentially executed legacy sigops.
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 0);

    // Introducing an input that spends a script with a single CHECKSIG will count it.
    COutPoint op{*Txid::FromHex("2d05f0c9c3e1c226e63b5fac240137687544cf631cd616fd34fd188fc9020866"), 0};
    tx.vin.push_back(CTxIn{op});
    coins_cache.AddCoin(op, Coin(CTxOut{42, CScript() << OP_CHECKSIG}, 141, false), false);
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 1);

    // Adding a CHECKSIG to the scriptSig will be counted too.
    tx.vin[0].scriptSig << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 2);

    // Now if we add an input that spends a CHECKMULTISIG, it will be counted as the number of associated pubkeys.
    ++op.n;
    tx.vin.push_back(CTxIn{op});
    CScript spk{CScript() << 16 << OP_CHECKMULTISIG};
    coins_cache.AddCoin(op, Coin(CTxOut{341341341, spk}, 21, true), false);
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 18);

    // Now if we add a CHECKSIGADD it would not be counted since it cannot be used in legacy context.
    tx.vin[1].scriptSig << OP_CHECKSIGADD;
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 18);

    // But a CHECKMULTISIG would be counted alright.
    tx.vin[1].scriptSig << 1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 19);

    // A CHECKMULTISIG and a CHECKSIGVERIFY inside P2SH are counted.
    ++op.n;
    tx.vin.push_back(CTxIn{op});
    CScript redeem_script{CScript() << 1 << OP_CHECKMULTISIG << OP_CHECKSIGVERIFY};
    CScript p2sh_script{GetScriptForDestination(ScriptHash(redeem_script))};
    BOOST_CHECK(p2sh_script.IsPayToScriptHash());
    tx.vin.push_back(CTxIn{op});
    tx.vin[2].scriptSig << ToByteVector(redeem_script);
    coins_cache.AddCoin(op, Coin(CTxOut{3434, p2sh_script}, 35, true), false);
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 21);

    // Now we add a coin from a different transaction with a ton of sigops from mixed opcodes, they'll all get counted.
    COutPoint sec_op{*Txid::FromHex("fe28050b93faea61fa88c4c630f0e1f0a1c24d0082dd0e10d369e13212128f33"), 30};
    tx.vin.push_back(CTxIn{sec_op});
    CScript large_spk{CScript() << 2};
    large_spk << 17 << OP_CHECKMULTISIGVERIFY;
    for (int i{0}; i < 174; ++i) large_spk << OP_CHECKSIG;
    coins_cache.AddCoin(sec_op, Coin(CTxOut{31313131, large_spk}, 32, false), false);
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), 215); // NOTE: 17 pubkeys in CMS get counted as 20 sigops.

    // Finally add inputs with a bunch of CHECKSIG's until we reach the legacy sigops limit.
    for (int i{215}; i < (int)MAX_TX_LEGACY_SIGOPS; i += 5) {
        ++sec_op.n;
        tx.vin.push_back(CTxIn{sec_op});
        for (int j{0}; j < 5; ++j) tx.vin.back().scriptSig << OP_CHECKSIGVERIFY;
        coins_cache.AddCoin(sec_op, Coin(CTxOut{i, CScript{}}, i, false), false);
    }
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), MAX_TX_LEGACY_SIGOPS);

    // Adding one more will make it reach a higher value and would fail the check in ConnectBlock past consensus cleanup activation.
    ++op.n;
    tx.vin.push_back(CTxIn{op});
    CScript spk2{CScript() << OP_CHECKSIG};
    coins_cache.AddCoin(op, Coin(CTxOut{90909090, spk2}, 112, true), false);
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), MAX_TX_LEGACY_SIGOPS + 1);

    // Changing other fields in the transaction have no incidence whatsoever on the returned value.
    tx.version = 113;
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), MAX_TX_LEGACY_SIGOPS + 1);
    tx.nLockTime = 130;
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), MAX_TX_LEGACY_SIGOPS + 1);
    tx.vin[tx.vin.size() / 2].nSequence = 147;
    BOOST_CHECK_EQUAL(GetLegacySigOps(CTransaction(tx), coins_cache), MAX_TX_LEGACY_SIGOPS + 1);
}

BOOST_AUTO_TEST_SUITE_END()
