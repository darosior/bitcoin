// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/util/setup_common.h>

#include <checkqueue.h>
#include <clientversion.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <key.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/transaction_utils.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <functional>
#include <map>
#include <ranges>
#include <string>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

// Uncomment if you want to output updated JSON tests.
// #define UPDATE_JSON_TESTS

using namespace util::hex_literals;
using util::SplitString;
using util::ToString;

typedef std::vector<unsigned char> valtype;

static CFeeRate g_dust{DUST_RELAY_TX_FEE};
static bool g_bare_multi{DEFAULT_PERMIT_BAREMULTISIG};

static const std::map<std::string, unsigned int>& mapFlagNames = g_verify_flag_names;

unsigned int ParseScriptFlags(std::string strFlags)
{
    unsigned int flags = SCRIPT_VERIFY_NONE;
    if (strFlags.empty() || strFlags == "NONE") return flags;

    std::vector<std::string> words = SplitString(strFlags, ',');
    for (const std::string& word : words)
    {
        if (!mapFlagNames.count(word)) {
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
            continue;
        }
        flags |= mapFlagNames.at(word);
    }
    return flags;
}

// Check that all flags in STANDARD_SCRIPT_VERIFY_FLAGS are present in mapFlagNames.
bool CheckMapFlagNames()
{
    unsigned int standard_flags_missing{STANDARD_SCRIPT_VERIFY_FLAGS};
    for (const auto& pair : mapFlagNames) {
        standard_flags_missing &= ~(pair.second);
    }
    return standard_flags_missing == 0;
}

/*
* Check that the input scripts of a transaction are valid/invalid as expected.
*/
bool CheckTxScripts(const CTransaction& tx, const std::map<COutPoint, CScript>& map_prevout_scriptPubKeys,
    const std::map<COutPoint, int64_t>& map_prevout_values, unsigned int flags,
    const PrecomputedTransactionData& txdata, const std::string& strTest, bool expect_valid)
{
    bool tx_valid = true;
    ScriptError err = expect_valid ? SCRIPT_ERR_UNKNOWN_ERROR : SCRIPT_ERR_OK;
    for (unsigned int i = 0; i < tx.vin.size() && tx_valid; ++i) {
        const CTxIn input = tx.vin[i];
        const CAmount amount = map_prevout_values.count(input.prevout) ? map_prevout_values.at(input.prevout) : 0;
        try {
            tx_valid = VerifyScript(input.scriptSig, map_prevout_scriptPubKeys.at(input.prevout),
                &input.scriptWitness, flags, TransactionSignatureChecker(&tx, i, amount, txdata, MissingDataBehavior::ASSERT_FAIL), &err);
        } catch (...) {
            BOOST_ERROR("Bad test: " << strTest);
            return true; // The test format is bad and an error is thrown. Return true to silence further error.
        }
        if (expect_valid) {
            BOOST_CHECK_MESSAGE(tx_valid, strTest);
            BOOST_CHECK_MESSAGE((err == SCRIPT_ERR_OK), ScriptErrorString(err));
            err = SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    if (!expect_valid) {
        BOOST_CHECK_MESSAGE(!tx_valid, strTest);
        BOOST_CHECK_MESSAGE((err != SCRIPT_ERR_OK), ScriptErrorString(err));
    }
    return (tx_valid == expect_valid);
}

/*
 * Trim or fill flags to make the combination valid:
 * WITNESS must be used with P2SH
 * CLEANSTACK must be used WITNESS and P2SH
 */

unsigned int TrimFlags(unsigned int flags)
{
    // WITNESS requires P2SH
    if (!(flags & SCRIPT_VERIFY_P2SH)) flags &= ~(unsigned int)SCRIPT_VERIFY_WITNESS;

    // CLEANSTACK requires WITNESS (and transitively CLEANSTACK requires P2SH)
    if (!(flags & SCRIPT_VERIFY_WITNESS)) flags &= ~(unsigned int)SCRIPT_VERIFY_CLEANSTACK;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

unsigned int FillFlags(unsigned int flags)
{
    // CLEANSTACK implies WITNESS
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_WITNESS;

    // WITNESS implies P2SH (and transitively CLEANSTACK implies P2SH)
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

// Exclude each possible script verify flag from flags. Returns a set of these flag combinations
// that are valid and without duplicates. For example: if flags=1111 and the 4 possible flags are
// 0001, 0010, 0100, and 1000, this should return the set {0111, 1011, 1101, 1110}.
// Assumes that mapFlagNames contains all script verify flags.
std::set<unsigned int> ExcludeIndividualFlags(unsigned int flags)
{
    std::set<unsigned int> flags_combos;
    for (const auto& pair : mapFlagNames) {
        const unsigned int flags_excluding_one = TrimFlags(flags & ~(pair.second));
        if (flags != flags_excluding_one) {
            flags_combos.insert(flags_excluding_one);
        }
    }
    return flags_combos;
}

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tx_valid)
{
    BOOST_CHECK_MESSAGE(CheckMapFlagNames(), "mapFlagNames is missing a script verification flag");
    // Read tests from test/data/tx_valid.json
    UniValue tests = read_json(json_tests::tx_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue& input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4)
                {
                    fValid = false;
                    break;
                }
                COutPoint outpoint{Txid::FromHex(vinput[0].get_str()).value(), uint32_t(vinput[1].getInt<int>())};
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].getInt<int64_t>();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream(ParseHex(transaction));
            CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

            TxValidationState state;
            BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), strTest);
            BOOST_CHECK(state.IsValid());

            PrecomputedTransactionData txdata(tx);
            unsigned int verify_flags = ParseScriptFlags(test[2].get_str());

            // Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            if (~verify_flags != FillFlags(~verify_flags)) {
                BOOST_ERROR("Bad test flags: " << strTest);
            }

            BOOST_CHECK_MESSAGE(CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, ~verify_flags, txdata, strTest, /*expect_valid=*/true),
                                "Tx unexpectedly failed: " << strTest);

            // Backwards compatibility of script verification flags: Removing any flag(s) should not invalidate a valid transaction
            for (const auto& [name, flag] : mapFlagNames) {
                // Removing individual flags
                unsigned int flags = TrimFlags(~(verify_flags | flag));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Tx unexpectedly failed with flag " << name << " unset: " << strTest);
                }
                // Removing random combinations of flags
                flags = TrimFlags(~(verify_flags | (unsigned int)m_rng.randbits(mapFlagNames.size())));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Tx unexpectedly failed with random flags " << ToString(flags) << ": " << strTest);
                }
            }

            // Check that flags are maximal: transaction should fail if any unset flags are set.
            for (auto flags_excluding_one : ExcludeIndividualFlags(verify_flags)) {
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, ~flags_excluding_one, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Too many flags unset: " << strTest);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid.json
    UniValue tests = read_json(json_tests::tx_invalid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue& input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4)
                {
                    fValid = false;
                    break;
                }
                COutPoint outpoint{Txid::FromHex(vinput[0].get_str()).value(), uint32_t(vinput[1].getInt<int>())};
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].getInt<int64_t>();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream(ParseHex(transaction));
            CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

            TxValidationState state;
            if (!CheckTransaction(tx, state) || state.IsInvalid()) {
                BOOST_CHECK_MESSAGE(test[2].get_str() == "BADTX", strTest);
                continue;
            }

            PrecomputedTransactionData txdata(tx);
            unsigned int verify_flags = ParseScriptFlags(test[2].get_str());

            // Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            if (verify_flags != FillFlags(verify_flags)) {
                BOOST_ERROR("Bad test flags: " << strTest);
            }

            // Not using FillFlags() in the main test, in order to detect invalid verifyFlags combination
            BOOST_CHECK_MESSAGE(CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, verify_flags, txdata, strTest, /*expect_valid=*/false),
                                "Tx unexpectedly passed: " << strTest);

            // Backwards compatibility of script verification flags: Adding any flag(s) should not validate an invalid transaction
            for (const auto& [name, flag] : mapFlagNames) {
                unsigned int flags = FillFlags(verify_flags | flag);
                // Adding individual flags
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Tx unexpectedly passed with flag " << name << " set: " << strTest);
                }
                // Adding random combinations of flags
                flags = FillFlags(verify_flags | (unsigned int)m_rng.randbits(mapFlagNames.size()));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Tx unexpectedly passed with random flags " << name << ": " << strTest);
                }
            }

            // Check that flags are minimal: transaction should succeed if any set flags are unset.
            for (auto flags_excluding_one : ExcludeIndividualFlags(verify_flags)) {
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags_excluding_one, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Too many flags set: " << strTest);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_no_inputs)
{
    CMutableTransaction empty;

    TxValidationState state;
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(empty), state), "Transaction with no inputs should be invalid.");
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-vin-empty");
}

BOOST_AUTO_TEST_CASE(tx_oversized)
{
    auto createTransaction =[](size_t payloadSize) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.emplace_back(1, CScript() << OP_RETURN << std::vector<unsigned char>(payloadSize));
        return CTransaction(tx);
    };
    const auto maxTransactionSize = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    const auto oversizedTransactionBaseSize = ::GetSerializeSize(TX_NO_WITNESS(createTransaction(maxTransactionSize))) - maxTransactionSize;

    auto maxPayloadSize = maxTransactionSize - oversizedTransactionBaseSize;
    {
        TxValidationState state;
        CheckTransaction(createTransaction(maxPayloadSize), state);
        BOOST_CHECK(state.GetRejectReason() != "bad-txns-oversize");
    }

    maxPayloadSize += 1;
    {
        TxValidationState state;
        BOOST_CHECK_MESSAGE(!CheckTransaction(createTransaction(maxPayloadSize), state), "Oversized transaction should be invalid");
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-oversize");
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    // Random real transaction (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    DataStream stream(vch);
    CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction(tx), state) && state.IsValid(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(tx), state) || !state.IsValid(), "Transaction with duplicate txins should be invalid.");
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins));
}

static void CreateCreditAndSpend(const FillableSigningProvider& keystore, const CScript& outscript, CTransactionRef& output, CMutableTransaction& input, bool success = true)
{
    CMutableTransaction outputm;
    outputm.version = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = outscript;
    DataStream ssout;
    ssout << TX_WITH_WITNESS(outputm);
    ssout >> TX_WITH_WITNESS(output);
    assert(output->vin.size() == 1);
    assert(output->vin[0] == outputm.vin[0]);
    assert(output->vout.size() == 1);
    assert(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.version = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout.hash = output->GetHash();
    inputm.vin[0].prevout.n = 0;
    inputm.vout.resize(1);
    inputm.vout[0].nValue = 1;
    inputm.vout[0].scriptPubKey = CScript();
    SignatureData empty;
    bool ret = SignSignature(keystore, *output, inputm, 0, SIGHASH_ALL, empty);
    assert(ret == success);
    DataStream ssin;
    ssin << TX_WITH_WITNESS(inputm);
    ssin >> TX_WITH_WITNESS(input);
    assert(input.vin.size() == 1);
    assert(input.vin[0] == inputm.vin[0]);
    assert(input.vout.size() == 1);
    assert(input.vout[0] == inputm.vout[0]);
    assert(input.vin[0].scriptWitness.stack == inputm.vin[0].scriptWitness.stack);
}

static void CheckWithFlag(const CTransactionRef& output, const CMutableTransaction& input, uint32_t flags, bool success)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output->vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output->vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &error);
    assert(ret == success);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

static void ReplaceRedeemScript(CScript& script, const CScript& redeemScript)
{
    std::vector<valtype> stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
    assert(stack.size() > 0);
    stack.back() = std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_witness_transaction)
{
    CMutableTransaction mtx;
    mtx.version = 1;

    CKey key = GenerateRandomKey(); // Need to use compressed keys in segwit or the signing will fail
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKeyPubKey(key, key.GetPubKey()));
    CKeyID hash = key.GetPubKey().GetID();
    CScript scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(hash.begin(), hash.end());

    std::vector<int> sigHashes;
    sigHashes.push_back(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_NONE);
    sigHashes.push_back(SIGHASH_SINGLE);
    sigHashes.push_back(SIGHASH_ALL);

    // create a big transaction of 4500 inputs signed by the same key
    for(uint32_t ij = 0; ij < 4500; ij++) {
        uint32_t i = mtx.vin.size();
        COutPoint outpoint(Txid::FromHex("0000000000000000000000000000000000000000000000000000000000000100").value(), i);

        mtx.vin.resize(mtx.vin.size() + 1);
        mtx.vin[i].prevout = outpoint;
        mtx.vin[i].scriptSig = CScript();

        mtx.vout.resize(mtx.vout.size() + 1);
        mtx.vout[i].nValue = 1000;
        mtx.vout[i].scriptPubKey = CScript() << OP_1;
    }

    // sign all inputs
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        SignatureData empty;
        bool hashSigned = SignSignature(keystore, scriptPubKey, mtx, i, 1000, sigHashes.at(i % sigHashes.size()), empty);
        assert(hashSigned);
    }

    DataStream ssout;
    ssout << TX_WITH_WITNESS(mtx);
    CTransaction tx(deserialize, TX_WITH_WITNESS, ssout);

    // check all inputs concurrently, with the cache
    PrecomputedTransactionData txdata(tx);
    CCheckQueue<CScriptCheck> scriptcheckqueue(/*batch_size=*/128, /*worker_threads_num=*/20);
    CCheckQueueControl<CScriptCheck> control(&scriptcheckqueue);

    std::vector<Coin> coins;
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        Coin coin;
        coin.nHeight = 1;
        coin.fCoinBase = false;
        coin.out.nValue = 1000;
        coin.out.scriptPubKey = scriptPubKey;
        coins.emplace_back(std::move(coin));
    }

    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        std::vector<CScriptCheck> vChecks;
        vChecks.emplace_back(coins[tx.vin[i].prevout.n].out, tx, signature_cache, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false, &txdata);
        control.Add(std::move(vChecks));
    }

    bool controlCheck = !control.Complete().has_value();
    assert(controlCheck);
}

SignatureData CombineSignatures(const CMutableTransaction& input1, const CMutableTransaction& input2, const CTransactionRef tx)
{
    SignatureData sigdata;
    sigdata = DataFromTransaction(input1, 0, tx->vout[0]);
    sigdata.MergeSignatureData(DataFromTransaction(input2, 0, tx->vout[0]));
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(input1, 0, tx->vout[0].nValue, SIGHASH_ALL), tx->vout[0].scriptPubKey, sigdata);
    return sigdata;
}

BOOST_AUTO_TEST_CASE(test_witness)
{
    FillableSigningProvider keystore, keystore2;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey();
    CKey key3 = GenerateRandomKey();
    CKey key1L = GenerateRandomKey(/*compressed=*/false);
    CKey key2L = GenerateRandomKey(/*compressed=*/false);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    CPubKey pubkey3 = key3.GetPubKey();
    CPubKey pubkey1L = key1L.GetPubKey();
    CPubKey pubkey2L = key2L.GetPubKey();
    BOOST_CHECK(keystore.AddKeyPubKey(key1, pubkey1));
    BOOST_CHECK(keystore.AddKeyPubKey(key2, pubkey2));
    BOOST_CHECK(keystore.AddKeyPubKey(key1L, pubkey1L));
    BOOST_CHECK(keystore.AddKeyPubKey(key2L, pubkey2L));
    CScript scriptPubkey1, scriptPubkey2, scriptPubkey1L, scriptPubkey2L, scriptMulti;
    scriptPubkey1 << ToByteVector(pubkey1) << OP_CHECKSIG;
    scriptPubkey2 << ToByteVector(pubkey2) << OP_CHECKSIG;
    scriptPubkey1L << ToByteVector(pubkey1L) << OP_CHECKSIG;
    scriptPubkey2L << ToByteVector(pubkey2L) << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1L));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2L));
    BOOST_CHECK(keystore.AddCScript(scriptMulti));
    CScript destination_script_1, destination_script_2, destination_script_1L, destination_script_2L, destination_script_multi;
    destination_script_1 = GetScriptForDestination(WitnessV0KeyHash(pubkey1));
    destination_script_2 = GetScriptForDestination(WitnessV0KeyHash(pubkey2));
    destination_script_1L = GetScriptForDestination(WitnessV0KeyHash(pubkey1L));
    destination_script_2L = GetScriptForDestination(WitnessV0KeyHash(pubkey2L));
    destination_script_multi = GetScriptForDestination(WitnessV0ScriptHash(scriptMulti));
    BOOST_CHECK(keystore.AddCScript(destination_script_1));
    BOOST_CHECK(keystore.AddCScript(destination_script_2));
    BOOST_CHECK(keystore.AddCScript(destination_script_1L));
    BOOST_CHECK(keystore.AddCScript(destination_script_2L));
    BOOST_CHECK(keystore.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddCScript(scriptMulti));
    BOOST_CHECK(keystore2.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddKeyPubKey(key3, pubkey3));

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;

    // Normal pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Witness pay-to-compressed-pubkey (v0).
    CreateCreditAndSpend(keystore, destination_script_1, output1, input1);
    CreateCreditAndSpend(keystore, destination_script_2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH witness pay-to-compressed-pubkey (v0).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, destination_script_1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1L, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2L, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1L)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2L)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1L);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Signing disabled for witness pay-to-uncompressed-pubkey (v1).
    CreateCreditAndSpend(keystore, destination_script_1L, output1, input1, false);
    CreateCreditAndSpend(keystore, destination_script_2L, output2, input2, false);

    // Signing disabled for P2SH witness pay-to-uncompressed-pubkey (v1).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1L)), output1, input1, false);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2L)), output2, input2, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptMulti)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(scriptMulti)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // Witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, destination_script_multi, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, destination_script_multi, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_multi)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(destination_script_multi)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90*CENT;
    CKey key = GenerateRandomKey();
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    constexpr auto CheckIsStandard = [](const auto& t, const unsigned int max_op_return_relay = MAX_OP_RETURN_RELAY) {
        std::string reason;
        BOOST_CHECK(IsStandardTx(CTransaction{t}, max_op_return_relay, g_bare_multi, g_dust, reason));
        BOOST_CHECK(reason.empty());
    };
    constexpr auto CheckIsNotStandard = [](const auto& t, const std::string& reason_in, const unsigned int max_op_return_relay = MAX_OP_RETURN_RELAY) {
        std::string reason;
        BOOST_CHECK(!IsStandardTx(CTransaction{t}, max_op_return_relay, g_bare_multi, g_dust, reason));
        BOOST_CHECK_EQUAL(reason_in, reason);
    };

    CheckIsStandard(t);

    // Check dust with default relay fee:
    CAmount nDustThreshold = 182 * g_dust.GetFeePerK() / 1000;
    BOOST_CHECK_EQUAL(nDustThreshold, 546);

    // Add dust outputs up to allowed maximum, still standard!
    for (size_t i{0}; i < MAX_DUST_OUTPUTS_PER_TX; ++i) {
        t.vout.emplace_back(0, t.vout[0].scriptPubKey);
        CheckIsStandard(t);
    }

    // dust:
    t.vout[0].nValue = nDustThreshold - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    CheckIsStandard(t);

    // Disallowed version
    t.version = std::numeric_limits<uint32_t>::max();
    CheckIsNotStandard(t, "version");

    t.version = 0;
    CheckIsNotStandard(t, "version");

    t.version = TX_MAX_STANDARD_VERSION + 1;
    CheckIsNotStandard(t, "version");

    // Allowed version
    t.version = 1;
    CheckIsStandard(t);

    t.version = 2;
    CheckIsStandard(t);

    // Check dust with odd relay fee to verify rounding:
    // nDustThreshold = 182 * 3702 / 1000
    g_dust = CFeeRate(3702);
    // dust:
    t.vout[0].nValue = 674 - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = 674;
    CheckIsStandard(t);
    g_dust = CFeeRate{DUST_RELAY_TX_FEE};

    t.vout[0].scriptPubKey = CScript() << OP_1;
    CheckIsNotStandard(t, "scriptpubkey");

    // Custom 83-byte TxoutType::NULL_DATA (standard with max_op_return_relay of 83)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    BOOST_CHECK_EQUAL(83, t.vout[0].scriptPubKey.size());
    CheckIsStandard(t, /*max_op_return_relay=*/83);

    // Non-standard if max_op_return_relay datacarrier arg is one less
    CheckIsNotStandard(t, "datacarrier", /*max_op_return_relay=*/82);

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ""_hex;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "00"_hex << "01"_hex;
    CheckIsStandard(t);
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0 << "01"_hex << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << 0 << "01"_hex << 2 << "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex;
    CheckIsStandard(t);

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    CheckIsNotStandard(t, "scriptpubkey");

    // TxoutType::NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    // Multiple TxoutType::NULL_DATA are permitted
    t.vout.resize(2);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[0].nValue = 0;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].nValue = 0;
    CheckIsStandard(t);

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    const auto datacarrier_size = t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size();
    CheckIsStandard(t); // Default max relay should never trigger
    CheckIsStandard(t, /*max_op_return_relay=*/datacarrier_size);
    CheckIsNotStandard(t, "datacarrier", /*max_op_return_relay=*/datacarrier_size-1);

    // Check large scriptSig (non-standard if size is >1650 bytes)
    t.vout.resize(1);
    t.vout[0].nValue = MAX_MONEY;
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    // OP_PUSHDATA2 with len (3 bytes) + data (1647 bytes) = 1650 bytes
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1647, 0); // 1650
    CheckIsStandard(t);

    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1648, 0); // 1651
    CheckIsNotStandard(t, "scriptsig-size");

    // Check scriptSig format (non-standard if there are any other ops than just PUSHs)
    t.vin[0].scriptSig = CScript()
        << OP_TRUE << OP_0 << OP_1NEGATE << OP_16 // OP_n (single byte pushes: n = 1, 0, -1, 16)
        << std::vector<unsigned char>(75, 0)      // OP_PUSHx [...x bytes...]
        << std::vector<unsigned char>(235, 0)     // OP_PUSHDATA1 x [...x bytes...]
        << std::vector<unsigned char>(1234, 0)    // OP_PUSHDATA2 x [...x bytes...]
        << OP_9;
    CheckIsStandard(t);

    const std::vector<unsigned char> non_push_ops = { // arbitrary set of non-push operations
        OP_NOP, OP_VERIFY, OP_IF, OP_ROT, OP_3DUP, OP_SIZE, OP_EQUAL, OP_ADD, OP_SUB,
        OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKLOCKTIMEVERIFY };

    CScript::const_iterator pc = t.vin[0].scriptSig.begin();
    while (pc < t.vin[0].scriptSig.end()) {
        opcodetype opcode;
        CScript::const_iterator prev_pc = pc;
        t.vin[0].scriptSig.GetOp(pc, opcode); // advance to next op
        // for the sake of simplicity, we only replace single-byte push operations
        if (opcode >= 1 && opcode <= OP_PUSHDATA4)
            continue;

        int index = prev_pc - t.vin[0].scriptSig.begin();
        unsigned char orig_op = *prev_pc; // save op
        // replace current push-op with each non-push-op
        for (auto op : non_push_ops) {
            t.vin[0].scriptSig[index] = op;
            CheckIsNotStandard(t, "scriptsig-not-pushonly");
        }
        t.vin[0].scriptSig[index] = orig_op; // restore op
        CheckIsStandard(t);
    }

    // Check tx-size (non-standard if transaction weight is > MAX_STANDARD_TX_WEIGHT)
    t.vin.clear();
    t.vin.resize(2438); // size per input (empty scriptSig): 41 bytes
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(19, 0); // output size: 30 bytes
    // tx header:                12 bytes =>     48 weight units
    // 2438 inputs: 2438*41 = 99958 bytes => 399832 weight units
    //    1 output:              30 bytes =>    120 weight units
    //                      ======================================
    //                                total: 400000 weight units
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction(t)), 400000);
    CheckIsStandard(t);

    // increase output size by one byte, so we end up with 400004 weight units
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(20, 0); // output size: 31 bytes
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction(t)), 400004);
    CheckIsNotStandard(t, "tx-size");

    // Check bare multisig (standard if policy flag g_bare_multi is set)
    g_bare_multi = true;
    t.vout[0].scriptPubKey = GetScriptForMultisig(1, {key.GetPubKey()}); // simple 1-of-1
    t.vin.resize(1);
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(65, 0);
    CheckIsStandard(t);

    g_bare_multi = false;
    CheckIsNotStandard(t, "bare-multisig");
    g_bare_multi = DEFAULT_PERMIT_BAREMULTISIG;

    // Add dust outputs up to allowed maximum
    assert(t.vout.size() == 1);
    t.vout.insert(t.vout.end(), MAX_DUST_OUTPUTS_PER_TX, {0, t.vout[0].scriptPubKey});

    // Check compressed P2PK outputs dust threshold (must have leading 02 or 03)
    t.vout[0].scriptPubKey = CScript() << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG;
    t.vout[0].nValue = 576;
    CheckIsStandard(t);
    t.vout[0].nValue = 575;
    CheckIsNotStandard(t, "dust");

    // Check uncompressed P2PK outputs dust threshold (must have leading 04/06/07)
    t.vout[0].scriptPubKey = CScript() << std::vector<unsigned char>(65, 0x04) << OP_CHECKSIG;
    t.vout[0].nValue = 672;
    CheckIsStandard(t);
    t.vout[0].nValue = 671;
    CheckIsNotStandard(t, "dust");

    // Check P2PKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    t.vout[0].nValue = 546;
    CheckIsStandard(t);
    t.vout[0].nValue = 545;
    CheckIsNotStandard(t, "dust");

    // Check P2SH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUAL;
    t.vout[0].nValue = 540;
    CheckIsStandard(t);
    t.vout[0].nValue = 539;
    CheckIsNotStandard(t, "dust");

    // Check P2WPKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0);
    t.vout[0].nValue = 294;
    CheckIsStandard(t);
    t.vout[0].nValue = 293;
    CheckIsNotStandard(t, "dust");

    // Check P2WSH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = 330;
    CheckIsStandard(t);
    t.vout[0].nValue = 329;
    CheckIsNotStandard(t, "dust");

    // Check P2TR outputs dust threshold (Invalid xonly key ok!)
    t.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = 330;
    CheckIsStandard(t);
    t.vout[0].nValue = 329;
    CheckIsNotStandard(t, "dust");

    // Check future Witness Program versions dust threshold (non-32-byte pushes are undefined for version 1)
    for (int op = OP_1; op <= OP_16; op += 1) {
        t.vout[0].scriptPubKey = CScript() << (opcodetype)op << std::vector<unsigned char>(2, 0);
        t.vout[0].nValue = 240;
        CheckIsStandard(t);

        t.vout[0].nValue = 239;
        CheckIsNotStandard(t, "dust");
    }

    // Check anchor outputs
    t.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>{0x4e, 0x73};
    BOOST_CHECK(t.vout[0].scriptPubKey.IsPayToAnchor());
    t.vout[0].nValue = 240;
    CheckIsStandard(t);
    t.vout[0].nValue = 239;
    CheckIsNotStandard(t, "dust");
}

BOOST_AUTO_TEST_CASE(max_standard_legacy_sigops)
{
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    CKey key;
    key.MakeNewKey(true);

    // Create a pathological P2SH script padded with as many sigops as is standard.
    CScript max_sigops_redeem_script{CScript() << std::vector<unsigned char>{} << key.GetPubKey()};
    for (unsigned i{0}; i < MAX_P2SH_SIGOPS - 1; ++i) max_sigops_redeem_script << OP_2DUP << OP_CHECKSIG << OP_DROP;
    max_sigops_redeem_script << OP_CHECKSIG << OP_NOT;
    const CScript max_sigops_p2sh{GetScriptForDestination(ScriptHash(max_sigops_redeem_script))};

    // Create a transaction fanning out as many such P2SH outputs as is standard to spend in a
    // single transaction, and a transaction spending them.
    CMutableTransaction tx_create, tx_max_sigops;
    const unsigned p2sh_inputs_count{MAX_TX_LEGACY_SIGOPS / MAX_P2SH_SIGOPS};
    tx_create.vout.reserve(p2sh_inputs_count);
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_create.vout.emplace_back(424242 + i, max_sigops_p2sh);
    }
    auto prev_txid{tx_create.GetHash()};
    tx_max_sigops.vin.reserve(p2sh_inputs_count);
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i, CScript() << ToByteVector(max_sigops_redeem_script));
    }

    // p2sh_inputs_count is truncated to 166 (from 166.6666..)
    BOOST_CHECK_LT(p2sh_inputs_count * MAX_P2SH_SIGOPS, MAX_TX_LEGACY_SIGOPS);
    AddCoins(coins, CTransaction(tx_create), 0, false);

    // 2490 sigops is below the limit.
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(tx_max_sigops), coins), 2490);
    BOOST_CHECK(::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Adding one more input will bump this to 2505, hitting the limit.
    tx_create.vout.emplace_back(424242, max_sigops_p2sh);
    prev_txid = tx_create.GetHash();
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_max_sigops.vin[i] = CTxIn(COutPoint(prev_txid, i), CScript() << ToByteVector(max_sigops_redeem_script));
    }
    tx_max_sigops.vin.emplace_back(prev_txid, p2sh_inputs_count, CScript() << ToByteVector(max_sigops_redeem_script));
    AddCoins(coins, CTransaction(tx_create), 0, false);
    BOOST_CHECK_GT((p2sh_inputs_count + 1) * MAX_P2SH_SIGOPS, MAX_TX_LEGACY_SIGOPS);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(tx_max_sigops), coins), 2505);
    BOOST_CHECK(!::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Now, check the limit can be reached with regular P2PK outputs too. Use a separate
    // preparation transaction, to demonstrate spending coins from a single tx is irrelevant.
    CMutableTransaction tx_create_p2pk;
    const auto p2pk_script{CScript() << key.GetPubKey() << OP_CHECKSIG};
    unsigned p2pk_inputs_count{10}; // From 2490 to 2500.
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_create_p2pk.vout.emplace_back(212121 + i, p2pk_script);
    }
    prev_txid = tx_create_p2pk.GetHash();
    tx_max_sigops.vin.resize(p2sh_inputs_count); // Drop the extra input.
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }
    AddCoins(coins, CTransaction(tx_create_p2pk), 0, false);

    // The transaction now contains exactly 2500 sigops, the check should pass.
    BOOST_CHECK_EQUAL(p2sh_inputs_count * MAX_P2SH_SIGOPS + p2pk_inputs_count * 1, MAX_TX_LEGACY_SIGOPS);
    BOOST_CHECK(::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Now, add some Segwit inputs. We add one for each defined Segwit output type. The limit
    // is exclusively on non-witness sigops and therefore those should not be counted.
    CMutableTransaction tx_create_segwit;
    const auto witness_script{CScript() << key.GetPubKey() << OP_CHECKSIG};
    tx_create_segwit.vout.emplace_back(121212, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));
    tx_create_segwit.vout.emplace_back(131313, GetScriptForDestination(WitnessV0ScriptHash(witness_script)));
    tx_create_segwit.vout.emplace_back(141414, GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey(key.GetPubKey())}));
    prev_txid = tx_create_segwit.GetHash();
    for (unsigned i{0}; i < tx_create_segwit.vout.size(); ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }

    // The transaction now still contains exactly 2500 sigops, the check should pass.
    AddCoins(coins, CTransaction(tx_create_segwit), 0, false);
    BOOST_REQUIRE(::AreInputsStandard(CTransaction(tx_max_sigops), coins));

    // Add one more P2PK input. We'll reach the limit.
    tx_create_p2pk.vout.emplace_back(212121, p2pk_script);
    prev_txid = tx_create_p2pk.GetHash();
    tx_max_sigops.vin.resize(p2sh_inputs_count);
    ++p2pk_inputs_count;
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }
    AddCoins(coins, CTransaction(tx_create_p2pk), 0, false);
    BOOST_CHECK_GT(p2sh_inputs_count * MAX_P2SH_SIGOPS + p2pk_inputs_count * 1, MAX_TX_LEGACY_SIGOPS);
    BOOST_CHECK(!::AreInputsStandard(CTransaction(tx_max_sigops), coins));
}

/** Get the (non-extended) child private key at the provided derivation index. */
static CKey GetKeyAt(CExtKey parent_xprv, unsigned int idx)
{
    CExtKey child_xprv;
    Assert(parent_xprv.Derive(child_xprv, idx));
    return child_xprv.key;
}

/** Generate an ECDSA signature for a specified input. */
static std::vector<uint8_t> SignInput(const CKey& key, const CScript& spent_script, CMutableTransaction& tx, unsigned idx, unsigned type = SIGHASH_ALL)
{
    const CAmount dummy{0};
    std::vector<uint8_t> sig;
    const auto sighash{SignatureHash(spent_script, tx, idx, type, dummy, SigVersion::BASE)};
    Assert(key.Sign(sighash, sig));
    sig.push_back(static_cast<uint8_t>(type));
    return sig;
}

/** Verify a transaction input's script against consensus rules. */
static bool VerifyTxin(const CScript& spent_script, CMutableTransaction& tx, unsigned idx, std::vector<CTxOut>&& spent_outputs, const CAmount& amount)
{
    Assert(idx < tx.vin.size());
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::forward<std::vector<CTxOut>>(spent_outputs), /*force=*/true);
    const auto checker{MutableTransactionSignatureChecker(&tx, idx, amount, txdata, MissingDataBehavior::ASSERT_FAIL)};
    return VerifyScript(tx.vin[idx].scriptSig, spent_script, &tx.vin[idx].scriptWitness, MANDATORY_SCRIPT_VERIFY_FLAGS, checker);
}

/** Verify a Segwit v0 input's script. */
static bool VerifyTxin(const CScript& spent_script, CMutableTransaction& tx, unsigned idx, const CAmount& amount)
{
    return VerifyTxin(spent_script, tx, idx, {}, amount);
}

/** Verify a legacy input's script. */
static bool VerifyTxin(const CScript& spent_script, CMutableTransaction& tx, unsigned idx)
{
    return VerifyTxin(spent_script, tx, idx, {}, 0);
}

/** Get a list of all coins spent by this transaction. All coins must be in cache. */
template<typename T>
static std::vector<CTxOut> RecordSpent(const CCoinsViewCache& coins, const T& tx)
{
    std::vector<CTxOut> spent_outputs(tx.vin.size());
    for (size_t i{0}; i < tx.vin.size(); ++i) {
        const auto coin{*Assert(coins.GetCoin(tx.vin[i].prevout))};
        spent_outputs[i] = std::move(coin.out);
    }
    return spent_outputs;
}

/** A test vector for the per-transaction sigop limit in BIP54. */
struct BIP54SigopsTestVector {
    //! The transaction being evaluated.
    const CTransaction spending_tx;
    //! The outputs corresponding to the transaction's inputs.
    const std::vector<CTxOut> spent_outputs;
    //! Whether this transaction passes the BIP54 sigops check.
    const bool success;
    //! Description of the test vector.
    const std::string comment;

    explicit BIP54SigopsTestVector(CTransaction tx, std::vector<CTxOut> spent_txos, bool valid, std::string com):
        spending_tx{std::move(tx)}, spent_outputs{std::move(spent_txos)}, success{valid}, comment{std::move(com)} {}

    UniValue GetJson() const
    {
        UniValue json{UniValue::VOBJ}, spent_txos{UniValue::VARR};
        for (const auto& txo: spent_outputs) {
            DataStream ssTxo;
            ssTxo << txo;
            spent_txos.push_back(HexStr(ssTxo));
        }
        json.pushKV("spent_outputs", std::move(spent_txos));
        json.pushKV("spending_tx", EncodeHexTx(spending_tx));
        json.pushKV("success", success);
        json.pushKV("comment", comment);
        return json;
    }
};

/** Check this transaction does not exceed the BIP54 sigops limit, and record it as a test vector. */
static void CheckWithinBIP54Limits(CTransaction tx, const CCoinsViewCache& coins, std::vector<BIP54SigopsTestVector>& test_vectors, std::string comment)
{
    BOOST_CHECK_MESSAGE(Consensus::CheckSigopsBIP54(tx, coins), comment);

    auto spent_outputs{RecordSpent(coins, tx)};
    test_vectors.emplace_back(tx, std::move(spent_outputs), /*valid=*/true, std::move(comment));
}

/** Check this transaction exceeds the BIP54 sigops limit, and record it as a test vector. */
static void CheckExceedsBIP54Limits(CTransaction tx, const CCoinsViewCache& coins, std::vector<BIP54SigopsTestVector>& test_vectors, std::string comment)
{
    BOOST_CHECK_MESSAGE(!Consensus::CheckSigopsBIP54(tx, coins), comment);

    auto spent_outputs{RecordSpent(coins, tx)};
    test_vectors.emplace_back(tx, std::move(spent_outputs), /*valid=*/false, std::move(comment));
}

/**
 * Test the BIP54 per-transaction limit on legacy signature operations in inputs. We perform
 * extensive tests of the new limit from a few different perspective. These extensive tests will
 * also be used to generate test vectors to help validate the BIP's semantics and re-implementation
 * of this logic. There are broadly 3 categories to this test. First, we check the bounds of the
 * new limit under various semi-realistic conditions: valid transactions with different combinations
 * of inputs and outputs types. Then, we exercise the new limit under some historical block chain
 * transactions known to be BIP54-invalid. Finally, we exercise some specific details and edge
 * cases of the implementation.
 */
BOOST_AUTO_TEST_CASE(bip54_legacy_sigops)
{
    // All keys in this test are derived from this seed using BIP32.
    CExtKey xprv;
    static constexpr std::array<const std::byte, 5> seed{{std::byte{'B'}, std::byte{'I'}, std::byte{'P'}, std::byte{'5'}, std::byte{'4'}}};
    xprv.SetSeed(seed);

    // For all following test cases we will use a transaction with outputs of various types.
    CMutableTransaction tx;
    tx.vout.emplace_back(0, GetScriptForDestination(PubKeyDestination(GetKeyAt(xprv, 1).GetPubKey())));
    tx.vout.emplace_back(0, GetScriptForDestination(PKHash(GetKeyAt(xprv, 2).GetPubKey())));
    const auto ms_script{CScript{} << OP_2 << ToByteVector(GetKeyAt(xprv, 2).GetPubKey()) << ToByteVector(GetKeyAt(xprv, 3).GetPubKey())
                        << ToByteVector(GetKeyAt(xprv, 4).GetPubKey()) << OP_3 << OP_CHECKMULTISIG};
    tx.vout.emplace_back(0, ms_script);
    tx.vout.emplace_back(0, GetScriptForDestination(ScriptHash(ms_script)));
    tx.vout.emplace_back(0, GetScriptForDestination(WitnessV0KeyHash(GetKeyAt(xprv, 5).GetPubKey())));
    tx.vout.emplace_back(0, GetScriptForDestination(WitnessV0ScriptHash(ms_script)));
    tx.vout.emplace_back(0, GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey{GetKeyAt(xprv, 6).GetPubKey()})));
    tx.vout.emplace_back(0, GetScriptForDestination(PayToAnchor()));
    tx.vout.emplace_back(0, GetScriptForDestination(WitnessUnknown(8, {42, 42, 42})));

    // Record the test vectors.
    std::vector<BIP54SigopsTestVector> test_vectors;

    // Reach the 2'500 limit using only CHECKSIG's in a bare Script.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx_copy{tx};

        // Use the first derivation as the private key to use in spent coins.
        const CKey privkey{GetKeyAt(xprv, 0)};
        const auto pubkey{privkey.GetPubKey()};

        // Create a spent Script that accounts for exactly a hundred sigops.
        auto spent_script{CScript() << ToByteVector(pubkey)};
        for (int i{0}; i < 99; ++i) {
            spent_script << OP_2DUP << OP_CHECKSIGVERIFY;
        }
        spent_script << OP_CHECKSIG;

        // Reach 2500 sigops: one more sigop and we'll exceed the limit.
        for (int i{0}; i < 25; ++i) {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(i, spent_script);
            AddCoins(coins, CTransaction(tx_create), 0, false);
            tx_copy.vin.emplace_back(tx_create.GetHash(), 0);
        }

        // Sign each input. Make sure all transaction inputs are valid.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << SignInput(privkey, spent_script, tx_copy, i);
            Assert(VerifyTxin(spent_script, tx_copy, i));
        }

        // We don't exceed the limit yet.
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Bare Script inputs totalling 2500 CHECKSIGs");

        // Add one more input with a single CHECKSIG.
        auto spent_script2{CScript() << ToByteVector(pubkey) << OP_CHECKSIG};
        CMutableTransaction tx_create_last;
        const auto idx{tx_copy.vin.size()};
        const auto value{static_cast<CAmount>(idx)};
        tx_create_last.vout.emplace_back(value, spent_script2);
        AddCoins(coins, CTransaction(tx_create_last), 0, false);
        tx_copy.vin.emplace_back(tx_create_last.GetHash(), 0);

        // Sign it and make sure it's valid.
        tx_copy.vin.back().scriptSig = CScript{} << SignInput(privkey, spent_script2, tx_copy, idx);
        Assert(VerifyTxin(spent_script2, tx_copy, idx));

        // Now we bump into the limit.
        CheckExceedsBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Bare Script inputs totalling 2501 CHECKSIGs");

        // Now malleate a bunch of unrelated fields to demonstrate how changing those does not affect
        // the BIP54 sigops calculation.
        tx_copy.version = 42;
        tx_copy.nLockTime = 21;
        tx_copy.vout = {tx_copy.vout.begin() + 2, tx_copy.vout.end()};
        tx_copy.vout[0].nValue = 50;
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].nSequence = 84 * i;
        }

        // Resign inputs as we just invalidated the signatures.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            CScript& script{spent_script};
            if (i == tx_copy.vin.size() - 1) script = spent_script2;
            tx_copy.vin[i].scriptSig = CScript{} << SignInput(privkey, script, tx_copy, i);
            Assert(VerifyTxin(script, tx_copy, i));
        }

        // The number of accounted sigops hasn't changed. We still exceed the limit.
        CheckExceedsBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Bare Script inputs totalling 2501 CHECKSIGs and unrelated transaction fields malleated");

        // Drop the last input with the single CHECKSIG, and resign everything.
        tx_copy.vin.pop_back();
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig = CScript{} << SignInput(privkey, spent_script, tx_copy, i);
            Assert(VerifyTxin(spent_script, tx_copy, i));
        }

        // Now we don't exceed the limit anymore.
        BOOST_CHECK(Consensus::CheckSigopsBIP54(CTransaction(tx_copy), coins));
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Bare Script inputs totalling 2500 CHECKSIGs and unrelated transaction fields malleated");
    }

    // Reach the 2'500 limit using only CHECKSIG's in a P2SH redeemScript.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx_copy{tx};

        // Use the second derivation as the private key to use in spent coins.
        const CKey privkey{GetKeyAt(xprv, 1)};
        const auto pubkey{privkey.GetPubKey()};

        // Create a redeem Script that accounts for exactly a hundred sigops.
        auto redeem_script{CScript() << ToByteVector(pubkey)};
        for (int i{0}; i < 99; ++i) {
            redeem_script = redeem_script << OP_2DUP << OP_CHECKSIGVERIFY;
        }
        redeem_script << OP_CHECKSIG;
        const auto spk{GetScriptForDestination(ScriptHash(redeem_script))};

        // Reach 2500 sigops: one more sigop and we'll exceed the limit. Contrary
        // to the bare Script version, here we'll use a single creation tx.
        CMutableTransaction tx_create;
        for (int i{0}; i < 25; ++i) {
            tx_create.vout.emplace_back(i, spk);
        }
        const auto prev_txid{tx_create.GetHash()};
        for (int i{0}; i < 25; ++i) {
            tx_copy.vin.emplace_back(prev_txid, i);
        }
        AddCoins(coins, CTransaction(tx_create), 0, false);

        // Sign each input. Make sure all transaction inputs are valid.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << SignInput(privkey, redeem_script, tx_copy, i) << ToByteVector(redeem_script);
            Assert(VerifyTxin(spk, tx_copy, i));
        }

        // We don't exceed the limit yet.
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "P2SH inputs totalling 2500 CHECKSIGs");

        // Add one more input with a single CHECKSIG (a bare P2PK, to mix input types).
        auto spent_script{CScript() << ToByteVector(pubkey) << OP_CHECKSIG};
        CMutableTransaction tx_create_last;
        const auto idx{tx_copy.vin.size()};
        const auto value{static_cast<CAmount>(idx)};
        tx_create_last.vout.emplace_back(value, spent_script);
        AddCoins(coins, CTransaction(tx_create_last), 0, false);
        tx_copy.vin.emplace_back(tx_create_last.GetHash(), 0);

        // Sign it and make sure it's valid.
        tx_copy.vin.back().scriptSig << SignInput(privkey, spent_script, tx_copy, idx);
        Assert(VerifyTxin(spent_script, tx_copy, idx));

        // Now we bump into the limit.
        BOOST_CHECK(!Consensus::CheckSigopsBIP54(CTransaction(tx_copy), coins));
        CheckExceedsBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "P2SH inputs totalling 2500 CHECKSIGs + 1 P2PK input");
    }

    // Create a transaction spending 250 7-of-10 bare multisigs with 10 different public keys.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx_copy{tx};

        // Get 10 private keys to create the multisig.
        std::vector<CKey> privkeys;
        for (int i{0}; i < 10; ++i) {
            privkeys.push_back(GetKeyAt(xprv, 10 + i));
        }

        // A 7-of-10 multisig.
        auto spent_script{CScript() << OP_7};
        for (const auto& pk: privkeys) {
            spent_script << ToByteVector(pk.GetPubKey());
        }
        spent_script << OP_10 << OP_CHECKMULTISIG;

        // Spend 250 of those in a single transaction, reaching the 2500 sigops limit.
        for (int i{0}; i < 250; ++i) {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(i, spent_script);
            AddCoins(coins, CTransaction(tx_create), 0, false);
            tx_copy.vin.emplace_back(tx_create.GetHash(), 0);
        }

        // Sign each input. Make sure all transaction inputs are valid. Sign using ACP so we
        // don't invalidate the signatures when adding an input below.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << OP_0 << OP_0 << OP_0 << OP_0;
            for (const auto& pk: privkeys | std::views::take(7)) {
                tx_copy.vin[i].scriptSig << SignInput(pk, spent_script, tx_copy, i, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
            }
            Assert(VerifyTxin(spent_script, tx_copy, i));
        }

        // We don't exceed the limit yet.
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Bare Script inputs totalling 250 7-of-10 CHECKMULTISIGs");

        // Add a 1-of-1 CHECKMULTISIG input.
        auto single_spent_script{CScript{} << OP_1 << ToByteVector(privkeys.front().GetPubKey()) << OP_1 << OP_CHECKMULTISIG};
        CMutableTransaction tx_create_single;
        const auto idx{tx_copy.vin.size()};
        const auto value{static_cast<CAmount>(idx)};
        tx_create_single.vout.emplace_back(value, single_spent_script);
        AddCoins(coins, CTransaction(tx_create_single), 0, false);
        tx_copy.vin.emplace_back(tx_create_single.GetHash(), 0);

        // Sign the 1-of-1 CMS.
        tx_copy.vin.back().scriptSig << OP_0 << SignInput(privkeys.front(), single_spent_script, tx_copy, idx);
        Assert(VerifyTxin(single_spent_script, tx_copy, idx));

        // Now we do exceed the limit.
        CheckExceedsBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Bare Script inputs totalling 250 7-of-10 CHECKMULTISIGs + 1 1-of-1 CHECKMULTISIG");
    }

    // Create a transaction spending 125 16-of-17 bare multisigs. This demonstrates how
    // a pubkey count >16 will be accounted as 20 keys. This also repeats the same public
    // key and does not use ACP.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx_copy{tx};

        // Get a single private key to repeat in the multisig.
        const auto privkey{GetKeyAt(xprv, 20)};
        const auto pubkey{privkey.GetPubKey()};

        // A 16-of-17 multisig with the same key repeated 17 times.
        auto spent_script{CScript() << OP_16};
        for (int i{0}; i < 17; ++i) {
            spent_script << ToByteVector(pubkey);
        }
        spent_script << 17 << OP_CHECKMULTISIG;

        // Spend 125 of those in a single transaction, reaching the 2500 sigops limit.
        for (int i{0}; i < 125; ++i) {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(i, spent_script);
            AddCoins(coins, CTransaction(tx_create), 0, false);
            tx_copy.vin.emplace_back(tx_create.GetHash(), 0);
        }

        // Sign each input. Make sure all transaction inputs are valid.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << OP_0 << OP_0;
            const auto sig{SignInput(privkey, spent_script, tx_copy, i)};
            for (int j{0}; j < 16; ++j) {
                tx_copy.vin[i].scriptSig << sig;
            }
            Assert(VerifyTxin(spent_script, tx_copy, i));
        }

        // We don't exceed the limit yet.
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "P2SH inputs totalling 125 16-of-17 CHECKMULTISIGs");

        // Add one more input with a single sigop (a P2PKH to mix input types).
        auto spk{GetScriptForDestination(PKHash(pubkey))};
        CMutableTransaction tx_create_last;
        const auto idx{tx_copy.vin.size()};
        const auto value{static_cast<CAmount>(idx)};
        tx_create_last.vout.emplace_back(value, spk);
        AddCoins(coins, CTransaction(tx_create_last), 0, false);
        tx_copy.vin.emplace_back(tx_create_last.GetHash(), 0);

        // Sign it and make sure it's valid.
        tx_copy.vin.back().scriptSig << SignInput(privkey, spk, tx_copy, idx) << ToByteVector(pubkey);
        Assert(VerifyTxin(spk, tx_copy, idx));

        // Resign all previous inputs which were invalidated by adding a new input.
        for (size_t i{0}; i < idx; ++i) {
            tx_copy.vin[i].scriptSig << OP_0 << OP_0;
            const auto sig{SignInput(privkey, spent_script, tx_copy, i)};
            for (int j{0}; j < 16; ++j) {
                tx_copy.vin[i].scriptSig << sig;
            }
            Assert(VerifyTxin(spent_script, tx_copy, i));
        }

        // Now we bump into the limit.
        BOOST_CHECK(!Consensus::CheckSigopsBIP54(CTransaction(tx_copy), coins));
        CheckExceedsBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "P2SH inputs totalling 125 16-of-17 CHECKMULTISIGs + 1 P2PKH input");
    }

    // Exceed the 2'500 limit using 18-of-18's CHECKMULTISIGs in an intentionally contrived P2SH redeemScript.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx_copy{tx};

        // Use a single private key, we'll copy the key to create the multisigs.
        const CKey privkey{GetKeyAt(xprv, 30)};
        const auto pubkey{privkey.GetPubKey()};

        // Create a redeem script performing two 18-of-18 CHECKMULTISIG's.
        auto redeem_script{CScript() << ToByteVector(pubkey)};
        // From a stack `<sig> <pk>`, create `<sig> <pk> <> {<sig>}*18 <pk>`
        redeem_script << OP_DUP << OP_TOALTSTACK << OP_OVER << OP_0 << OP_SWAP << OP_DUP << OP_2DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_FROMALTSTACK;
        // From a stack `<sig> <pk> <> {<sig>}*18 <pk>`, create `<sig> <pk> <> {<sig>}*18 <18> {<pk>}*18 <18> CMSVERIFY`
        redeem_script << 18 << OP_SWAP << OP_DUP << OP_2DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP << 18 << OP_CHECKMULTISIGVERIFY;
        // From a stack `<sig> <pk>`, create `<> {<sig>}*18 <pk>`
        redeem_script << OP_0 << OP_ROT << OP_ROT << OP_TOALTSTACK << OP_DUP << OP_2DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_FROMALTSTACK;
        // From a stack `<> {<sig>}*18 <pk>`, create `<> {<sig>}*18 <18> {<pk>}*18 <18> CHECKMULTISIG`
        redeem_script << 18 << OP_SWAP << OP_DUP << OP_2DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP << 18 << OP_CHECKMULTISIG;
        const auto spk{GetScriptForDestination(ScriptHash(redeem_script))};

        // Reach 2400 sigops with 62 inputs.
        CMutableTransaction tx_create;
        for (int i{0}; i < 62; ++i) {
            tx_create.vout.emplace_back(i, spk);
        }
        const auto prev_txid{tx_create.GetHash()};
        for (int i{0}; i < 62; ++i) {
            tx_copy.vin.emplace_back(prev_txid, i);
        }
        AddCoins(coins, CTransaction(tx_create), 0, false);

        // Sign each input. Make sure all transaction inputs are valid.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << SignInput(privkey, redeem_script, tx_copy, i) << ToByteVector(redeem_script);
            Assert(VerifyTxin(spk, tx_copy, i));
        }

        // We don't exceed the limit yet.
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "62 inputs with a contrived P2SH redeemScript executing 2 18-of-18 CHECKMULTISIGs");

        // Add one more input with the same spent script.
        const auto idx{tx_copy.vin.size()};
        const auto value{static_cast<CAmount>(idx)};
        tx_create.vout.emplace_back(value, spk);
        AddCoins(coins, CTransaction(tx_create), 0, false);
        tx_copy.vin.emplace_back(tx_create.GetHash(), idx);

        // Re-sign each input.
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << SignInput(privkey, redeem_script, tx_copy, i) << ToByteVector(redeem_script);
            Assert(VerifyTxin(spk, tx_copy, i));
        }

        // We now reached 2600 sigops. We exceed the limit.
        CheckExceedsBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "62 inputs with a contrived P2SH redeemScript executing 2 18-of-18 CHECKMULTISIGs");
    }

    // Now reach exactly 2500 sigops with a transaction mixing CMS-only input, CHECKSIG-only input, an input with
    // a mix of both, and 3 more of the same but under P2SH. Then we'll check we do exceed the limit by adding one
    // more legacy sigop, but not by adding non-legacy sigops for various existing non-legacy input types. This
    // test also demonstrates how sigops in unexecuted branches still account toward the limit.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx_copy{tx};

        // A script with 100 CHECKSIG's which takes a single sig as input.
        const auto cs_only_privkey{GetKeyAt(xprv, 40)};
        const auto cs_only_pubkey{cs_only_privkey.GetPubKey()};
        auto cs_only_script{CScript{} << ToByteVector(cs_only_pubkey)};
        for (int i{0}; i < 99; ++i) {
            cs_only_script << OP_2DUP << OP_CHECKSIGVERIFY;
        }
        cs_only_script << OP_CHECKSIG;

        // A script with 9 1-of-20 CHECKMULTISIG's which takes 9 sigs as input.
        CScript cms_only_barescript;
        for (int i{0}; i < 9; ++i) {
            const auto privkey{GetKeyAt(xprv, 41 + i)};
            const auto pubkey{privkey.GetPubKey()};
            cms_only_barescript << OP_0 << OP_SWAP << OP_1;
            for (int j{0}; j < 20; ++j) cms_only_barescript << ToByteVector(pubkey);
            if (i < 9 - 1) {
                cms_only_barescript << 20 << OP_CHECKMULTISIGVERIFY;
            } else {
                cms_only_barescript << 20 << OP_CHECKMULTISIG;
            }
        }

        // A script with 50 CHECKSIG's and 5 19-of-19 CHECKMULTISIG's which takes as input
        // one signature for all CHECKSIG's and then the inputs to the 5 CMS.
        const auto mixed_bare_privkey{GetKeyAt(xprv, 50)};
        const auto mixed_bare_pubkey{mixed_bare_privkey.GetPubKey()};
        auto mixed_barescript{CScript{} << ToByteVector(mixed_bare_pubkey)};
        for (int i{0}; i < 49; ++i) {
            mixed_barescript << OP_2DUP << OP_CHECKSIGVERIFY;
        }
        mixed_barescript << OP_CHECKSIGVERIFY;
        for (int i{0}; i < 5; ++i) {
            mixed_barescript << 19;
            for (int j{0}; j < 19; ++j) mixed_barescript << ToByteVector(mixed_bare_pubkey);
            mixed_barescript << 19;
            if (i < 5 - 1) {
                mixed_barescript << OP_CHECKMULTISIGVERIFY;
            } else {
                mixed_barescript << OP_CHECKMULTISIG;
            }
        }

        // A P2SH with 100 CHECKSIG's.
        const auto cs_only_p2sh{GetScriptForDestination(ScriptHash(cs_only_script))};

        // A P2SH with 8 16-of-16 CHECKMULTISIG's. Takes the inputs to all 8 CMS.
        CScript cms_only_redeem_script;
        for (int i{0}; i < 8; ++i) {
            const auto privkey{GetKeyAt(xprv, 51 + i)};
            const auto pubkey{privkey.GetPubKey()};
            cms_only_redeem_script << OP_16 << ToByteVector(pubkey) << OP_DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_16;
            if (i < 8 - 1) {
                cms_only_redeem_script << OP_CHECKMULTISIGVERIFY;
            } else {
                cms_only_redeem_script << OP_CHECKMULTISIG;
            }
        }
        const auto cms_only_p2sh{GetScriptForDestination(ScriptHash(cms_only_redeem_script))};

        // A P2SH with 9 13-of-13 CMS followed by 9 CHECKSIGs. The 9 CHECKMULTISIG's are in
        // a non-executed Script branch. Takes as input a single signature for the CHECKSIG's.
        const auto mixed_p2sh_privkey{GetKeyAt(xprv, 50)};
        const auto mixed_p2sh_pubkey{mixed_p2sh_privkey.GetPubKey()};
        auto mixed_redeem_script{CScript{} << OP_0 << OP_IF};
        for (int i{0}; i < 9; ++i) {
            mixed_redeem_script << OP_13 << ToByteVector(mixed_p2sh_pubkey) << OP_DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_13 << OP_CHECKMULTISIGVERIFY;
        }
        mixed_redeem_script << OP_ENDIF << ToByteVector(mixed_p2sh_pubkey);
        for (int i{0}; i < 4; ++i) {
            mixed_redeem_script << OP_2DUP << OP_CHECKSIGVERIFY;
        }
        mixed_redeem_script << OP_CHECKSIG;
        const auto mixed_p2sh{GetScriptForDestination(ScriptHash(mixed_redeem_script))};

        // Now create the spending transaction. To start it will spend 2 inputs with a
        // bare script filled with CHECKSIG's. That's 200 sigops accounted for.
        for (int i{0}; i < 2; ++i) {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(i, cs_only_script);
            AddCoins(coins, CTransaction(tx_create), 0, false);
            tx_copy.vin.emplace_back(tx_create.GetHash(), 0);
        }

        // Sign those two first inputs. (With ACP so we can add more inputs.)
        for (size_t i{0}; i < tx_copy.vin.size(); ++i) {
            tx_copy.vin[i].scriptSig << SignInput(cs_only_privkey, cs_only_script, tx_copy, i, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
            Assert(VerifyTxin(cs_only_script, tx_copy, i));
        }

        // Then it will spend 10 inputs with bare multisigs, bringing it to 2000 sigops
        // accounted for in total.
        {
            CMutableTransaction tx_create;
            for (int i{0}; i < 10; ++i) {
                tx_create.vout.emplace_back(i, cms_only_barescript);
            }
            const auto prev_txid{tx_create.GetHash()};
            for (int i{0}; i < 10; ++i) {
                tx_copy.vin.emplace_back(prev_txid, i);
            }
            AddCoins(coins, CTransaction(tx_create), 0, false);
        }

        // Sign those ten additional inputs. (With ACP so we can add more inputs.)
        for (size_t i{2}; i < tx_copy.vin.size(); ++i) {
            for (size_t j{0}; j < 9; ++j) {
                // We used indexes from 41 through 49 for the 9 CMS.
                const auto privkey{GetKeyAt(xprv, 49 - j)};
                const auto sig{SignInput(privkey, cms_only_barescript, tx_copy, i, SIGHASH_ALL | SIGHASH_ANYONECANPAY)};
                tx_copy.vin[i].scriptSig << sig;
            }
            Assert(VerifyTxin(cms_only_barescript, tx_copy, i));
        }

        // And it will spend one input for a bare Script with mixed CMS and CHECKSIGs. That's
        // now 2150 sigops accounted in total.
        {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(422421, mixed_barescript);
            const auto prev_txid{tx_create.GetHash()};
            tx_copy.vin.emplace_back(prev_txid, 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);
        }

        // Sign this input (still ACP). Use ops in the scriptSig for a change.
        {
            const auto idx{tx_copy.vin.size() - 1};
            const auto sig{SignInput(mixed_bare_privkey, mixed_barescript, tx_copy, idx, SIGHASH_ALL | SIGHASH_ANYONECANPAY)};
            for (size_t i{0}; i < 5; ++i) {
                tx_copy.vin[idx].scriptSig << OP_0 << sig << OP_DUP << OP_2DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP << OP_3DUP;
            }
            tx_copy.vin[idx].scriptSig << sig; // For the CHECKSIG's
            Assert(VerifyTxin(mixed_barescript, tx_copy, idx));
        }

        // It will spend a single p2sh input with only CHECKSIGs, getting to 2250 sigops.
        {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(181827, cs_only_p2sh);
            const auto prev_txid{tx_create.GetHash()};
            tx_copy.vin.emplace_back(prev_txid, 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);
        }

        // Sign this input (still ACP).
        {
            const auto idx{tx_copy.vin.size() - 1};
            const auto sig{SignInput(cs_only_privkey, cs_only_script, tx_copy, idx, SIGHASH_ALL | SIGHASH_ANYONECANPAY)};
            tx_copy.vin[idx].scriptSig << sig << ToByteVector(cs_only_script);
            Assert(VerifyTxin(cs_only_p2sh, tx_copy, idx));
        }

        // It will spend a single p2sh input only CMS's, getting to 2378 sigops.
        {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(999, cms_only_p2sh);
            const auto prev_txid{tx_create.GetHash()};
            tx_copy.vin.emplace_back(prev_txid, 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);
        }

        // Sign the P2SH multisigs, still with ACP.
        {
            const auto idx{tx_copy.vin.size() - 1};
            for (int i{0}; i < 8; ++i) {
                // Traverse the derivation indexes used to create them (51 through 58) in reverse order.
                const auto privkey{GetKeyAt(xprv, 58 - i)};
                const auto sig{SignInput(privkey, cms_only_redeem_script, tx_copy, idx, SIGHASH_ALL | SIGHASH_ANYONECANPAY)};
                tx_copy.vin[idx].scriptSig << OP_0;
                for (int j{0}; j < 16; ++j) {
                    tx_copy.vin[idx].scriptSig << sig;
                }
            }
            tx_copy.vin[idx].scriptSig << ToByteVector(cms_only_redeem_script);
            Assert(VerifyTxin(cms_only_p2sh, tx_copy, idx));
        }

        // It will finally spend a single p2sh input with mixed CS - CMS, getting
        // to 2500 sigops.
        {
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(776, mixed_p2sh);
            const auto prev_txid{tx_create.GetHash()};
            tx_copy.vin.emplace_back(prev_txid, 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);
        }

        // Sign this final input. It only needs one signature for the CHECKSIG's because
        // the CMS are not executed.
        {
            const auto idx{tx_copy.vin.size() - 1};
            const auto sig{SignInput(mixed_p2sh_privkey, mixed_redeem_script, tx_copy, idx, SIGHASH_ALL | SIGHASH_ANYONECANPAY)};
            tx_copy.vin[idx].scriptSig << sig << ToByteVector(mixed_redeem_script);
            Assert(VerifyTxin(mixed_p2sh, tx_copy, idx));
        }

        // We reached exactly 2500 sigops, we don't exceed the limit.
        CheckWithinBIP54Limits(CTransaction(tx_copy), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops");

        // Now we are going to add an input and make sure we exceed the limit or not as
        // expected. This is the index of this input.
        const auto idx{tx_copy.vin.size()};

        // Adding a P2PK input will make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 60)};
            const auto pubkey{privkey.GetPubKey()};
            const auto spent_script{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10101, spent_script);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto sig{SignInput(privkey, spent_script, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << sig;
            Assert(VerifyTxin(spent_script, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2PK input");
        }

        // Adding a P2PKH input will make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 60)};
            const auto pubkey{privkey.GetPubKey()};
            const auto spk{GetScriptForDestination(PKHash(pubkey))};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10101, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto sig{SignInput(privkey, spk, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << sig << ToByteVector(pubkey);
            Assert(VerifyTxin(spk, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2PKH input");
        }

        // Adding a 1-of-1 bare multisig input will make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 61)};
            const auto pubkey{privkey.GetPubKey()};
            const auto spent_script{CScript{} << OP_1 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10102, spent_script);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto sig{SignInput(privkey, spent_script, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << OP_0 << sig;
            Assert(VerifyTxin(spent_script, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a bare 1-of-1 multisig input");
        }

        // Adding an input spending an empty Script but having a sigop in the scriptSig
        // will make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 62)};
            const auto pubkey{privkey.GetPubKey()};
            const CScript spent_script;

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10103, spent_script);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto signed_script{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};
            const auto sig{SignInput(privkey, signed_script, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << sig << ToByteVector(pubkey) << OP_CHECKSIG;
            Assert(VerifyTxin(spent_script, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + an input with a CHECKSIG in the scriptSig");
        }

        // Adding an input spending a single CHECKSIG in a p2sh will make us exceed the
        // limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 63)};
            const auto pubkey{privkey.GetPubKey()};
            const auto redeem_script{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};
            const auto spk{GetScriptForDestination(ScriptHash(redeem_script))};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10104, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto sig{SignInput(privkey, redeem_script, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << sig << ToByteVector(redeem_script);
            Assert(VerifyTxin(spk, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2SH input with a single CHECKSIG");
        }

        // Adding an input spending a 1of1 multisig in a p2sh will make us exceed the
        // limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 64)};
            const auto pubkey{privkey.GetPubKey()};
            const auto redeem_script{CScript{} << OP_1 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG};
            const auto spk{GetScriptForDestination(ScriptHash(redeem_script))};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10105, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto sig{SignInput(privkey, redeem_script, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << OP_0 << sig << ToByteVector(redeem_script);
            Assert(VerifyTxin(spk, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2SH input with 1-of-1 CHECMULTISIG");
        }

        // Adding an input spending an invalid Script but containing a CHECKSIG will
        // make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            const auto spent_script{CScript{} << OP_0 << OP_CHECKSIG};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10106, spent_script);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + an input spending an invalid bare Script containing a CHECKSIG");
        }

        // Adding an input spending an invalid p2sh but containing a CHECKMULTISIG
        // will make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto redeem_script{CScript{} << OP_RETURN << OP_CHECKMULTISIG};
            const auto spk{GetScriptForDestination(ScriptHash(redeem_script))};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10107, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);
            tx_copy2.vin[idx].scriptSig << ToByteVector(redeem_script);

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + an input spending an invalid p2sh containing a CHECKMULTISIG");
        }

        // Adding an input spending a P2WPKH will not exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            FillableSigningProvider keystore;
            SignatureData dummy_sigdata;

            const auto privkey{GetKeyAt(xprv, 65)};
            const auto pubkey{privkey.GetPubKey()};
            const auto keyhash{WitnessV0KeyHash(pubkey)};
            const auto spk{GetScriptForDestination(keyhash)};
            Assert(keystore.AddKeyPubKey(privkey, pubkey));

            const CAmount value{10108};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            Assert(SignSignature(keystore, spk, tx_copy2, idx, value, SIGHASH_ALL, dummy_sigdata));
            Assert(VerifyTxin(spk, tx_copy2, idx, value));

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2WPKH input");
        }

        // Adding an input spending a P2WSH will not exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            FillableSigningProvider keystore;
            SignatureData dummy_sigdata;

            const auto privkey{GetKeyAt(xprv, 66)};
            const auto pubkey{privkey.GetPubKey()};
            const auto witscript{CScript{} << OP_1 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG};
            const auto witprogram{WitnessV0ScriptHash(witscript)};
            const auto spk{GetScriptForDestination(witprogram)};
            Assert(keystore.AddKeyPubKey(privkey, pubkey));
            Assert(keystore.AddCScript(witscript));

            const CAmount value{10109};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            Assert(SignSignature(keystore, spk, tx_copy2, idx, value, SIGHASH_ALL, dummy_sigdata));
            Assert(VerifyTxin(spk, tx_copy2, idx, value));

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2WSH input");
        }

        // Adding an input spending a P2SH-P2WPKH will not exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            FillableSigningProvider keystore;
            SignatureData dummy_sigdata;

            const auto privkey{GetKeyAt(xprv, 67)};
            const auto pubkey{privkey.GetPubKey()};
            const auto keyhash{WitnessV0KeyHash(pubkey)};
            const auto witprogram{GetScriptForDestination(keyhash)};
            const auto spk{GetScriptForDestination(ScriptHash(witprogram))};
            Assert(keystore.AddKeyPubKey(privkey, pubkey));
            Assert(keystore.AddCScript(witprogram));

            const CAmount value{10110};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            Assert(SignSignature(keystore, spk, tx_copy2, idx, value, SIGHASH_ALL, dummy_sigdata));
            Assert(VerifyTxin(spk, tx_copy2, idx, value));

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2SH-P2WPKH input");
        }

        // Adding an input spending a P2SH-P2WSH will not exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            FillableSigningProvider keystore;
            SignatureData dummy_sigdata;

            const auto privkey{GetKeyAt(xprv, 68)};
            const auto pubkey{privkey.GetPubKey()};
            const auto witscript{CScript{} << ToByteVector(pubkey) << OP_CHECKSIG};
            const auto witprogram{GetScriptForDestination(WitnessV0ScriptHash(witscript))};
            const auto spk{GetScriptForDestination(ScriptHash(witprogram))};
            Assert(keystore.AddKeyPubKey(privkey, pubkey));
            Assert(keystore.AddCScript(witscript));
            Assert(keystore.AddCScript(witprogram));

            const CAmount value{10111};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            Assert(SignSignature(keystore, spk, tx_copy2, idx, value, SIGHASH_ALL, dummy_sigdata));
            Assert(VerifyTxin(spk, tx_copy2, idx, value));

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a P2SH-P2WSH input");
        }

        // Adding an input spending a Taproot through the key path will not exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            FlatSigningProvider keystore;
            SignatureData sigdata;

            const auto privkey{GetKeyAt(xprv, 69)};
            const auto pubkey{privkey.GetPubKey()};
            TaprootBuilder builder;
            builder.Finalize(XOnlyPubKey{pubkey});
            const auto spk{GetScriptForDestination(builder.GetOutput())};
            keystore.keys[pubkey.GetID()] = privkey;

            const CAmount value{10112};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            sigdata.tr_spenddata = builder.GetSpendData();
            auto spent_outputs{RecordSpent(coins, tx_copy2)};
            Assert(SignSignature(keystore, spk, tx_copy2, idx, value, std::vector<CTxOut>(spent_outputs), SIGHASH_ALL, sigdata));
            Assert(VerifyTxin(spk, tx_copy2, idx, std::move(spent_outputs), value));

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a Taproot key path spend input");
        }

        // Adding an input spending a Taproot through the key path will not exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};
            FlatSigningProvider keystore;
            SignatureData sigdata;

            const auto privkey{GetKeyAt(xprv, 70)};
            const auto pubkey{privkey.GetPubKey()};
            TaprootBuilder builder;
            const auto leaf_script{CScript{} << ToByteVector(XOnlyPubKey{pubkey}) << OP_CHECKSIG};
            builder.Add(0, ToByteVector(leaf_script), TAPROOT_LEAF_TAPSCRIPT);
            builder.Finalize(XOnlyPubKey::NUMS_H);
            const auto spk{GetScriptForDestination(builder.GetOutput())};
            keystore.keys[pubkey.GetID()] = privkey;

            const CAmount value{10113};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            AddCoins(coins, CTransaction(tx_create), 0, false);

            sigdata.tr_spenddata = builder.GetSpendData();
            auto spent_outputs{RecordSpent(coins, tx_copy2)};
            Assert(SignSignature(keystore, spk, tx_copy2, idx, value, std::vector<CTxOut>(spent_outputs), SIGHASH_ALL, sigdata));
            Assert(VerifyTxin(spk, tx_copy2, idx, std::move(spent_outputs), value));

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a Taproot script path spend input");
        }

        // Adding an input spending a future witness program does not somehow make us exceed
        // the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 71)};
            const auto pubkey{privkey.GetPubKey()};
            const auto spk{GetScriptForDestination(WitnessUnknown(4, ToByteVector(pubkey)))};

            const CAmount value{10114};
            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(value, spk);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            tx_copy2.vin.back().scriptWitness.stack.push_back({0x42, 0x42});
            const auto sig{ParseHex("5da6d1157e4f2c45fa8441152f01e3e96898fd0c39326a47327d3bd024c4f6a2083e954ac803f8cb539aba8e31cdd9554a92309f47d489aa6a431ab262efa15a")};
            tx_copy2.vin.back().scriptWitness.stack.push_back(std::move(sig));
            tx_copy2.vin.back().scriptWitness.stack.push_back(ToByteVector(pubkey));
            AddCoins(coins, CTransaction(tx_create), 0, false);

            CheckWithinBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + a future Segwit program input");
        }

        // Adding an input spending a bare Script with no sigop but with a sigop in the
        // scriptSig will make us exceed the limit.
        {
            CMutableTransaction tx_copy2{tx_copy};

            const auto privkey{GetKeyAt(xprv, 72)};
            const auto pubkey{privkey.GetPubKey()};
            const auto spent_script{CScript{} << OP_2 << OP_2 << OP_ADD << OP_4 << OP_EQUAL};

            CMutableTransaction tx_create;
            tx_create.vout.emplace_back(10101, spent_script);
            tx_copy2.vin.emplace_back(tx_create.GetHash(), 0);
            tx_copy2.vin.back().scriptSig << OP_0 << ToByteVector(pubkey) << OP_CHECKSIG << OP_DROP;
            AddCoins(coins, CTransaction(tx_create), 0, false);

            const auto sig{SignInput(privkey, spent_script, tx_copy2, idx)};
            tx_copy2.vin[idx].scriptSig << sig;
            Assert(VerifyTxin(spent_script, tx_copy2, idx));

            CheckExceedsBIP54Limits(CTransaction(tx_copy2), coins, test_vectors, "Mixed input types reaching exactly 2500 BIP54-sigops + an input with one CHECKSIG in the scriptSig");
        }
    }

    // Some historical transactions which would have exceeded the BIP54 sigops limit. For
    // a full list of such transactions, see this mailing list post:
    // https://gnusha.org/pi/bitcoindev/49dyqqkf5NqGlGdinp6SELIoxzE_ONh3UIj6-EB8S804Id5yROq-b1uGK8DUru66eIlWuhb5R3nhRRutwuYjemiuOOBS2FQ4KWDnEh0wLuA=@protonmail.com/
    struct HistoricalTx {
        const std::vector<CTxOut> spent_outputs;
        const CTransaction tx;
    };
    std::vector<HistoricalTx> historical_txs;

    // This is bea1c2b87fee95a203c5b5d9f3e5d0f472385c34cb5af02d0560aab973169683.
    {
        DataStream stream(ParseHex("0100000001cce43bcf04bec97d9389e2e92705723a6f5869770dde262312fbcccdaba35c9702000000fd2703510000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004cc9afafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafffffffff01905f0100000000001976a9140af76822b5d13fd23b7b9380184c66e9a543368388ac00000000"));
        const std::vector<CTxOut> spent_outputs = {
            CTxOut{100000, CScript{} << OP_HASH160 << ParseHex("923fdf3ff05b994004e374c69c8a2196c9e79344") << OP_EQUAL},
        };
        historical_txs.push_back({
            .spent_outputs = std::move(spent_outputs),
            .tx = CTransaction{deserialize, TX_WITH_WITNESS, stream},
        });
    }

    // This is 62fc8d091a7c597783981f00b889d72d24ad5e3e224dbe1c2a317aabef89217e.
    {
        DataStream stream(ParseHex("0100000002321438a932139c6642dfd5c14f231aed8988e3519e116ed96600db86a3511c3001000000cd51004cc963afafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafaf68ffffffff321438a932139c6642dfd5c14f231aed8988e3519e116ed96600db86a3511c3002000000cd51004cc963afafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafaf68ffffffff01905f0100000000001976a9140af770d29305bc0cfee379cac4d3f932dfb343de88ac00000000"));
        const std::vector<CTxOut> spent_outputs = {
            CTxOut{50000, CScript{} << OP_HASH160 << ParseHex("a9395da5c22d266bb90ea2cc695a92ffd68c5597") << OP_EQUAL},
            CTxOut{50000, CScript{} << OP_HASH160 << ParseHex("a9395da5c22d266bb90ea2cc695a92ffd68c5597") << OP_EQUAL},
        };
        historical_txs.push_back({
            .spent_outputs = std::move(spent_outputs),
            .tx = CTransaction{deserialize, TX_WITH_WITNESS, stream},
        });
    }

    for (const auto& tx: historical_txs) {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);

        for (size_t i{0}; i < tx.tx.vin.size(); ++i) {
            const auto& spent_txo{tx.spent_outputs[i]};
            CMutableTransaction mtx{tx.tx};
            Assert(VerifyTxin(spent_txo.scriptPubKey, mtx, i));
            coins.AddCoin(tx.tx.vin[i].prevout, Coin(spent_txo, 0, false), false);
        }

        std::string comment{"Historical Bitcoin transaction "};
        CheckExceedsBIP54Limits(CTransaction(tx.tx), coins, test_vectors, std::move(comment) + tx.tx.GetHash().ToString());
    }

    // Now we move on to test some pathological transactions to demonstrates edge cases of the
    // sigop accounting functions. Those transactions would already be invalid anyways, but
    // this is useful to generate explicit test vectors.

    // CheckSigopsBIP54() does not validate Script. It will count also for (some) invalid Scripts.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx2;

        // Create an unspendable bare Script which exceeds 2500 sigops.
        CScript spk;
        for (unsigned i{0}; i < MAX_TX_LEGACY_SIGOPS + 1; ++i) {
            spk << OP_CHECKSIGVERIFY;
        }

        CMutableTransaction tx_create;
        tx_create.vout.emplace_back(0, spk);
        AddCoins(coins, CTransaction(tx_create), 0, false);
        tx2.vin.emplace_back(tx_create.GetHash(), 0);

        // CheckSigopsBIP54 will return false despite the Script being invalid.
        CheckExceedsBIP54Limits(CTransaction(tx2), coins, test_vectors, "Invalid bare script with 2501 CHECKSIGs");
    }

    // CheckSigopsBIP54 uses GetSigOpCount, which will only count the number of sigops in
    // CHECKMULTISIG operations accurately if the CMS / CMSVERIFY opcode is directly preceded
    // by OP_1-OP_16 and will always count it for 20 sigops otherwise. The previous tests have
    // exercised OP_0 and various counts >16. This exercises having another opcode as the count.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx2;

        // The first CMS will have OP_INVALIDOPCODE as its "last op", and count for 20. All the
        // following 124 CMS will have the previous CMS as their "last op", and will similarly
        // count for 20.
        CScript spk;
        for (unsigned i{0}; i < MAX_TX_LEGACY_SIGOPS / 20 + 1; ++i) {
            spk << OP_CHECKMULTISIG;
        }

        CMutableTransaction tx_create;
        tx_create.vout.emplace_back(0, spk);
        AddCoins(coins, CTransaction(tx_create), 0, false);
        tx2.vin.emplace_back(tx_create.GetHash(), 0);

        // CheckSigopsBIP54 will return false because there is 125 CMS that account for 20 each.
        CheckExceedsBIP54Limits(CTransaction(tx2), coins, test_vectors, "Invalid bare script with 125 CHECMULTISIGs each accounted for 20 BIP54-sigops");
    }

    // Note this is also a limitation for legitimate Scripts, for instance if the arguments to
    // CMS are decided dynamically.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx2;

        const auto privkey{GetKeyAt(xprv, 100)};
        const auto pubkey{privkey.GetPubKey()};

        // Start with a dummy multisig which can be either a 1of1 or a 1of2. Then pad the Script
        // with 2481 dummy CHECKSIG's.
        auto spk{CScript{} << OP_IF << OP_1 << ToByteVector(pubkey) << OP_1 << OP_ELSE};
        spk << OP_1 << ToByteVector(pubkey) << ToByteVector(pubkey) << OP_2 << OP_ENDIF << OP_CHECKMULTISIG;
        for (unsigned i{0}; i < MAX_TX_LEGACY_SIGOPS - 20 + 1; ++i) {
            spk << OP_CHECKSIG;
        }

        CMutableTransaction tx_create;
        tx_create.vout.emplace_back(0, spk);
        AddCoins(coins, CTransaction(tx_create), 0, false);
        tx2.vin.emplace_back(tx_create.GetHash(), 0);

        // CheckSigopsBIP54 will return false because the first CHECKMULTISIG counts for 20 sigops.
        CheckExceedsBIP54Limits(CTransaction(tx2), coins, test_vectors, "Invalid bare script with 1 CHECKMULTISIG accounted for 20 sigops + 2481 CHECKSIGs");
    }

    // In case of parsing error, CheckSigopsBIP54 will count sigops up to the point with incorrect encoding.
    // Here we have 2501 sigops and an invalid PUSHDATA1. This will fail the check.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx2;

        CScript spk;
        for (unsigned i{0}; i < MAX_TX_LEGACY_SIGOPS + 1; ++i) {
            spk << OP_CHECKSIG;
        }
        spk.push_back(static_cast<uint8_t>(OP_PUSHDATA1));
        spk.push_back(0x01);

        CMutableTransaction tx_create;
        tx_create.vout.emplace_back(0, spk);
        AddCoins(coins, CTransaction(tx_create), 0, false);
        tx2.vin.emplace_back(tx_create.GetHash(), 0);

        // CheckSigopsBIP54 will return false because 2501 sigops were counted before encountering the error.
        CheckExceedsBIP54Limits(CTransaction(tx2), coins, test_vectors, "Bare Script with malformed PUSHDATA1 after counting 2501 BIP54-sigops");
    }

    // Now we have 2500 CHECKSIGs before the PUSHDATA2 parsing error, and one after. This will pass the check.
    {
        CCoinsView coins_dummy;
        CCoinsViewCache coins(&coins_dummy);
        CMutableTransaction tx2;

        CScript spk;
        for (unsigned i{0}; i < MAX_TX_LEGACY_SIGOPS; ++i) {
            spk << OP_CHECKSIG;
        }
        spk.push_back(static_cast<uint8_t>(OP_PUSHDATA2));
        spk.push_back(0x42);
        spk.push_back(0x42);
        spk << OP_CHECKSIG;

        CMutableTransaction tx_create;
        tx_create.vout.emplace_back(0, spk);
        AddCoins(coins, CTransaction(tx_create), 0, false);
        tx2.vin.emplace_back(tx_create.GetHash(), 0);

        // CheckSigopsBIP54 will return true because 2500 sigops were counted before encountering the error.
        CheckWithinBIP54Limits(CTransaction(tx2), coins, test_vectors, "Bare Script with malformed PUSHDATA2 after counting 2500 BIP54-sigops");
    }

    // Optionally dump test vectors as JSON. Uncomment UPDATE_JSON_TESTS at the top of this file to use.
#ifdef UPDATE_JSON_TESTS
    UniValue json_vectors{UniValue::VARR};
    for (const auto& test_vector: test_vectors) {
        json_vectors.push_back(test_vector.GetJson());
    }
    const auto json_str{json_vectors.write(4)};
    FILE* file = fsbridge::fopen("bip54_sigops.json.gen", "w");
    fputs(json_str.c_str(), file);
    fclose(file);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
