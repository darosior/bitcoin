// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <hash.h>
#include <key.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/strencodings.h>


//! Some pre-computed data to simulate challenges.
struct TestData {
    typedef CPubKey Key;

    // Precomputed public keys, and a dummy signature for each of them.
    std::vector<Key> dummy_keys;
    std::map<CKeyID, Key> dummy_keys_map;
    std::map<Key, std::vector<unsigned char>> dummy_sigs;

    // Precomputed hashes of each kind.
    std::vector<std::vector<unsigned char>> sha256;
    std::vector<std::vector<unsigned char>> ripemd160;
    std::vector<std::vector<unsigned char>> hash256;
    std::vector<std::vector<unsigned char>> hash160;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> sha256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> ripemd160_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash160_preimages;

    //! Set the precomputed data.
    void Init() {
        unsigned char keydata[32] = {1};
        for (size_t i = 0; i < 256; i++) {
            keydata[31] = i;
            CKey privkey;
            privkey.Set(keydata, keydata + 32, true);
            const Key pubkey = privkey.GetPubKey();

            dummy_keys.push_back(pubkey);
            dummy_keys_map.insert({pubkey.GetID(), pubkey});
            std::vector<unsigned char> sig;
            privkey.Sign(uint256S(""), sig);
            sig.push_back(1); // SIGHASH_ALL
            dummy_sigs.insert({pubkey, sig});

            std::vector<unsigned char> hash;
            hash.resize(32);
            CSHA256().Write(keydata, 32).Finalize(hash.data());
            sha256.push_back(hash);
            sha256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash256().Write(keydata).Finalize(hash);
            hash256.push_back(hash);
            hash256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            hash.resize(20);
            CRIPEMD160().Write(keydata, 32).Finalize(hash.data());
            assert(hash.size() == 20);
            ripemd160.push_back(hash);
            ripemd160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash160().Write(keydata).Finalize(hash);
            hash160.push_back(hash);
            hash160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
        }
    }
};

//! Context to parse a Miniscript node to and from Script or text representation.
struct ParserContext {
    typedef CPubKey Key;
    TestData *test_data;

    bool ToString(const Key& key, std::string& ret) const { ret = HexStr(key); return true; }

    const std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    const std::vector<unsigned char> ToPKHBytes(const Key& key) const {
        const auto h = Hash160(key);
        return {h.begin(), h.end()};
    }

    template<typename I>
    bool FromString(I first, I last, Key& key) const {
        const auto bytes = ParseHex(std::string(first, last));
        key.Set(bytes.begin(), bytes.end());
        return key.IsValid();
    }

    template<typename I>
    bool FromPKBytes(I first, I last, CPubKey& key) const {
        key.Set(first, last);
        return key.IsValid();
    }

    template<typename I>
    bool FromPKHBytes(I first, I last, CPubKey& key) const {
        assert(last - first == 20);
        CKeyID keyid;
        std::copy(first, last, keyid.begin());
        const auto it = test_data->dummy_keys_map.find(keyid);
        if (it == test_data->dummy_keys_map.end()) return false;
        key = it->second;
        return true;
    }
};

//! Context to produce a satisfaction for a Miniscript node using the pre-computed data.
struct SatisfierContext: ParserContext {
    // Timelock challenges satisfaction. Make the value (deterministically) vary to explore different
    // paths.
    bool CheckAfter(uint32_t value) const { return value % 2; }
    bool CheckOlder(uint32_t value) const { return value % 2; }

    // Signature challenges fulfilled with a dummy signature, if it was one of our dummy keys.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        const auto it = test_data->dummy_sigs.find(key);
        if (it == test_data->dummy_sigs.end()) return miniscript::Availability::NO;
        sig = it->second;
        return miniscript::Availability::YES;
    }

    //! Lookup generalization for all the hash satisfactions below
    miniscript::Availability LookupHash(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage,
                                        const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& map) const
    {
        const auto it = map.find(hash);
        if (it == map.end()) return miniscript::Availability::NO;
        preimage = it->second;
        return miniscript::Availability::YES;
    }
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->sha256_preimages);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->ripemd160_preimages);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->hash256_preimages);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return LookupHash(hash, preimage, test_data->hash160_preimages);
    }
};

//! Context to check a satisfaction against the pre-computed data.
struct CheckerContext: BaseSignatureChecker {
    TestData *test_data;

    // Signature checker methods. Checks the right dummy signature is used. Always assumes timelocks are
    // correct.
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey,
                             const CScript& scriptCode, SigVersion sigversion) const override
    {
        const CPubKey key{vchPubKey};
        const auto it = test_data->dummy_sigs.find(key);
        if (it == test_data->dummy_sigs.end()) return false;
        return it->second == sig;
    }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};

// The various contexts
TestData TEST_DATA;
ParserContext PARSER_CTX;
SatisfierContext SATISFIER_CTX;
CheckerContext CHECKER_CTX;
// A dummy scriptsig to pass to VerifyScript (we always use Segwit v0).
const CScript DUMMY_SCRIPTSIG;

using Fragment = miniscript::Fragment;
using NodeRef = miniscript::NodeRef<CPubKey>;
using miniscript::operator"" _mst;

//! Construct a miniscript node as a shared_ptr.
template<typename... Args> NodeRef MakeNodeRef(Args&&... args) { return miniscript::MakeNodeRef<CPubKey>(std::forward<Args>(args)...); }

/** A QueueElem represents (partial) information about a miniscript Node to be constructed in GenNode(). */
struct QueueElem {
    /** What miniscript type is required. */
    miniscript::Type typ;
    /** If already decided, what Fragment to use, and how many children. */
    std::optional<std::pair<Fragment, unsigned>> info;

    /** Construct an invalid QueueElem. */
    QueueElem() : typ(""_mst) {}
    /** Construct a QueueElem that permits an arbitrary node of specified type. */
    QueueElem(miniscript::Type typ_) : typ(typ_) {}
    /** Construct a QueueElem that permits a specific Fragment, with no children. */
    QueueElem(Fragment nt_) : typ(""_mst), info({nt_, 0}) {}
};

/** Helper for modifying the GenNode todo list. */
template<typename... Args>
void Plan(std::vector<QueueElem>& todo, Fragment nt, Args... args)
{
    auto& elem = todo.back();
    assert(!elem.info.has_value());
    elem.info = {nt, sizeof...(args)};
    todo.resize(todo.size() + sizeof...(args));
    int pos{0};
    ( (*(todo.rbegin() + (pos++)) = QueueElem{args}, 0), ...);
}

std::set<std::pair<Fragment, miniscript::Type>> types;

/**
 * Generate a Miniscript node based on the fuzzer's input.
 */
NodeRef GenNode(FuzzedDataProvider& provider, const miniscript::Type typ) {
    /** A stack of miniscript Nodes being built up. */
    std::vector<NodeRef> stack;
    /** The queue of instructions. */
    std::vector<QueueElem> todo{QueueElem{typ}};

    while (!todo.empty()) {
        // The expected type we have to construct.
        miniscript::Type typ = todo.back().typ;
        if (!todo.back().info.has_value()) {
            // Fragment/children have not been decided yet. Decide them.

            // Not all type properties are implemented in the match logic below,
            // so strip away the ones we cannot discern. When the node is actually
            // constructed, we compare the full requested type properties.
            typ = typ & "BVWKzondu"_mst;
            // Helper for computing the child nodes' type properties.
            auto basetype = "BVK"_mst & typ;

            // Fragcode selects which of the (applicable) matching rules below is selected.
            // Every rule, if it matches, checks if fragcode has reached 0, and if so,
            // the rule is used. If not, fragcode is decremented and we continue to the
            // next rule. This is performed in a loop so that if all rules were tried,
            // and fragcode hasn't reached 0 yet, we start over. This avoids the need to
            // count the number of matching rules up front.
            int fragcode = provider.ConsumeIntegralInRange<uint8_t>(0, 63);
            while (true) {
                /* Count how many matching rules we have, so that if there are none
                 * we can abort instead of looping forever. */
                int candidates = 0;
                if ("Bzud"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::JUST_0); // 0
                } else if ("Bzu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::JUST_1); // 1
                } else if ("Kondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::PK_K); // pk_k
                } else if ("Kndu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::PK_H); // pk_h
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_C, Fragment::PK_K); // pk
                } else if ("Bndu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_C, Fragment::PK_H); // pkh
                } else if ("Bz"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OLDER); // older
                } else if ("Bz"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::AFTER); // after
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::SHA256); // sha256
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::RIPEMD160); // ripemd160
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::HASH256); // hash256
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::HASH160); // hash160
                } else if ("Bndu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::MULTI); // multi
                } else if ("Wdu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_A, "B"_mst); // a:
                } else if ("Wdu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_S, "Bo"_mst); // s:
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_C, "K"_mst); // c:
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_D, "Vz"_mst); // d:
                } else if ("Vzon"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_V, "B"_mst); // d:
                } else if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_J, "Bn"_mst); // j:
                } else if ("Bzondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::WRAP_N, "B"_mst); // n:
                } else if ("Boud"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OR_I, Fragment::JUST_0, "B"_mst); // l:
                } else if ("Boud"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OR_I, "B"_mst, Fragment::JUST_0); // u:
                } else if ("BVKzonu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::AND_V, "V"_mst, basetype); // and_v
                } else if ("Bzondu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::AND_B, "B"_mst, "W"_mst); // and_b
                } else if ("Bzoud"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::ANDOR, "Bdu"_mst, basetype, Fragment::JUST_0); // and_n
                } else if ("Bzodu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OR_B, "Bd"_mst, "Wd"_mst); // or_b
                } else if ("Vzo"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OR_C, "Bdu"_mst, "V"_mst); // or_c
                } else if ("Bzodu"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OR_D, "Bdu"_mst, "B"_mst); // or_d
                } else if ("BKVoud"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::OR_I, basetype, basetype); // or_i
                } else if ("BVKzoud"_mst << typ && ++candidates && !(fragcode--)) {
                    Plan(todo, Fragment::ANDOR, "Bdu"_mst, basetype, basetype); // andor
                } else if ("Bzodu"_mst << typ && ++candidates && !(fragcode--)) {
                    // thresh()
                    auto children = provider.ConsumeIntegralInRange<uint32_t>(1, MAX_OPS_PER_SCRIPT / 2);
                    todo.back().info = {Fragment::THRESH, children};
                    todo.reserve(todo.size() + children);
                    for (uint32_t i = 1; i < children; ++i) todo.emplace_back("Wdu"_mst);
                    todo.emplace_back("Bdu"_mst);
                } else if (candidates == 0) {
                    // This typ value has no applicable rules. Abort.
                    return {};
                } else {
                    // One or more fragments were applicable, but fragcode hadn't reached 0 yet.
                    // Loop again.
                    continue;
                }
                // If we reach this line, a fragment was selected.
                break;
            }
        } else {
            // The back of todo has nodetype and number of children decided, and
            // those children have been constructed at the back of stack. Pop
            // that entry off todo, and use it to construct a new NodeRef on
            // stack.
            auto [nodetype, children] = *todo.back().info;
            todo.pop_back();
            // Gather children from the back of stack.
            std::vector<NodeRef> sub;
            sub.reserve(children);
            for (size_t i = 0; i < children; ++i) {
                sub.push_back(std::move(*(stack.end() - children + i)));
            }
            stack.erase(stack.end() - children, stack.end());
            // Additional arguments for construction of NodeRef.
            uint32_t val = 0;
            std::vector<unsigned char> arg;
            std::vector<CPubKey> keys;
            // Fill in arguments
            switch (nodetype) {
                case Fragment::PK_K:
                case Fragment::PK_H:
                    keys.push_back(PickValue(provider, TEST_DATA.dummy_keys));
                    break;
                case Fragment::MULTI: {
                    int num_keys = provider.ConsumeIntegralInRange<int>(1, 20);
                    val = provider.ConsumeIntegralInRange<uint32_t>(1, num_keys);
                    for (int i = 0; i < num_keys; ++i) keys.push_back(PickValue(provider, TEST_DATA.dummy_keys));
                    break;
                }
                case Fragment::THRESH:
                    val = provider.ConsumeIntegralInRange<uint32_t>(1, sub.size());
                    break;
                case Fragment::AFTER:
                case Fragment::OLDER:
                    val = provider.ConsumeIntegralInRange<uint32_t>(1, 0x7FFFFFFF);
                    break;
                case Fragment::SHA256:
                    arg = PickValue(provider, TEST_DATA.sha256);
                    break;
                case Fragment::RIPEMD160:
                    arg = PickValue(provider, TEST_DATA.ripemd160);
                    break;
                case Fragment::HASH256:
                    arg = PickValue(provider, TEST_DATA.hash256);
                    break;
                case Fragment::HASH160:
                    arg = PickValue(provider, TEST_DATA.hash160);
                    break;
                default:
                    break;
            }
            // Construct new NodeRef.
            NodeRef node;
            if (keys.empty()) {
                node = MakeNodeRef(nodetype, std::move(sub), std::move(arg), val);
            } else {
                assert(sub.empty());
                assert(arg.empty());
                node = MakeNodeRef(nodetype, std::move(keys), val);
            }
            // Verify acceptability.
            if (!node || !node->IsValid() || !(node->GetType() << typ)) return {};
            // Move it to the stack.
            stack.push_back(std::move(node));
        }
    }
    assert(stack.size() == 1);
    return std::move(stack[0]);
}

//! Pre-compute the test data and point the various contexts to it.
void initialize_miniscript_random() {
    ECC_Start();
    TEST_DATA.Init();
    PARSER_CTX.test_data = &TEST_DATA;
    SATISFIER_CTX.test_data = &TEST_DATA;
    CHECKER_CTX.test_data = &TEST_DATA;
}

FUZZ_TARGET_INIT(miniscript_random, initialize_miniscript_random)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Generate a top-level node
    const auto node = GenNode(fuzzed_data_provider, "B"_mst);
    if (!node || !node->IsValidTopLevel()) return;

    // Check roundtrip to Script, and consistency between script size estimation and real size
    const auto script = node->ToScript(PARSER_CTX);
    assert(node->ScriptSize() == script.size());
    auto decoded = miniscript::FromScript(script, PARSER_CTX);
    assert(decoded);
    // Note we can't use *decoded == *node because the miniscript representation may differ, so we check that:
    // - The script corresponding to that decoded form matchs exactly
    // - The type matches exactly
    assert(decoded->ToScript(PARSER_CTX) == script);
    assert(decoded->GetType() == node->GetType());

    // Check consistency of "x" property with the script (relying on the fact that no
    // top-level scripts end with a hash or key push, whose last byte could match these opcodes).
    bool ends_in_verify = !(node->GetType() << "x"_mst);
    assert(ends_in_verify == (script.back() == OP_CHECKSIG || script.back() == OP_CHECKMULTISIG || script.back() == OP_EQUAL));

    // Check that it roundtrips to text representation
    std::string str;
    assert(node->ToString(PARSER_CTX, str));
    auto parsed = miniscript::FromString(str, PARSER_CTX);
    assert(parsed);
    assert(*parsed == *node);


    // Check both malleable and non-malleable satisfaction. Note that we only assert the produced witness
    // is valid if the Miniscript was sane, as otherwise it could overflow the limits.
    CScriptWitness witness;
    const CScript script_pubkey = CScript() << OP_0 << WitnessV0ScriptHash(script);
    const bool mal_success = node->Satisfy(SATISFIER_CTX, witness.stack, false) == miniscript::Availability::YES;
    if (mal_success && node->IsSaneTopLevel()) {
        witness.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));
        assert(VerifyScript(DUMMY_SCRIPTSIG, script_pubkey, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, CHECKER_CTX));
    }
    witness.stack.clear();
    const bool nonmal_success = node->Satisfy(SATISFIER_CTX, witness.stack, true) == miniscript::Availability::YES;
    if (nonmal_success && node->IsSaneTopLevel()) {
        witness.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));
        assert(VerifyScript(DUMMY_SCRIPTSIG, script_pubkey, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, CHECKER_CTX));
    }
    // If a nonmalleable solution exists, a solution whatsoever must also exist.
    assert(mal_success >= nonmal_success);
    // If a miniscript is nonmalleable and needs a signature, and a solution exists, a non-malleable solution must also exist.
    if (node->IsNonMalleable() && node->NeedsSignature()) assert(nonmal_success == mal_success);
}
