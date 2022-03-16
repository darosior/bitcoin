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

namespace {

//! Some pre-computed data to simulate challenges.
struct TestData {
    typedef CPubKey Key;

    // Precomputed public keys, and a dummy signature for each of them.
    std::vector<Key> dummy_keys;
    std::map<CKeyID, Key> dummy_keys_map;
    std::map<Key, std::pair<std::vector<unsigned char>, bool>> dummy_sigs;

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
            dummy_sigs.insert({pubkey, {sig, i & 1}});

            std::vector<unsigned char> hash;
            hash.resize(32);
            CSHA256().Write(keydata, 32).Finalize(hash.data());
            sha256.push_back(hash);
            if (i & 1) sha256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash256().Write(keydata).Finalize(hash);
            hash256.push_back(hash);
            if (i & 1) hash256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            hash.resize(20);
            CRIPEMD160().Write(keydata, 32).Finalize(hash.data());
            assert(hash.size() == 20);
            ripemd160.push_back(hash);
            if (i & 1) ripemd160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash160().Write(keydata).Finalize(hash);
            hash160.push_back(hash);
            if (i & 1) hash160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
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
        if (it->second.second) {
            // Key is "available"
            sig = it->second.first;
            return miniscript::Availability::YES;
        } else {
            return miniscript::Availability::NO;
        }
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

    // Signature checker methods. Checks the right dummy signature is used.
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey,
                             const CScript& scriptCode, SigVersion sigversion) const override
    {
        const CPubKey key{vchPubKey};
        const auto it = test_data->dummy_sigs.find(key);
        if (it == test_data->dummy_sigs.end()) return false;
        return it->second.first == sig;
    }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return nLockTime.GetInt64() & 1; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return nSequence.GetInt64() & 1; }
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
using Node = miniscript::Node<CPubKey>;
using miniscript::operator"" _mst;

//! Construct a miniscript node as a shared_ptr.
template<typename... Args> NodeRef MakeNodeRef(Args&&... args) { return miniscript::MakeNodeRef<CPubKey>(std::forward<Args>(args)...); }

/** Information about a yet to be constructed Miniscript node. */
struct NodeInfo {
    //! The type of this node
    Fragment fragment;
    //! Number of subs of this node
    uint8_t n_subs;
    //! The timelock value for older() and after(), the threshold value for multi() and thresh()
    uint32_t k;
    //! Keys for this node, if it has some
    std::vector<CPubKey> keys;
    //! The hash value for this node, if it has one
    std::vector<unsigned char> hash;
    //! The type requirements for the children of this node.
    std::vector<miniscript::Type> subtypes;

    NodeInfo(Fragment frag): fragment(frag), n_subs(0), k(0) {}
    NodeInfo(Fragment frag, CPubKey key): fragment(frag), n_subs(0), k(0), keys({key}) {}
    NodeInfo(Fragment frag, uint32_t _k): fragment(frag), n_subs(0), k(_k) {}
    NodeInfo(Fragment frag, std::vector<unsigned char> h): fragment(frag), n_subs(0), k(0), hash(std::move(h)) {}
    NodeInfo(uint8_t subs, Fragment frag): fragment(frag), n_subs(subs), k(0), subtypes(subs, ""_mst) {}
    NodeInfo(uint8_t subs, Fragment frag, uint32_t _k): fragment(frag), n_subs(subs), k(_k), subtypes(subs, ""_mst)  {}
    NodeInfo(std::vector<miniscript::Type> subt, Fragment frag): fragment(frag), n_subs(subt.size()), k(0), subtypes(std::move(subt)) {}
    NodeInfo(std::vector<miniscript::Type> subt, Fragment frag, uint32_t _k): fragment(frag), n_subs(subt.size()), k(_k), subtypes(std::move(subt))  {}
    NodeInfo(Fragment frag, uint32_t _k, std::vector<CPubKey> _keys): fragment(frag), n_subs(0), k(_k), keys(std::move(_keys)) {}
};

/** Pick an index in a collection from a single byte in the fuzzer's output. */
template<typename T, typename A>
T ConsumeIndex(FuzzedDataProvider& provider, A& col) {
    const uint8_t i = provider.ConsumeIntegral<uint8_t>();
    return col[i];
}

CPubKey ConsumePubKey(FuzzedDataProvider& provider) {
    return ConsumeIndex<CPubKey>(provider, TEST_DATA.dummy_keys);
}

std::vector<unsigned char> ConsumeSha256(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.sha256);
}

std::vector<unsigned char> ConsumeHash256(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.hash256);
}

std::vector<unsigned char> ConsumeRipemd160(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.ripemd160);
}

std::vector<unsigned char> ConsumeHash160(FuzzedDataProvider& provider) {
    return ConsumeIndex<std::vector<unsigned char>>(provider, TEST_DATA.hash160);
}

std::optional<uint32_t> ConsumeTimeLock(FuzzedDataProvider& provider) {
    const uint32_t k = provider.ConsumeIntegral<uint32_t>();
    if (k == 0 || k >= 0x80000000) return {};
    return k;
}

/**
 * Consume a Miniscript node from the fuzzer's output.
 *
 * This version is intended to have a fixed, stable, encoding for Miniscript nodes:
 *  - The first byte sets the type of the fragment. 0, 1 and all non-leaf fragments but thresh() are a
 *    single byte.
 *  - For the other leaf fragments, the following bytes depend on their type.
 *    - For older() and after(), the next 4 bytes define the timelock value.
 *    - For pk_k(), pk_h(), and all hashes, the next byte defines the index of the value in the test data.
 *    - For multi(), the next 2 bytes define respectively the threshold and the number of keys. Then as many
 *      bytes as the number of keys define the index of each key in the test data.
 *    - For thresh(), the next byte defines the threshold value and the following one the number of subs.
 */
std::optional<NodeInfo> ConsumeNodeStable(FuzzedDataProvider& provider) {
    switch (provider.ConsumeIntegral<uint8_t>()) {
        case 0: return {{Fragment::JUST_0}};
        case 1: return {{Fragment::JUST_1}};
        case 2: return {{Fragment::PK_K, ConsumePubKey(provider)}};
        case 3: return {{Fragment::PK_H, ConsumePubKey(provider)}};
        case 4: {
            const auto k = ConsumeTimeLock(provider);
            if (!k) return {};
            return {{Fragment::OLDER, *k}};
        }
        case 5: {
            const auto k = ConsumeTimeLock(provider);
            if (!k) return {};
            return {{Fragment::AFTER, *k}};
        }
        case 6: return {{Fragment::SHA256, ConsumeSha256(provider)}};
        case 7: return {{Fragment::HASH256, ConsumeHash256(provider)}};
        case 8: return {{Fragment::RIPEMD160, ConsumeRipemd160(provider)}};
        case 9: return {{Fragment::HASH160, ConsumeHash160(provider)}};
        case 10: {
            const auto k = provider.ConsumeIntegral<uint8_t>();
            const auto n_keys = provider.ConsumeIntegral<uint8_t>();
            if (n_keys > 20 || k == 0 || k > n_keys) return {};
            std::vector<CPubKey> keys{n_keys};
            for (auto& key: keys) key = ConsumePubKey(provider);
            return {{Fragment::MULTI, k, std::move(keys)}};
        }
        case 11: return {{3, Fragment::ANDOR}};
        case 12: return {{2, Fragment::AND_V}};
        case 13: return {{2, Fragment::AND_B}};
        case 15: return {{2, Fragment::OR_B}};
        case 16: return {{2, Fragment::OR_C}};
        case 17: return {{2, Fragment::OR_D}};
        case 18: return {{2, Fragment::OR_I}};
        case 19: {
            auto k = provider.ConsumeIntegral<uint8_t>();
            auto n_subs = provider.ConsumeIntegral<uint8_t>();
            if (k == 0 || k > n_subs) return {};
            return {{n_subs, Fragment::THRESH, k}};
        }
        case 20: return {{1, Fragment::WRAP_A}};
        case 21: return {{1, Fragment::WRAP_S}};
        case 22: return {{1, Fragment::WRAP_C}};
        case 23: return {{1, Fragment::WRAP_D}};
        case 24: return {{1, Fragment::WRAP_V}};
        case 25: return {{1, Fragment::WRAP_J}};
        case 26: return {{1, Fragment::WRAP_N}};
        default:
            break;
    }
    return {};
}

/**
 * Consume a Miniscript node from the fuzzer's output.
 *
 * This is similar to ConsumeNodeStable, but uses a miniscript::Type-driven heuristics
 * to construct the nodes. It is intended to more quickly explore interesting miniscripts,
 * at the cost of higher implementation complexity (which could cause it miss things if
 * incorrect), and with less regard for stability of the seeds (as changes to the
 * heuristics implemented here may dramatically alter the resulting node for a given seed).
 */
std::optional<NodeInfo> ConsumeNodeSmart(FuzzedDataProvider& provider, miniscript::Type type_needed) {
    // If no bytes remain in provider, abort. This prevents infinite loops
    // in case a read zero (for fragcode) results in a recursive rule triggering.
    if (provider.remaining_bytes() == 0) return {};

    // Not all type properties are implemented in the match logic below,
    // so strip away the ones we cannot discern. When the node is actually
    // constructed, we compare the full requested type properties.
    auto typ = type_needed & "BVWKzondu"_mst;
    // Some helpers for computing the child nodes' type properties.
    auto base = "BVK"_mst & typ;
    auto tz = typ & "z"_mst;
    auto toz = "z"_mst.If(typ << "o"_mst);
    auto to = typ & "o"_mst;
    auto tn = typ & "n"_mst;
    auto td = typ & "d"_mst;
    auto tu = typ & "u"_mst;

    // Fragcode selects which of the (applicable) matching rules below is selected.
    // Every rule, if it matches, checks if fragcode has reached 0, and if so,
    // the rule is used. If not, fragcode is decremented and we continue to the
    // next rule. This is performed in a loop so that if all rules were tried,
    // and fragcode hasn't reached 0 yet, we start over. This avoids the need to
    // count the number of matching rules up front.
    int fragcode = provider.ConsumeIntegral<uint8_t>();

    while (true) {
        /** Counter for the number of applicable rules. */
        int candidates = 0;

        // Rules for constructing leaf nodes
        if ("Bzud"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::JUST_0}};
        if ("Bzu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::JUST_1}};
        if ("Kondu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::PK_K, ConsumePubKey(provider)}};
        if ("Kndu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::PK_H, ConsumePubKey(provider)}};
        if ("Bz"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::OLDER, provider.ConsumeIntegralInRange<uint32_t>(1, 0x7FFFFFF)}};
        if ("Bz"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::AFTER, provider.ConsumeIntegralInRange<uint32_t>(1, 0x7FFFFFF)}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::SHA256, PickValue(provider, TEST_DATA.sha256)}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::RIPEMD160, PickValue(provider, TEST_DATA.ripemd160)}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::HASH256, PickValue(provider, TEST_DATA.hash256)}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{Fragment::HASH160, PickValue(provider, TEST_DATA.hash160)}};

        // Rules for constructing wrappers
        if ("Wdu"_mst << typ && ++candidates && !(fragcode--)) return {{{"B"_mst | td | tu}, Fragment::WRAP_A}};
        if ("Wdu"_mst << typ && ++candidates && !(fragcode--)) return {{{"Bo"_mst | td | tu}, Fragment::WRAP_S}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{{"K"_mst | to | tn | td}, Fragment::WRAP_C}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{{"Vz"_mst}, Fragment::WRAP_D}};
        if ("Vzon"_mst << typ && ++candidates && !(fragcode--)) return {{{"B"_mst | tz | to | tn}, Fragment::WRAP_V}};
        if ("Bondu"_mst << typ && ++candidates && !(fragcode--)) return {{{"Bn"_mst | to | tu}, Fragment::WRAP_J}};
        if ("Bzondu"_mst << typ && ++candidates && !(fragcode--)) return {{{"B"_mst | tz | to | tn | td}, Fragment::WRAP_N}};
        if ("BVKzonu"_mst << typ && ++candidates && !(fragcode--)) return {{{"V"_mst | tz, base | tz | tu}, Fragment::AND_V}};

        // Rules for constructing connectives
        if ("Bzondu"_mst << typ && ++candidates && !(fragcode--)) return {{{"B"_mst | tz | td, "W"_mst | tz | td}, Fragment::AND_B}};
        if ("Bzodu"_mst << typ && ++candidates && !(fragcode--)) return {{{"Bd"_mst | tz, "Wd"_mst | tz}, Fragment::OR_B}};
        if ("Vzo"_mst << typ && ++candidates && !(fragcode--)) return {{{"Bdu"_mst | tz | to, "V"_mst | tz | toz}, Fragment::OR_C}};
        if ("Bzodu"_mst << typ && ++candidates && !(fragcode--)) return {{{"Bdu"_mst | tz | to, "B"_mst | tz | td | tu | toz}, Fragment::OR_D}};
        if ("BKVoud"_mst << typ && ++candidates && !(fragcode--)) return {{{base | toz | tu, base | toz | tu}, Fragment::OR_I}};
        if ("BVKzoud"_mst << typ && ++candidates && !(fragcode--)) return {{{"Bdu"_mst | tz, base | tz | tu, base | tz | tu | td}, Fragment::ANDOR}};

        // Multi
        if ("Bndu"_mst << typ && ++candidates && !(fragcode--)) {
            const auto n_keys = provider.ConsumeIntegralInRange<uint8_t>(1, 20);
            const auto k = provider.ConsumeIntegralInRange<uint8_t>(1, n_keys);
            std::vector<CPubKey> keys{n_keys};
            for (auto& key: keys) key = ConsumePubKey(provider);
            return {{Fragment::MULTI, k, std::move(keys)}};
        }

        // Thresh
        if ("Bzodu"_mst << typ && ++candidates && !(fragcode--)) {
            auto children = provider.ConsumeIntegralInRange<uint32_t>(1, MAX_OPS_PER_SCRIPT / 2);
            auto k = provider.ConsumeIntegralInRange<uint32_t>(1, children);
            std::vector<miniscript::Type> subt{children - 1, "Wdu"_mst};
            subt.push_back("Bdu"_mst);
            return {{std::move(subt), Fragment::THRESH, k}};
        }

        if (candidates == 0) {
            // This typ value has no applicable rules. Abort.
            break;
        }

        // If this point was reached, the typ value had applicable rules, but the initial
        // fragcode value was larger than their count. Make sure that this doesn't occur
        // again in the next iteration of the loop.
        fragcode %= candidates;
    }
    return {};
}

// As they are repeated several times in the mappings below, we class the fragment by
// their types and *possible* properties. There are therefore groups with conflicting
// properties. It's fine, the right one will be chosen by ConsumeNodeSmartMap.
// See the properties table on https://bitcoin.sipa.be/miniscript/.

// Base types
// o; n; d; u
#define B_DNOU Fragment::SHA256, Fragment::HASH256, Fragment::RIPEMD160, Fragment::HASH160, Fragment::WRAP_D
// z; o; d; u
#define B_DOUZ Fragment::OR_D
// n; d; u
#define B_DNU Fragment::MULTI
// z; u; d
#define B_DUZ Fragment::JUST_0
// n; d
#define B_DN Fragment::WRAP_J
// d; u
#define B_DU Fragment::OR_B, Fragment::THRESH
// z; u
#define B_UZ Fragment::JUST_1
// u
#define B_U Fragment::AND_B, Fragment::WRAP_C, Fragment::WRAP_N
// z
#define B_Z Fragment::OLDER, Fragment::AFTER

// Key types
// o; n; d; u
#define K_DNOU Fragment::PK_K
// n; d; u
#define K_DNU Fragment::PK_H

// Verify types
// z; o; n
#define V_NOZ Fragment::WRAP_V
// z; o
#define V_OZ Fragment::OR_C

// Wrapped types
// d; u
#define W_DU Fragment::WRAP_A, Fragment::WRAP_S

// Base, Key, or Verify types
// z; o; u; d
#define DOUZ Fragment::ANDOR
// o; u; d
#define DOU Fragment::OR_I
// z; o; n; u
#define NOUZ Fragment::AND_V

// A mapping from properties that may be asked to the possible B fragments that
// *can* have these properties.
std::map<miniscript::Type, std::vector<Fragment>> base_fragments = {
    {"dnou"_mst, {B_DNOU}},
    {"dno"_mst, {B_DNOU}},
    {"dnu"_mst, {B_DNOU, B_DNU}},
    {"dou"_mst, {B_DNOU, B_DOUZ, DOUZ, DOU}},
    {"duz"_mst, {B_DUZ, B_DOUZ, DOUZ}},
    {"nou"_mst, {B_DNOU, NOUZ}},
    {"do"_mst, {B_DNOU, B_DOUZ, DOUZ, DOU}},
    {"dn"_mst, {B_DNOU, B_DNU, B_DN}},
    {"du"_mst, {B_DNOU, B_DOUZ, B_DNU, B_DUZ, B_DU, DOUZ, DOU}},
    {"dz"_mst, {B_DOUZ, B_DUZ, DOUZ}},
    {"no"_mst, {B_DNOU, NOUZ}},
    {"nu"_mst, {B_DNOU, B_DNU, NOUZ}},
    {"ou"_mst, {B_DNOU, B_DOUZ, DOUZ, NOUZ, DOU}},
    {"uz"_mst, {B_DOUZ, B_DUZ, B_UZ, DOUZ, NOUZ}},
    {"d"_mst, {B_DNOU, B_DOUZ, B_DNU, B_DUZ, B_DN, B_DU, DOUZ, DOU}},
    {"n"_mst, {B_DNOU, B_DNU, B_DN, NOUZ}},
    {"o"_mst, {B_DNOU, B_DOUZ, DOUZ, NOUZ, DOU}},
    {"u"_mst, {B_DNOU, B_DOUZ, B_DNU, B_DUZ, B_DU, B_UZ, B_U, DOUZ, NOUZ, DOU}},
    {"z"_mst, {B_DOUZ, B_DUZ, B_UZ, B_Z, DOUZ, NOUZ}},
    {""_mst, {B_DNOU, B_DOUZ, B_DNU, B_DUZ, B_DN, B_DU, B_UZ, B_U, B_Z, DOUZ, NOUZ, DOU}}, // Any property
};

// A mapping from properties that may be asked to the possible K fragments that
// *can* have these properties.
// Note the K fragments can never have the 'z' property.
std::map<miniscript::Type, std::vector<Fragment>> key_fragments = {
    {"dnou"_mst, {K_DNOU}},
    {"dno"_mst, {K_DNOU}},
    {"dnu"_mst, {K_DNOU, K_DNU}},
    {"dou"_mst, {K_DNOU, DOUZ, DOU}},
    {"nou"_mst, {K_DNOU, NOUZ}},
    {"do"_mst, {K_DNOU, DOUZ, DOU}},
    {"dn"_mst, {K_DNOU, K_DNU}},
    {"du"_mst, {K_DNOU, K_DNU, DOUZ, DOU}},
    {"no"_mst, {K_DNOU, NOUZ}},
    {"nu"_mst, {K_DNOU, K_DNU, NOUZ}},
    {"ou"_mst, {K_DNOU, DOUZ, NOUZ, DOU}},
    {"d"_mst, {K_DNOU, K_DNU, DOUZ, DOU}},
    {"n"_mst, {K_DNOU, K_DNU, NOUZ}},
    {"o"_mst, {K_DNOU, DOUZ, NOUZ, DOU}},
    {"u"_mst, {K_DNOU, K_DNU, DOUZ, NOUZ, DOU}},
    {""_mst, {K_DNOU, K_DNU, DOUZ, NOUZ, DOU}}, // Any property
};

// A mapping from properties that may be asked to the possible V fragments that
// *can* have these properties.
std::map<miniscript::Type, std::vector<Fragment>> verify_fragments = {
    {"dou"_mst, {DOUZ, DOU}},
    {"duz"_mst, {DOUZ}},
    {"nou"_mst, {B_DNOU, NOUZ}},
    {"do"_mst, {DOUZ, DOU}},
    {"du"_mst, {DOUZ, DOU}},
    {"dz"_mst, {DOUZ}},
    {"no"_mst, {V_NOZ, NOUZ}},
    {"nu"_mst, {NOUZ}},
    {"ou"_mst, {DOUZ, NOUZ, DOU}},
    {"uz"_mst, {DOUZ, NOUZ}},
    {"d"_mst, {DOUZ, DOU}},
    {"n"_mst, {V_NOZ, NOUZ}},
    {"o"_mst, {V_NOZ, V_OZ, DOUZ, NOUZ, DOU}},
    {"u"_mst, {DOUZ, NOUZ, DOU}},
    {"z"_mst, {V_NOZ, V_OZ, DOUZ, NOUZ}},
    {""_mst, {V_NOZ, V_OZ, DOUZ, NOUZ, DOU}}, // Any property
};

// A mapping from properties that may be asked to the possible W fragments that
// *can* have these properties.
std::map<miniscript::Type, std::vector<Fragment>> wrapped_fragments = {
    {"du"_mst, {W_DU}},
    {"d"_mst, {W_DU}},
    {"u"_mst, {W_DU}},
    {""_mst, {W_DU}}, // Any property
};

// A mapping from type to the existing fragments for these types, keyed by available
// properties.
std::map<miniscript::Type, std::map<miniscript::Type, std::vector<Fragment>>> fragments = {
    {"B"_mst, base_fragments},
    {"K"_mst, key_fragments},
    {"V"_mst, verify_fragments},
    {"W"_mst, wrapped_fragments},
    // FIXME: K, V and W are awfully done in initialize_miniscript_random as i can't find a way to have B + K + V + W here
    {""_mst, base_fragments}, // Any type.
};

/**
 * Consume a Miniscript node from the fuzzer's output.
 *
 * Same as ConsumeNodeSmart, but uses a mapping instead of a loop.
 */
std::optional<NodeInfo> ConsumeNodeSmartMap(FuzzedDataProvider& provider, miniscript::Type type_needed) {
    // If no bytes remain in provider, abort. This prevents infinite loops.
    if (provider.remaining_bytes() == 0) return {};

    // Get the possible fragments for the requested type and properties from the mapping.
    // Then make the fuzzer 'choose' which of the possible fragments to use.
    const auto typ = type_needed & "BKVW"_mst;
    const auto props = type_needed & "dnouz"_mst;
    const auto possible_frags = fragments[typ][props];
    assert(possible_frags.size() > 0);
    const size_t index = provider.ConsumeIntegralInRange<size_t>(0, possible_frags.size() - 1);
    const auto frag = possible_frags[index];

    // Helpers for properties pass-through
    // FIXME: should we try to pass more properties even if that means more combinations?
    auto tz = props & "z"_mst;
    auto toz = "z"_mst.If(props << "o"_mst);
    auto to = props & "o"_mst;
    auto tn = props & "n"_mst;
    auto td = props & "d"_mst;
    auto tu = props & "u"_mst;

    switch (frag) {
        case Fragment::JUST_0:
        case Fragment::JUST_1: return {{frag}};
        case Fragment::PK_K:
        case Fragment::PK_H: return {{frag, ConsumePubKey(provider)}};
        case Fragment::OLDER:
        case Fragment::AFTER: return {{frag, provider.ConsumeIntegralInRange<uint32_t>(1, 0x7FFFFFF)}};
        case Fragment::SHA256: return {{frag, PickValue(provider, TEST_DATA.sha256)}};
        case Fragment::RIPEMD160: return {{frag, PickValue(provider, TEST_DATA.ripemd160)}};
        case Fragment::HASH256: return {{frag, PickValue(provider, TEST_DATA.hash256)}};
        case Fragment::HASH160: return {{frag, PickValue(provider, TEST_DATA.hash160)}};
        case Fragment::MULTI: {
            const auto n_keys = provider.ConsumeIntegralInRange<uint8_t>(1, 20);
            const auto k = provider.ConsumeIntegralInRange<uint8_t>(1, n_keys);
            std::vector<CPubKey> keys{n_keys};
            for (auto& key: keys) key = ConsumePubKey(provider);
            return {{frag, k, std::move(keys)}};
        }
        case Fragment::AND_V: return {{{"V"_mst | tz, typ | tz | tu}, frag}};
        case Fragment::AND_B: return {{{"B"_mst | tz | td, "W"_mst | tz | td}, frag}};
        case Fragment::OR_B: return {{{"Bd"_mst | tz, "Wd"_mst | tz}, frag}};
        case Fragment::OR_C: return {{{"Bdu"_mst | tz | to, "V"_mst | tz | toz}, frag}};
        case Fragment::OR_D: return {{{"Bdu"_mst | tz | to, "B"_mst | tz | td | tu | toz}, frag}};
        case Fragment::OR_I: return {{{typ | toz | tu, "B"_mst | toz | tu}, frag}};
        case Fragment::ANDOR: return {{{"Bdu"_mst | tz, typ | tz | tu, typ | tz | tu | td}, frag}};
        case Fragment::THRESH: {
            auto children = provider.ConsumeIntegralInRange<uint32_t>(1, MAX_OPS_PER_SCRIPT / 2);
            auto k = provider.ConsumeIntegralInRange<uint32_t>(1, children);
            std::vector<miniscript::Type> subt{children - 1, "Wdu"_mst};
            subt.push_back("Bdu"_mst);
            return {{std::move(subt), frag, k}};
        }
        case Fragment::WRAP_A: return {{{"B"_mst | td | tu}, frag}};
        case Fragment::WRAP_S: return {{{"Bo"_mst | td | tu}, frag}};
        case Fragment::WRAP_C: return {{{"K"_mst | to | tn | td}, frag}};
        case Fragment::WRAP_D: return {{{"Vz"_mst}, frag}};
        case Fragment::WRAP_V: return {{{"B"_mst | tz | to | tn}, frag}};
        case Fragment::WRAP_J: return {{{"Bn"_mst | to | tu}, frag}};
        case Fragment::WRAP_N: return {{{"B"_mst | tz | to | tn | td}, frag}};
        default: break;
    }

    assert(false);
    return {};
}

/**
 * Generate a Miniscript node based on the fuzzer's input.
 */
template<typename F>
NodeRef GenNode(F ConsumeNode) {
    /** A stack of miniscript Nodes being built up. */
    std::vector<NodeRef> stack;
    /** The queue of instructions. */
    std::vector<std::pair<miniscript::Type, std::optional<NodeInfo>>> todo{{""_mst, {}}};

    while (!todo.empty()) {
        // The expected type we have to construct.
        auto type_needed = todo.back().first;
        if (!todo.back().second) {
            // Fragment/children have not been decided yet. Decide them.
            auto node_info = ConsumeNode(type_needed);
            if (!node_info) return {};
            auto subtypes = std::move(node_info)->subtypes;
            todo.back().second = std::move(node_info);
            todo.reserve(todo.size() + subtypes.size());
            for (auto type : subtypes) todo.emplace_back(type, std::nullopt);
        } else {
            // The back of todo has fragment and number of children decided, and
            // those children have been constructed at the back of stack. Pop
            // that entry off todo, and use it to construct a new NodeRef on
            // stack.
            const NodeInfo& info = *todo.back().second;
            // Gather children from the back of stack.
            std::vector<NodeRef> sub;
            sub.reserve(info.n_subs);
            for (size_t i = 0; i < info.n_subs; ++i) {
                sub.push_back(std::move(*(stack.end() - info.n_subs + i)));
            }
            stack.erase(stack.end() - info.n_subs, stack.end());
            // Construct new NodeRef.
            NodeRef node;
            if (info.keys.empty()) {
                node = MakeNodeRef(info.fragment, std::move(sub), std::move(info.hash), info.k);
            } else {
                assert(sub.empty());
                assert(info.hash.empty());
                node = MakeNodeRef(info.fragment, std::move(info.keys), info.k);
            }
            // Verify acceptability.
            if (!node || !node->IsValid() || !(node->GetType() << type_needed)) return {};
            // Move it to the stack.
            stack.push_back(std::move(node));
            todo.pop_back();
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

    // FIXME: can't we do that statically?
    fragments[""_mst].merge(key_fragments);
    fragments[""_mst].merge(verify_fragments);
    fragments[""_mst].merge(wrapped_fragments);
}

/** Perform various applicable tests on a miniscript Node. */
void TestNode(const NodeRef& node, FuzzedDataProvider& provider)
{
    if (!node) return;

    // Check that it roundtrips to text representation
    std::string str;
    assert(node->ToString(PARSER_CTX, str));
    auto parsed = miniscript::FromString(str, PARSER_CTX);
    assert(parsed);
    assert(*parsed == *node);

    // Check consistency between script size estimation and real size.
    auto script = node->ToScript(PARSER_CTX);
    assert(node->ScriptSize() == script.size());

    // Check consistency of "x" property with the script (type K is excluded, because it can end
    // with a push of a key, which could match these opcodes).
    if (!(node->GetType() << "K"_mst)) {
        bool ends_in_verify = !(node->GetType() << "x"_mst);
        assert(ends_in_verify == (script.back() == OP_CHECKSIG || script.back() == OP_CHECKMULTISIG || script.back() == OP_EQUAL));
    }

    // The rest of the checks only apply when testing a valid top-level script.
    if (!node->IsValidTopLevel()) return;

    // Check roundtrip to script
    auto decoded = miniscript::FromScript(script, PARSER_CTX);
    assert(decoded);
    // Note we can't use *decoded == *node because the miniscript representation may differ, so we check that:
    // - The script corresponding to that decoded form matchs exactly
    // - The type matches exactly
    assert(decoded->ToScript(PARSER_CTX) == script);
    assert(decoded->GetType() == node->GetType());

    if (provider.ConsumeBool()) {
        // Optionally pad the script with OP_NOPs to max op the ops limit of the constructed script.
        // This makes the script obviously not actually miniscript-compatible anymore, but the
        // signatures constructed in this test don't commit to the script anyway, so the same
        // miniscript satisfier will work. This increases the sensitivity of the test to the ops
        // counting logic being too low, especially for simple scripts.
        for (int i = node->GetOps(); i < MAX_OPS_PER_SCRIPT; ++i) {
            script.push_back(OP_NOP);
        }
    }

    // Run malleable satisfaction algorithm.
    const CScript script_pubkey = CScript() << OP_0 << WitnessV0ScriptHash(script);
    CScriptWitness witness_mal;
    const bool mal_success = node->Satisfy(SATISFIER_CTX, witness_mal.stack, false) == miniscript::Availability::YES;
    witness_mal.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));

    // Run non-malleable satisfaction algorithm.
    CScriptWitness witness_nonmal;
    const bool nonmal_success = node->Satisfy(SATISFIER_CTX, witness_nonmal.stack, true) == miniscript::Availability::YES;
    witness_nonmal.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));

    if (nonmal_success) {
        // Non-malleable satisfactions are bounded by GetStackSize().
        assert(witness_nonmal.stack.size() <= node->GetStackSize());
        // If a non-malleable satisfaction exists, the malleable one must also exist, and be identical to it.
        assert(mal_success);
        assert(witness_nonmal.stack == witness_mal.stack);

        // Test non-malleable satisfaction.
        ScriptError serror;
        bool res = VerifyScript(DUMMY_SCRIPTSIG, script_pubkey, &witness_nonmal, STANDARD_SCRIPT_VERIFY_FLAGS, CHECKER_CTX, &serror);
        // Non-malleable satisfactions are guaranteed to be valid if ValidSatisfactions().
        if (node->ValidSatisfactions()) assert(res);
        // More detailed: non-malleable satisfactions must be valid, or could fail with ops count error (if CheckOpsLimit failed),
        // or with a stack size error (if CheckStackSize check failed).
        assert(res ||
               (!node->CheckOpsLimit() && serror == ScriptError::SCRIPT_ERR_OP_COUNT) ||
               (!node->CheckStackSize() && serror == ScriptError::SCRIPT_ERR_STACK_SIZE));
    }

    if (mal_success && (!nonmal_success || witness_mal.stack != witness_nonmal.stack)) {
        // Test malleable satisfaction only if it's different from the non-malleable one.
        ScriptError serror;
        bool res = VerifyScript(DUMMY_SCRIPTSIG, script_pubkey, &witness_mal, STANDARD_SCRIPT_VERIFY_FLAGS, CHECKER_CTX, &serror);
        // Malleable satisfactions are not guaranteed to be valid under any conditions, but they can only
        // fail due to stack or ops limits.
        assert(res || serror == ScriptError::SCRIPT_ERR_OP_COUNT || serror == ScriptError::SCRIPT_ERR_STACK_SIZE);
    }

    if (node->IsSaneTopLevel()) {
        // For sane nodes, the two algorithms behave identically.
        assert(mal_success == nonmal_success);
    }

    // Verify that if a node is policy-satisfiable, the malleable satisfaction
    // algorithm succeeds. Given that under IsSaneTopLevel() both satisfactions
    // are identical, this implies that for such nodes, the non-malleable
    // satisfaction will also match the expected policy.
    bool satisfiable = node->IsSatisfiable([](const Node& node) -> bool {
        switch (node.fragment) {
        case Fragment::PK_K:
        case Fragment::PK_H: {
            auto it = TEST_DATA.dummy_sigs.find(node.keys[0]);
            assert(it != TEST_DATA.dummy_sigs.end());
            return it->second.second;
        }
        case Fragment::MULTI: {
            size_t sats = 0;
            for (const auto& key : node.keys) {
                auto it = TEST_DATA.dummy_sigs.find(key);
                assert(it != TEST_DATA.dummy_sigs.end());
                sats += it->second.second;
            }
            return sats >= node.k;
        }
        case Fragment::OLDER:
        case Fragment::AFTER:
            return node.k & 1;
        case Fragment::SHA256:
            return TEST_DATA.sha256_preimages.count(node.data);
        case Fragment::HASH256:
            return TEST_DATA.hash256_preimages.count(node.data);
        case Fragment::RIPEMD160:
            return TEST_DATA.ripemd160_preimages.count(node.data);
        case Fragment::HASH160:
            return TEST_DATA.hash160_preimages.count(node.data);
        default:
            assert(false);
        }
        return false;
    });
    assert(mal_success == satisfiable);
}

} // namespace

/** Fuzz target that runs TestNode on nodes generated using ConsumeNodeStable. */
FUZZ_TARGET_INIT(miniscript_random_stable, initialize_miniscript_random)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    TestNode(GenNode([&](miniscript::Type) {
        return ConsumeNodeStable(provider);
    }), provider);
}

/** Fuzz target that runs TestNode on nodes generated using ConsumeNodeSmart. */
FUZZ_TARGET_INIT(miniscript_random_smart, initialize_miniscript_random)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    TestNode(GenNode([&](miniscript::Type needed_type) {
        return ConsumeNodeSmart(provider, needed_type);
    }), provider);
}

/** Fuzz target that runs TestNode on nodes generated using ConsumeNodeSmart. */
FUZZ_TARGET_INIT(miniscript_random_smart_map, initialize_miniscript_random)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    TestNode(GenNode([&](miniscript::Type needed_type) {
        return ConsumeNodeSmartMap(provider, needed_type);
    }), provider);
}
