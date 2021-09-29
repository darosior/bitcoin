// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <hash.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/strencodings.h>


#include <optional>

/** A class encapulating conversion routines for CPubKey. Since we can't have access to a
 * hash->pubkey mapping, and since fuzzing the conversion itself here would be useless
 * computation we use a static dummy public key and its hash. */
struct MockedKeyConverter {
    typedef CPubKey Key;

    std::string dummy_key_hex;
    std::vector<unsigned char> dummy_key_ser;
    std::vector<unsigned char> dummy_key_hash_ser;
    CPubKey dummy_key;
    uint160 dummy_key_hash;

    MockedKeyConverter() :
        dummy_key_hex("02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"),
        dummy_key_ser(ParseHex(dummy_key_hex)),
        dummy_key_hash_ser(ParseHex("9fc5dbe5efdce10374a4dd4053c93af540211718")),
        dummy_key(dummy_key_ser),
        dummy_key_hash(dummy_key_hash_ser) {}

    bool ToString(const CPubKey& key, std::string& ret) const { ret = dummy_key_hex; return true; }

    std::vector<unsigned char> ToPKBytes(const CPubKey& key) const { return dummy_key_ser; }

    std::vector<unsigned char> ToPKHBytes(const CPubKey& key) const { return dummy_key_hash_ser; }

    template<typename I>
    bool FromString(I first, I last, CPubKey& key) const { return true; }

    template<typename I>
    bool FromPKBytes(I first, I last, CPubKey& key) const { return true; }

    template<typename I>
    bool FromPKHBytes(I first, I last, CPubKey& key) const { return true; }
};

/** Same for the satisfier, but here we try to make the output vary (deterministically)
 * when possible in order to cover mode codepaths. */
struct MockedSatisfier : public MockedKeyConverter {
    bool CheckAfter(uint32_t value) const {
        return value % 2 == 0;
    }

    bool CheckOlder(uint32_t value) const {
        return value % 2;
    }

    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        // We can't make the availability vary on the key as it's hardcoded
        sig = ParseHex("3044022026929d0d38474ba9ddada4f19b3eed9f5f33eb9b60b50f413918ba2a22c3ffa8022044bbd366c0ad61c0b1290f7a07804ae7d5d302ba522b3dd20eacdc8c470adeb2");
        return miniscript::Availability::YES;
    }

    miniscript::Availability SatHash(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        if (hash[0] % 2) {
            return miniscript::Availability::NO;
        }
        preimage = ParseHex("054a45f8515922b2a943f3657b93c40a7c435880afe66715cca07ed14e041509");
        return miniscript::Availability::YES;
    }

    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage); }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage); }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage); }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const { return SatHash(hash, preimage); }
};


const MockedKeyConverter CONVERTER{};
const MockedSatisfier SATISFIER{};

// Since the mocked key converter replaces all the keys with a hardcoded one we can't just
// compare the two scripts. This asserts that the two scripts are equal except for the pushes.
void assertSameOps(const CScript& script_a, const CScript& script_b) {
    CScript::const_iterator it_a{script_a.begin()}, it_b{script_b.begin()};
    opcodetype op_a, op_b;

    while (script_a.GetOp(it_a, op_a)) {
        assert(script_b.GetOp(it_b, op_b));
        assert(op_a == op_b);
    }
}

FUZZ_TARGET(miniscript_decode)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const std::optional<CScript> script_opt = ConsumeDeserializable<CScript>(fuzzed_data_provider);
    if (!script_opt) return;
    const CScript script{*script_opt};

    const auto ms = miniscript::FromScript(script, CONVERTER);
    if (ms) {
        // We can roundtrip it to its string representation.
        std::string ms_str;
        assert(ms->ToString(CONVERTER, ms_str));
        assert(*miniscript::FromScript(script, CONVERTER) == *ms);
        // The Script representation must roundtrip.
        const CScript ms_script = ms->ToScript(CONVERTER);
        assertSameOps(ms_script, script);
        // We can compute the costs for this script, and (maybe) produce a satisfaction
        std::vector<std::vector<unsigned char>> stack;
        ms->Satisfy(SATISFIER, stack, true);
        ms->Satisfy(SATISFIER, stack, false);
    }
}
