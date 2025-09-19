// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/system.h>
#include <core_io.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>

#include <test/util/setup_common.h>

#include <chrono>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std::chrono_literals;

//! Uncomment to prefill the headers up to height 2015 instead of mining them.
//#define PREFILL_FIRST_HEADERS

#ifdef PREFILL_FIRST_HEADERS
#include <test/bip54_premined_headers.h>

/** Fill the chain with the 2015 first mined headers. */
void PrefillHeaders(std::vector<CBlockHeader>& header_chain)
{
    static_assert(std::size(PREMINED_HEADERS) == 2015); // Blocks up to height 2015 without the genesis block.
    Assert(header_chain.size() == 1); // Only has the genesis block.
    for (const auto str: PREMINED_HEADERS) {
        header_chain.emplace_back();
        Assert(DecodeHexBlockHeader(header_chain.back(), std::string{str}));
    }
}

#endif // PREFILL_FIRST_HEADERS

BOOST_FIXTURE_TEST_SUITE(bip54_header_miner, BasicTestingSetup)

//! Genesis block header as hex.
constexpr std::string_view GENESIS_HEADER{"010000006bda3a09be117c461fcd20256907a93a2ead15139b162013172a05a0000000000000000000000000000000000000000000000000000000000000000000000000ceca5f49ffff001d0bc4cc08"};

/**
 * A multithreaded header-only miner.
 * Given a block header, it will launch as many threads as the CPU supports and grind the nonce and Merkle
 * root. The extranonce space (in the Merkle root) given to each thread is set by the STEPS constant.
 */
class HeaderMiner {
    std::vector<std::thread> m_mining_threads;
    std::atomic_flag m_found{};
    std::atomic<CBlockHeader> m_header{};

    void MineOne(CBlockHeader header, Consensus::Params params)
    {
        while (!CheckProofOfWorkImpl(header.GetHash(), header.nBits, params)) {
            if (m_found.test()) return;
            if (++header.nNonce == 0) {
                auto arith{UintToArith256(header.hashMerkleRoot)};
                Assert(++arith <= STEPS);
                header.hashMerkleRoot = ArithToUint256(arith);
            }
        }
        m_header.store(header);
        (void)m_found.test_and_set();
        m_found.notify_all();
    }

public:
    static constexpr uint32_t STEPS{100'000};

    CBlockHeader Mine(CBlockHeader header, Consensus::Params params)
    {
        auto num_cores{std::thread::hardware_concurrency()};
        for (uint32_t i{0}; i < num_cores; ++i) {
            header.nNonce = 0;
            header.hashMerkleRoot = ArithToUint256(arith_uint256{STEPS * i});
            m_mining_threads.emplace_back(&HeaderMiner::MineOne, this, std::move(header), params);
        }

        m_found.wait(false);
        for (auto& thread: m_mining_threads) {
            thread.join();
        }

        return m_header.load();
    }
};

static std::string HexHeader(const CBlockHeader& header)
{
    DataStream stream{};
    stream << header;
    return HexStr(stream);
}

static void PrintLastHeader(const std::vector<CBlockHeader>& chain)
{
    std::cout << "Mined block header at height " << chain.size() - 1 << ": " << HexHeader(chain.back()) << std::endl;
}

/** A BIP54 timestamp-related test vector. */
struct TestVector {
    //! The chain of headers to be tested against the new rules.
    const std::vector<CBlockHeader> chain;
    //! Whether the chain of headers is valid according to the new rules.
    const bool valid;
    //! Description of this specific test case.
    const std::string comment;

    explicit TestVector(std::vector<CBlockHeader> headers, bool val, std::string com):
        chain{std::move(headers)}, valid{val}, comment{std::move(com)} {}

    UniValue GetJson() const
    {
        UniValue chain_json{UniValue::VARR};
        for (const auto& h: chain) {
            chain_json.push_back(HexHeader(h));
        }

        UniValue json{UniValue::VOBJ};
        json.pushKV("header_chain", chain_json);
        json.pushKV("valid", valid);
        json.pushKV("comment", comment);
        return json;
    }
};

static void WriteVectors(const std::vector<TestVector>& test_vectors)
{
    UniValue json_vectors{UniValue::VARR};
    for (const auto& test_vector: test_vectors) {
        json_vectors.push_back(test_vector.GetJson());
    }
    const auto json_str{json_vectors.write(4)};
    FILE* file = fsbridge::fopen("bip54_timestamps.json.gen", "w");
    fputs(json_str.c_str(), file);
    fclose(file);
}

static void RecordTestVector(std::vector<TestVector>& test_vectors, std::vector<CBlockHeader>& header_chain, bool valid, std::string comment)
{
    test_vectors.emplace_back(header_chain, valid, std::move(comment));
    WriteVectors(test_vectors); // Write the updated test vectors to disk.
}

/**
 * Test the BIP54 timestamp-related rules: timewarp and Murch-Zawy fixes.
 *
 * The test mines a chain of 4032 headers from the mainnet genesis block. Along the way it mines alternative
 * chains and record them as different test vectors. It notably exercises the bounds of where each check
 * applies to test for off-by-ones.
 */
BOOST_AUTO_TEST_CASE(mine_header_chain)
{
    SelectParams(ChainType::MAIN);
    const auto params{Params().GetConsensus()};

    // Start from the mainnet genesis block.
    std::vector<CBlockHeader> header_chain;
    header_chain.emplace_back();
    Assert(DecodeHexBlockHeader(header_chain.back(), std::string{GENESIS_HEADER}));

    // Record each generated test vector throughout.
    std::vector<TestVector> test_vectors;

    // Optionally skip re-mining the headers for the first difficulty adjustment period.
#ifdef PREFILL_FIRST_HEADERS
    PrefillHeaders(header_chain);
    for (auto it{header_chain.begin()}; it + 1 < header_chain.end(); ++it) {
        Assert(it->GetHash() == (it + 1)->hashPrevBlock);
    }
    std::cout << "Prefilled and sanity checked headers up to block height " << header_chain.size() - 1 << std::endl;
#else
    // First generate a chain of 41 blocks from genesis where each block is 10 minutes
    // after the previous one, except the last one (height 40) that is 2 hours in the
    // future.
    while (header_chain.size() < 41) {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        if (header_chain.size() < 41 - 1) {
            header.nTime += std::chrono::seconds{10min}.count();
        } else {
            header.nTime += std::chrono::seconds{2h}.count();
        }

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
    Assert(header_chain.size() == 41);

    // Now mine a 42nd block (height 41) that is more than 2 hours before the previous
    // one. This is valid, because the timewarp rule only applies to the first block
    // in a difficulty adjustment period.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime -= std::chrono::seconds{2h + 1min}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 41 is more than 2 hours before block 40.");
    }
    Assert(header_chain.size() == 42);

    // Now extend the chain to 2000 blocks in order to do the same at a further height.
    while (header_chain.size() < 2000) {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        if (header_chain.size() < 2000 - 1) {
            header.nTime += std::chrono::seconds{10min}.count();
        } else {
            header.nTime += std::chrono::seconds{2h + 10min}.count();
        }

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
    Assert(header_chain.size() == 2000);

    // Now mine a 2001st block (height 2000) that is more than 2 hours before the previous
    // one. This is valid, because the timewarp rule only applies to the first block
    // in a difficulty adjustment period.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime -= std::chrono::seconds{2h + 1s}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 2001 is more than 2 hours before block 2000.");
    }
    Assert(header_chain.size() == 2001);

    // Finally extend the chain to 2016 blocks. Make the last block (height 2015) be
    // 10 minutes + 2 hours in the future (simulating the maximum timestamp rule).
    while (header_chain.size() < 2016) {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        if (header_chain.size() < 2016 - 1) {
            header.nTime += std::chrono::seconds{10min}.count();
        } else {
            header.nTime += std::chrono::seconds{2h + 10min}.count();
        }

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
#endif // PREFILL_FIRST_HEADERS
    Assert(header_chain.size() == 2016);

    // No need to adapt nBits because it took >2 weeks between block 0 and block 2015
    // and we are already at difficulty 1.
    Assert(header_chain.back().nTime - header_chain.front().nTime >= 14 * 24 * 60 * 60);

    // Now mine two 2017th blocks (height 2016). One has timestamp 2 hours before the
    // previous one. It is valid according to BIP54. The other has timestamp 2 hours
    // + 1 second before the previous one. It is invalid according to BIP54.

    // First alternative: a valid header for height 2016.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime -= std::chrono::seconds{2h}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 2016 is exactly 2 hours before block 2015.");
    }
    Assert(header_chain.size() == 2017);

    // Second alternative: an invalid header for height 2016.
    header_chain.pop_back();
    Assert(header_chain.size() == 2016);
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime -= std::chrono::seconds{2h + 1s}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, false, "Block at height 2016 is more than 2 hours before block 2015.");
    }
    Assert(header_chain.size() == 2017);

    // Now mine different 2015th and 2016th blocks (heights 2014 and 2015) to make clear
    // the rule only applies to the first block of a retarget period, not the last block
    // of the previous period.
    header_chain.resize(header_chain.size() - 3);
    Assert(header_chain.size() == 2014);
    // Block at height 2014 is 5 hours after block at height 2013.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime += std::chrono::seconds{5h}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
    Assert(header_chain.size() == 2015);
    // And block at height 2015 is 2h and 1s before block at height 2014. This is valid.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime -= std::chrono::seconds{2h + 1s}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 2015 is more than 2 hours before block 2014.");
    }
    Assert(header_chain.size() == 2016);

    // No need to adapt nBits because it took >2 weeks between block 0 and block 2015
    // and we are already at difficulty 1.
    Assert(header_chain.back().nTime - header_chain.front().nTime >= 14 * 24 * 60 * 60);

    // Now do the same on the "other side". Mine a block at height 2017 that is more
    // than 2 hours before block at height 2016.
    // First a block at height 2016 that is 2h "in the future", i.e. 4h after block
    // 2015 which was itself 2h before block 2014.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime += std::chrono::seconds{4h + 10min}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
    Assert(header_chain.size() == 2017);
    // And block at height 2017 is 2h and 10 minutes before block at height 2016. This is valid.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime -= std::chrono::seconds{2h + 10min}.count();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 2017 is more than 2 hours before block 2016.");
    }
    Assert(header_chain.size() == 2018);

    // Now we get onto testing the fix for the Murch-Zawy attack. To do so we'll make the first
    // block of the second retarget period be well in the future, so we can make the last block
    // of the second retarget period have a lower timestamp and test the failure condition.

    // Drop blocks at heights 2016 and 2017.
    header_chain.resize(header_chain.size() - 2);
    Assert(header_chain.size() == 2016);

    // Now mine 2015 blocks on top of that, where all blocks' are only 1s after the previous
    // block (to avoid hiking up the MTP requirement), except the first block that is 24 hours
    // in the future.
    while (header_chain.size() < 2016 + 2015) {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        if (header_chain.size() == 2016) {
            header.nTime += std::chrono::seconds{24h}.count();
        } else {
            header.nTime += std::chrono::seconds{1s}.count();
        }

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
    Assert(header_chain.size() == 4031); // last block is at height 4030.

    // Now mine a block at height 4031 with a timestamp one second before the timestamp of
    // block at height 2016. This is invalid (diff adjustment period can't be negative).
    const auto& header2016{header_chain.at(2016)};
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime = header2016.nTime - 1;

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, false, "Block at height 4031 has a lower timestamp than block at height 2016.");
    }
    Assert(header_chain.size() == 4032);

    // Now mine an alternative block at height 4031 (last block of second retarget period)
    // with the same timestamp as block at height 2016 (first block of second retarget period).
    // This is valid.
    header_chain.pop_back();
    Assert(header_chain.size() == 4031);
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime = header2016.nTime;

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 4031 has exactly the same timestamp as block at height 2016.");
    }
    Assert(header_chain.size() == 4032);

    // Now mine a block at height 4032 with a timestamp below that of block at height 2016.
    // This is valid because the rule only applies to the last block of a retarget period.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime = header2016.nTime - 1;

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
        RecordTestVector(test_vectors, header_chain, true, "Block at height 4032 has a lower timestamp than block at height 2016.");
    }
    Assert(header_chain.size() == 4033);

    // Dump the test vectors as JSON. TODO: drop now that we always write after each recording?
    WriteVectors(test_vectors);
}

BOOST_AUTO_TEST_SUITE_END()
