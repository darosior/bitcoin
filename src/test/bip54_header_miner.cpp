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
#include <util/check.h>

#include <test/util/setup_common.h>

#include <chrono>
#include <map>
#include <variant>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std::chrono_literals;

//! Uncomment to prefill the headers up to height 2015 instead of mining them.
#define PREFILL_HEADERS

#ifdef PREFILL_HEADERS
#include <test/bip54_premined_headers.h>

template<typename T>
static void FillHeaders(std::vector<CBlockHeader>& header_chain, const T& headers_hex)
{
    for (const auto str: headers_hex) {
        header_chain.emplace_back();
        Assert(DecodeHexBlockHeader(header_chain.back(), std::string{str}));
    }
}

/** Fill the chain with the 2015 first mined headers. */
static void PrefillFirstHeaders(std::vector<CBlockHeader>& header_chain)
{
    static_assert(std::size(FIRST_PREMINED_HEADERS) == 2015); // Blocks up to height 2015 without the genesis block.
    Assert(header_chain.size() == 1); // Only has the genesis block.
    FillHeaders(header_chain, FIRST_PREMINED_HEADERS);
}

/** Fill the chain with the 2015 first mined headers of the second difficulty adjustment period. */
static void PrefillSecondHeaders(std::vector<CBlockHeader>& header_chain)
{
    static_assert(std::size(SECOND_PREMINED_HEADERS) == 2015); // Blocks from height 2016 to height 4030
    Assert(header_chain.size() == 2016); // Has blocks 0 through 2015 (first retarget period)
    FillHeaders(header_chain, SECOND_PREMINED_HEADERS);
}

#endif // PREFILL_HEADERS

BOOST_FIXTURE_TEST_SUITE(bip54_header_miner, BasicTestingSetup)

//! Genesis block header as hex.
constexpr std::string_view GENESIS_HEADER{"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"};

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
        uint64_t steps{0};
        while (!CheckProofOfWorkImpl(header.GetHash(), header.nBits, params)) {
            if (m_found.test()) return;
            if (++header.nNonce == 0) {
                auto arith{UintToArith256(header.hashMerkleRoot)};
                Assert(++steps != STEPS);
                header.hashMerkleRoot = ArithToUint256(arith + steps);
            }
        }
        m_header.store(header);
        (void)m_found.test_and_set();
        m_found.notify_all();
    }

public:
    static constexpr uint64_t STEPS{1LU << 57};

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

struct TestVectorDetails {
    const bool valid;
    const std::string comment;
};

struct TestVectorNode;

//! Inner nodes contain branches, leaf nodes contain metadata about the test vector.
using TestBranches = std::vector<TestVectorNode>;
using TestNodeType = std::variant<TestBranches, TestVectorDetails>;

/** Test vectors are arranged in a tree where nodes contain a chain of headers
 * that is a common ancestor of all their descendant branches. Leaves of the
 * tree are the test vectors, containing a comment describing the test case and
 * a boolean indicating whether the full chain of headers from the root of the
 * tree is valid.
 */
struct TestVectorNode {
    std::vector<CBlockHeader> chain;
    TestNodeType node_type;

    static TestVectorNode Leaf(std::vector<CBlockHeader> headers, TestVectorDetails details)
    {
        return TestVectorNode {
            .chain = headers,
            .node_type = details,
        };
    }

    static TestVectorNode EmptyInner()
    {
        return TestVectorNode {
            .chain = {},
            .node_type = TestBranches{},
        };
    }

    /**
     * Build the tree of test vectors from the chain that all vectors fork from and an ordered
     * list of test vectors and their fork height.
     */
    static TestVectorNode BuildTree(std::vector<CBlockHeader>&& header_chain, std::map<int, std::vector<TestVectorNode>>&& leaves)
    {
        auto root{TestVectorNode::EmptyInner()};
        TestVectorNode* parent{&root};
        int last_height{0};
        Assert(!leaves.empty());
        for (auto it{leaves.begin()}; ; ) {
            Assert(parent->chain.empty());
            const int height{it->first};
            Assert(height > last_height);
            auto first_header{std::make_move_iterator(header_chain.begin() + last_height)};
            auto last_header{std::make_move_iterator(header_chain.begin() + height)};
            parent->chain.insert(parent->chain.end(), first_header, last_header);
            last_height = height;

            auto& parent_branches{*Assert(std::get_if<TestBranches>(&parent->node_type))};
            auto test_vectors{std::move(it->second)};
            for (auto& test: test_vectors) {
                Assert(parent->chain.back().GetHash() == test.chain.front().hashPrevBlock);
                parent_branches.emplace_back(std::move(test));
            }

            if (++it == leaves.end()) {
                break;
            } else {
                auto& parent_branches{*Assert(std::get_if<TestBranches>(&parent->node_type))};
                parent_branches.emplace_back(TestVectorNode::EmptyInner());
                parent = &parent_branches.back();
            }
        }
        return root;
    }

    UniValue GetJson() const
    {
        UniValue node{UniValue::VOBJ};

        UniValue headers_array{UniValue::VARR};
        for (const auto& h: chain) {
            headers_array.push_back(HexHeader(h));
        }
        node.pushKV("block_headers", std::move(headers_array));

        if (const auto* branches = std::get_if<TestBranches>(&node_type)) {
            UniValue branches_array{UniValue::VARR};
            for (const auto& branch: *branches) {
                branches_array.push_back(branch.GetJson());
            }
            node.pushKV("extensions", std::move(branches_array));
        } else {
            const auto& details{*Assert(std::get_if<TestVectorDetails>(&node_type))};
            node.pushKV("valid", details.valid);
            node.pushKV("comment", details.comment);
        }

        return node;
    }
};

static void WriteVectors(const TestVectorNode& test_vectors)
{
    auto json_str{test_vectors.GetJson().write(4)};
    json_str += '\n';
    FILE* file = fsbridge::fopen("bip54_timestamps.json.gen", "w");
    fputs(json_str.c_str(), file);
    fclose(file);
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
    Assert(header_chain.back().GetHash().ToString() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

    // Record each generated test vector throughout.
    std::map<int, std::vector<TestVectorNode>> test_vectors;

    // Optionally skip re-mining the headers for the first difficulty adjustment period.
#ifdef PREFILL_HEADERS
    PrefillFirstHeaders(header_chain);
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
        // Test case recorded below.
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
        // Test case recorded below.
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
#endif // PREFILL_HEADERS
    Assert(header_chain.size() == 2016);

    // Record a couple test cases from this chain. We do it now to make sure it gets recorded
    // even if we start from the prefilled chain.
    test_vectors[41].emplace_back(TestVectorNode::Leaf({header_chain.at(41)}, {true, "Block at height 41 is more than 2 hours before block 40."}));
    test_vectors[2000].emplace_back(TestVectorNode::Leaf({header_chain.at(2000)}, {true, "Block at height 2001 is more than 2 hours before block 2000."}));

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
    }
    Assert(header_chain.size() == 2017);

    // NOTE: blocks down to height 2014 get wiped below, so make sure this test case got them.
    test_vectors[2014].emplace_back(TestVectorNode::Leaf({header_chain.begin() + 2014, header_chain.end()}, {true, "Block at height 2016 is exactly 2 hours before block 2015."}));

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
    }
    Assert(header_chain.size() == 2017);

    // Same as above, fork at height 2014 since those get wiped below.
    test_vectors[2014].emplace_back(TestVectorNode::Leaf({header_chain.begin() + 2014, header_chain.end()}, {false, "Block at height 2016 is more than 2 hours before block 2015."}));

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
    }
    Assert(header_chain.size() == 2016);

    // NOTE: block at height 2015 may be erased if using prefilled headers below, make sure
    // to include it with the test case here.
    test_vectors[2014].emplace_back(TestVectorNode::Leaf({header_chain.begin() + 2014, header_chain.end()}, {true, "Block at height 2015 is more than 2 hours before block 2014."}));

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
    }
    Assert(header_chain.size() == 2018);

    // Same as above, fork at height 2014 because block at height 2015 may be erased by prefilled
    // headers below.
    test_vectors[2014].emplace_back(TestVectorNode::Leaf({header_chain.begin() + 2014, header_chain.end()}, {true, "Block at height 2017 is more than 2 hours before block 2016."}));

    // Now we get onto testing the fix for the Murch-Zawy attack. To do so we'll make the first
    // block of the second retarget period be well in the future, so we can make the last block
    // of the second retarget period have a lower timestamp and test the failure condition.

    // Drop blocks at heights 2016 and 2017.
    header_chain.resize(header_chain.size() - 2);
    Assert(header_chain.size() == 2016);

    // Now mine 2015 blocks on top of that, where all blocks' are only 1s after the previous
    // block (to avoid hiking up the MTP requirement), except the first block that is 24 hours
    // in the future.

    // Optionally allow to skip mining the second difficulty adjustment period. NOTE: block at
    // height 2015 will be different between the two paths.
#ifdef PREFILL_HEADERS
    header_chain.resize(1);
    PrefillFirstHeaders(header_chain);
    PrefillSecondHeaders(header_chain);
    for (auto it{header_chain.begin()}; it + 1 < header_chain.end(); ++it) {
        Assert(it->GetHash() == (it + 1)->hashPrevBlock);
    }
    std::cout << "Prefilled and sanity checked headers up to block height " << header_chain.size() - 1 << std::endl;
#else
    while (header_chain.size() < 2016 + 2015) {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        if (header_chain.size() == 2016) {
            header.nTime += std::chrono::seconds{24h}.count();
        } else if (header_chain.size() == 2017) {
            header.nTime -= std::chrono::seconds{24h}.count();
        } else {
            header.nTime += std::chrono::seconds{1s}.count();
        }

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
#endif
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
    }
    Assert(header_chain.size() == 4032);
    test_vectors[4031].emplace_back(TestVectorNode::Leaf({header_chain.at(4031)}, {false, "Block at height 4031 has a lower timestamp than block at height 2016."}));

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
    }
    Assert(header_chain.size() == 4032);
    test_vectors[4031].emplace_back(TestVectorNode::Leaf({header_chain.at(4031)}, {true, "Block at height 4031 has exactly the same timestamp as block at height 2016."}));

    // Now mine a block at height 4032 with a timestamp below that of block at height 2016.
    // This is valid because the rule only applies to the last block of a retarget period.
    {
        CBlockHeader header{header_chain.back()};
        header.hashPrevBlock = header.GetHash();
        header.nTime = header2016.nTime - 1;

        // This time we need to adjust the target. In the past period, the first and last
        // blocks have the same timestamp, therefore the difficulty will be increased by the
        // maximum of 4x.
        arith_uint256 target;
        target.SetCompact(header.nBits);
        target /= 4;
        header.nBits = target.GetCompact();

        HeaderMiner miner;
        header_chain.emplace_back(miner.Mine(std::move(header), params));
        PrintLastHeader(header_chain);
    }
    Assert(header_chain.size() == 4033);
    test_vectors[4032].emplace_back(TestVectorNode::Leaf({header_chain.at(4032)}, {true, "Block at height 4032 has a lower timestamp than block at height 2016."}));

    // Dump the test vectors as JSON.
    const auto root_node{TestVectorNode::BuildTree(std::move(header_chain), std::move(test_vectors))};
    WriteVectors(root_node);
}

BOOST_AUTO_TEST_SUITE_END()
