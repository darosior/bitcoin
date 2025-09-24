// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/system.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <versionbits.h>

#include <test/util/setup_common.h>

#include <chrono>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(bip54_block_miner, BasicTestingSetup)

//! Genesis block as hex.
constexpr std::string_view GENESIS_BLOCK{"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"};

struct Nonces {
    uint32_t nonce;
    int64_t extranonce;
};

static void SetExtraNonce(CBlock& block, int height, int64_t extranonce)
{
    CMutableTransaction coinbase_tx{*block.vtx.at(0)};
    coinbase_tx.vin.at(0).scriptSig = CScript{} << height << extranonce;
    block.vtx[0] = MakeTransactionRef(coinbase_tx);
    block.hashMerkleRoot = BlockMerkleRoot(block);
}

/**
 * A multithreaded miner.
 * Given a block, it will launch as many threads as the CPU supports and grind the nonce and coinbase
 * extranonce. The extranonce space given to each thread is set by the STEP constant.
 */
class Miner {
    std::vector<std::thread> m_mining_threads;
    std::atomic_flag m_found{};
    std::atomic<Nonces> m_nonces{};

    void MineOne(CBlock block, int height, Consensus::Params params, int64_t extranonce)
    {
        while (!CheckProofOfWorkImpl(block.GetHash(), block.nBits, params)) {
            if (m_found.test()) return;
            if (++block.nNonce == 0) {
                Assert(++extranonce <= STEPS);
                SetExtraNonce(block, height, extranonce);
            }
        }
        m_nonces.store({.nonce = block.nNonce, .extranonce = extranonce});
        (void)m_found.test_and_set();
        m_found.notify_all();
    }

public:
    static constexpr int64_t STEPS{100'000};

    Nonces Mine(CBlock block, int height, Consensus::Params params)
    {
        auto num_cores{std::thread::hardware_concurrency()};
        for (uint32_t i{0}; i < num_cores; ++i) {
            block.nNonce = 0;
            int64_t extranonce{STEPS * i};
            SetExtraNonce(block, height, extranonce);
            m_mining_threads.emplace_back(&Miner::MineOne, this, block, height, params, extranonce);
        }

        m_found.wait(false);
        for (auto& thread: m_mining_threads) {
            thread.join();
        }

        return m_nonces.load();
    }
};

static std::string HexBlock(const CBlock& block)
{
    DataStream stream{};
    stream << TX_WITH_WITNESS(block);
    return HexStr(stream);
}

static void PrintLastBlock(const std::vector<CBlock>& chain)
{
    std::cout << "Mined block at height " << chain.size() - 1 << ": " << HexBlock(chain.back()) << std::endl;
}

/** A BIP54 coinbase-related test vector. */
struct TestVector {
    //! The chain of blocks to be tested against the new rules.
    const std::vector<CBlock> chain;
    //! Whether the chain is valid according to the new rules.
    const bool valid;
    //! Description of this specific test case.
    const std::string comment;

    explicit TestVector(std::vector<CBlock> blocks, bool val, std::string com):
        chain{std::move(blocks)}, valid{val}, comment{std::move(com)} {}

    UniValue GetJson() const
    {
        UniValue chain_json{UniValue::VARR};
        for (const auto& h: chain) {
            chain_json.push_back(HexBlock(h));
        }

        UniValue json{UniValue::VOBJ};
        json.pushKV("block_chain", chain_json);
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
    auto json_str{json_vectors.write(4)};
    json_str += '\n';
    FILE* file = fsbridge::fopen("bip54_coinbases.json.gen", "w");
    fputs(json_str.c_str(), file);
    fclose(file);
}

static void RecordTestVector(std::vector<TestVector>& test_vectors, std::vector<CBlock>& block_chain, bool valid, std::string comment)
{
    test_vectors.emplace_back(block_chain, valid, std::move(comment));
    WriteVectors(test_vectors); // Write the updated test vectors to disk.
}

/**
 * Test the BIP54 rule mandating coinbase transactions be timelocked at the block's height.
 *
 * This test mines a short chain of valid mainnet blocks up to height 3, and mine different blocks
 * height 4 with various values for the coinbase transaction's nLockTime and nSequence.
 */
BOOST_AUTO_TEST_CASE(mine_block_chain)
{
    SelectParams(ChainType::MAIN);
    const auto params{Params().GetConsensus()};

    // Start from the mainnet genesis block.
    std::vector<CBlock> chain;
    chain.emplace_back();
    Assert(DecodeHexBlk(chain.back(), std::string{GENESIS_BLOCK}));

    // Record each generated test vector throughout.
    std::vector<TestVector> test_vectors;

    // Mine a few blocks to not have the test vectors be on the very first non-genesis
    // block in the chain.
    for (int height{1}; height < 4; ++height) {
        CBlock block{chain.back()};
        block.hashPrevBlock = block.GetHash();
        block.nTime += std::chrono::seconds{10min}.count();
        //block.nVersion = VERSIONBITS_TOP_BITS;
        Assert(block.vtx.size() == 1);
        CMutableTransaction ctx{*block.vtx.at(0)};
        ctx.nLockTime = static_cast<uint32_t>(height) - 1;
        ctx.vin.at(0).nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
        block.vtx[0] = MakeTransactionRef(ctx);

        // Miner takes care of Merkle root and height in scriptSig.
        Miner miner;
        const auto nonces{miner.Mine(block, height, params)};
        block.nNonce = nonces.nonce;
        SetExtraNonce(block, height, nonces.extranonce);
        chain.emplace_back(std::move(block));
        PrintLastBlock(chain);
    }
    Assert(chain.size() == 4);

    // The block we are going to mine with different locktime/sequence values.
    constexpr int height{4};
    CBlock block{chain.back()};
    block.hashPrevBlock = block.GetHash();
    block.nTime += std::chrono::seconds{10min}.count();

    // Various nLockTime/nSequence values for block at height 4.
    static const struct {
        uint32_t nLockTime;
        uint32_t nSequence;
        bool valid;
        std::string_view comment;
    } TIMELOCK_VALUES[]{
        {.nLockTime = 21, .nSequence = CTxIn::MAX_SEQUENCE_NONFINAL, .valid = false, .comment = "Block at height 4 with coinbase's nLockTime set to 21 and non-final nSequence."},
        {.nLockTime = 4, .nSequence = 4242, .valid = false, .comment = "Block at height 4 with coinbase's nLockTime set to 4 and non-final nSequence."},
        {.nLockTime = 2, .nSequence = CTxIn::MAX_SEQUENCE_NONFINAL, .valid = false, .comment = "Block at height 4 with coinbase's nLockTime set to 2 and non-final nSequence."},
        {.nLockTime = 3, .nSequence = 213243, .valid = true, .comment = "Block at height 4 with coinbase's nLockTime set to 3 and non-final nSequence."},
        {.nLockTime = 3, .nSequence = CTxIn::MAX_SEQUENCE_NONFINAL, .valid = true, .comment = "Block at height 4 with coinbase's nLockTime set to 3 and maximum non-final nSequence."},
        {.nLockTime = 2, .nSequence = CTxIn::SEQUENCE_FINAL, .valid = false, .comment = "Block at height 4 with coinbase's nLockTime set to 2 and final nSequence."},
        {.nLockTime = block.nTime - 1, .nSequence = CTxIn::MAX_SEQUENCE_NONFINAL, .valid = false, .comment = "Block at height 4 with coinbase's nLockTime set to block's nTime minus 1 and maximum non-final nSequence."},
    };

    // For each pair of nLockTime/nSequence value, mine a different block at height 4 and record
    // the chain as a test vector.
    for (const auto tl_values: TIMELOCK_VALUES) {
        CMutableTransaction ctx{*block.vtx.at(0)};
        ctx.nLockTime = tl_values.nLockTime;
        ctx.vin.at(0).nSequence = tl_values.nSequence;
        block.vtx[0] = MakeTransactionRef(ctx);

        // Miner takes care of Merkle root and height in scriptSig.
        Miner miner;
        const auto nonces{miner.Mine(block, height, params)};
        block.nNonce = nonces.nonce;
        SetExtraNonce(block, height, nonces.extranonce);

        chain.emplace_back(block);
        PrintLastBlock(chain);
        RecordTestVector(test_vectors, chain, /*valid=*/tl_values.valid, std::string{tl_values.comment});
        chain.pop_back();
    }
}

BOOST_AUTO_TEST_SUITE_END()
