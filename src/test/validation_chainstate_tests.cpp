// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

class CTxMemPool;

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches)
{
    ChainstateManager& manager = *Assert(m_node.chainman);
    CTxMemPool& mempool = *Assert(m_node.mempool);
    Chainstate& c1 = WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /*cache_size_bytes=*/8_MiB, /*in_memory=*/true, /*should_wipe=*/false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(8_MiB));
    BOOST_REQUIRE(manager.LoadGenesisBlock()); // Need at least one block loaded to be able to flush caches

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(m_rng, c1.CoinsTip());

        // Set a meaningless bestblock value in the coinsview cache - otherwise we won't
        // flush during ResizecoinsCaches() and will subsequently hit an assertion.
        c1.CoinsTip().SetBestBlock(m_rng.rand256());

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            16_MiB, // upsizing the coinsview cache
            4_MiB // downsizing the coinsdb cache
        );

        // View should still have the coin cached, since we haven't destructed the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            4_MiB, // downsizing the coinsview cache
            8_MiB // upsizing the coinsdb cache
        );

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

BOOST_FIXTURE_TEST_CASE(connect_tip_does_not_cache_inputs_on_failed_connect, TestChain100Setup)
{
    Chainstate& chainstate{Assert(m_node.chainman)->ActiveChainstate()};

    COutPoint outpoint;
    {
        LOCK(cs_main);
        outpoint = AddTestCoin(m_rng, chainstate.CoinsTip());
        chainstate.CoinsTip().Flush(/*reallocate_cache=*/false);
    }

    CMutableTransaction tx;
    tx.vin.emplace_back(outpoint);
    tx.vout.emplace_back(MAX_MONEY, CScript{} << OP_TRUE);

    const auto tip{WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash())};
    const CBlock block{CreateBlock({tx}, CScript{} << OP_TRUE)};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(block), true, true, nullptr));

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(tip, chainstate.m_chain.Tip()->GetBlockHash()); // block rejected
    BOOST_CHECK(!chainstate.CoinsTip().HaveCoinInCache(outpoint));    // input not cached
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const auto get_notify_tip{[&]() {
        LOCK(m_node.notifications->m_tip_block_mutex);
        BOOST_REQUIRE(m_node.notifications->TipBlock());
        return *m_node.notifications->TipBlock();
    }};
    uint256 curr_tip = get_notify_tip();

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
    // be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlock(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/ true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.CurrentChainstate().m_from_snapshot_blockhash));

    curr_tip = get_notify_tip();

    // Mine a new block on top of the activated snapshot chainstate.
    mineBlocks(1);  // Defined in TestChain100Setup.

    // After adding some blocks to the snapshot tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);

    curr_tip = get_notify_tip();

    Chainstate& background_cs{*Assert(WITH_LOCK(::cs_main, return chainman.HistoricalChainstate()))};

    // Append the first block to the background chain.
    BlockValidationState state;
    CBlockIndex* pindex = nullptr;
    const CChainParams& chainparams = Params();
    bool newblock = false;

    // TODO: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
    }
    bool accepted = chainman.AcceptBlock(
        pblockone, state, &pindex, true, nullptr, &newblock, true);
    BOOST_CHECK(accepted);

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(), pblockone->GetHash());

    // get_notify_tip() should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, get_notify_tip());
}

//! Mine a header on top of `prev`.
static CBlockHeader MineHeader(const ChainstateManager& chainman, const CBlockIndex& prev)
{
    CBlockHeader header;
    header.nVersion = prev.nVersion;
    header.hashPrevBlock = prev.GetBlockHash();
    header.hashMerkleRoot = uint256::ONE;
    header.nTime = prev.nTime + 1;
    header.nBits = GetNextWorkRequired(&prev, &header, chainman.GetConsensus());
    while (!CheckProofOfWork(header.GetHash(), header.nBits, chainman.GetConsensus())) ++header.nNonce;
    return header;
}

//! A header built on an invalidated block is rejected, and the best header does not descend from the invalid block.
BOOST_FIXTURE_TEST_CASE(header_child_of_invalidated_block, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const CBlock block{CreateBlock({}, CScript{} << OP_TRUE)};
    const CBlockHeader& header{block};
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state));
    CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
    BOOST_REQUIRE(pindex);
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(state, pindex));
    BOOST_CHECK(WITH_LOCK(chainman.m_blockman.m_block_storage_mutex, return chainman.m_blockman.m_blocks_being_invalidated.empty()));

    const CBlockHeader child{MineHeader(chainman, *pindex)};
    BlockValidationState child_state;
    BOOST_CHECK(!chainman.ProcessNewBlockHeaders({&child, 1}, /*min_pow_checked=*/true, child_state));
    BOOST_CHECK_EQUAL(child_state.GetRejectReason(), "bad-prevblk");

    BOOST_CHECK(!chainman.m_blockman.LookupBlockIndex(child.GetHash()));
    const CBlockIndex* best{chainman.m_blockman.GetBestHeader()};
    BOOST_REQUIRE(best);
    BOOST_CHECK(best->GetAncestor(pindex->nHeight) != pindex);
}

//! While a block is being invalidated, headers building on it or on its descendants are rejected,
//! since they would not be marked invalid with it. Headers building elsewhere are accepted.
BOOST_FIXTURE_TEST_CASE(header_on_block_being_invalidated, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    const CBlockIndex* invalidating{tip->pprev};

    // The state InvalidateBlock() leaves between two disconnections.
    WITH_LOCK(blockman.m_block_storage_mutex, blockman.m_blocks_being_invalidated.push_back(invalidating));

    for (const CBlockIndex* prev : {invalidating, tip}) {
        const CBlockHeader header{MineHeader(chainman, *prev)};
        BlockValidationState state;
        BOOST_CHECK(!chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-prevblk");
        BOOST_CHECK(!blockman.LookupBlockIndex(header.GetHash()));
    }

    const CBlockHeader fork{MineHeader(chainman, *invalidating->pprev)};
    BlockValidationState state;
    BOOST_CHECK(chainman.ProcessNewBlockHeaders({&fork, 1}, /*min_pow_checked=*/true, state));
    BOOST_CHECK(blockman.LookupBlockIndex(fork.GetHash()));

    WITH_LOCK(blockman.m_block_storage_mutex, blockman.m_blocks_being_invalidated.clear());
}

BOOST_FIXTURE_TEST_CASE(processnewblock_concurrent_storage, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};

    // The number of blocks stored in the block files, which must not depend on how many times
    // a block was delivered.
    const auto count_stored_blocks{[&] {
        LOCK(chainman.m_blockman.m_block_storage_mutex);
        uint64_t total{0};
        for (size_t file{0};; ++file) {
            try {
                total += chainman.m_blockman.GetBlockFileInfo(file)->nBlocks;
            } catch (const std::out_of_range&) {
                return total;
            }
        }
    }};

    constexpr int NUM_THREADS{4};
    constexpr int NUM_BLOCKS{4};
    for (int round{0}; round < 3; ++round) {
        // Distinct blocks competing at the same height, on the current tip.
        std::vector<std::shared_ptr<const CBlock>> blocks;
        for (int i{0}; i < NUM_BLOCKS; ++i) {
            blocks.push_back(std::make_shared<const CBlock>(CreateBlock({}, CScript() << round << i)));
        }
        const int height_before{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Height())};
        const uint64_t stored_before{count_stored_blocks()};

        // Each thread delivers every block, starting from a different one, so that the
        // threads race on the same blocks.
        std::vector<std::vector<int>> accepted(NUM_THREADS, std::vector<int>(NUM_BLOCKS));
        std::vector<std::vector<int>> stored(NUM_THREADS, std::vector<int>(NUM_BLOCKS));
        std::vector<std::thread> threads;
        for (int t{0}; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t] {
                for (int i{0}; i < NUM_BLOCKS; ++i) {
                    const int idx{(i + t) % NUM_BLOCKS};
                    bool new_block{false};
                    accepted[t][idx] = chainman.ProcessNewBlock(blocks[idx], /*force_processing=*/true, /*min_pow_checked=*/true, &new_block);
                    stored[t][idx] = new_block;
                }
            });
        }
        for (auto& thread : threads) {
            thread.join();
        }

        for (int idx{0}; idx < NUM_BLOCKS; ++idx) {
            int stored_by{0};
            for (int t{0}; t < NUM_THREADS; ++t) {
                BOOST_CHECK(accepted[t][idx]);
                stored_by += stored[t][idx];
            }
            // Exactly one call stored each block, even when several were in progress at once.
            BOOST_CHECK_EQUAL(stored_by, 1);
        }
        BOOST_CHECK_EQUAL(count_stored_blocks() - stored_before, static_cast<uint64_t>(NUM_BLOCKS));
        // One of the competing blocks extends the chain.
        BOOST_CHECK_EQUAL(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Height()), height_before + 1);
    }
}

//! A block invalidated while its data is written without cs_main must not be recorded as stored.
BOOST_FIXTURE_TEST_CASE(invalidate_block_while_storing, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const CBlock block{CreateBlock({}, CScript{} << OP_TRUE)};
    const auto pblock{std::make_shared<const CBlock>(block)};
    const CBlockHeader& header{block};

    BlockValidationState state;
    const CBlockIndex* header_index{nullptr};
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state, &header_index));

    CBlockIndex* pindex{nullptr};
    std::optional<int> store_height;
    bool new_block{false};
    {
        LOCK(::cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE(pindex);
        BOOST_REQUIRE(chainman.PrepareAcceptBlock(pblock, state, pindex, /*fRequested=*/true, &new_block, /*min_pow_checked=*/true, store_height));
        BOOST_CHECK(new_block);
    }

    // The block passed validation and is now written to disk without cs_main. Invalidate it in the meantime.
    chainman.ActiveChainstate().InvalidateBlock(state, pindex);

    BOOST_CHECK(!chainman.StoreAcceptedBlock(pblock, state, pindex, *store_height, /*dbp=*/nullptr));
    BOOST_CHECK_EQUAL(state.GetResult(), BlockValidationResult::BLOCK_CACHED_INVALID);

    // The data must not be recorded, since the block cannot be made valid again later without it being
    // re-downloaded: BLOCK_HAVE_DATA would prevent that, while BLOCK_VALID_TRANSACTIONS is never set.
    LOCK(::cs_main);
    BOOST_CHECK(chainman.m_blockman.GetStatus(*pindex) & BLOCK_FAILED_VALID);
    BOOST_CHECK(!(chainman.m_blockman.GetStatus(*pindex) & BLOCK_HAVE_DATA));
    BOOST_CHECK_EQUAL(chainman.m_blockman.GetNumTx(*pindex), 0U);
}

//! A caller delivering a block that another caller is still writing waits for that write, and then
//! reports the block as already known, rather than reporting success before it is stored.
BOOST_FIXTURE_TEST_CASE(processnewblock_waits_for_store, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const CBlock block{CreateBlock({}, CScript{} << OP_TRUE)};
    const auto pblock{std::make_shared<const CBlock>(block)};
    const CBlockHeader& header{block};

    BlockValidationState state;
    const CBlockIndex* header_index{nullptr};
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state, &header_index));

    // The first caller has validated the block and is writing it to disk, but has not recorded it yet.
    CBlockIndex* pindex{nullptr};
    std::optional<int> store_height;
    {
        LOCK(::cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE(pindex);
        BOOST_REQUIRE(chainman.PrepareAcceptBlock(pblock, state, pindex, /*fRequested=*/true, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true, store_height));
        BOOST_REQUIRE(store_height);
    }

    // A second caller delivers the same block meanwhile. It must not return before the first store is recorded.
    std::atomic<bool> second_done{false};
    bool second_accepted{false};
    bool second_new_block{true};
    std::thread second{[&] {
        bool new_block{false};
        second_accepted = chainman.ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block);
        second_new_block = new_block;
        second_done = true;
    }};
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    BOOST_CHECK(!second_done);

    BOOST_CHECK(chainman.StoreAcceptedBlock(pblock, state, pindex, *store_height, /*dbp=*/nullptr));
    second.join();

    BOOST_CHECK(second_accepted);
    BOOST_CHECK(!second_new_block);
    LOCK(::cs_main);
    BOOST_CHECK(chainman.m_blockman.GetStatus(*pindex) & BLOCK_HAVE_DATA);
}

//! WaitForBlockStore() returns once a block being stored is recorded in the block index, so that a
//! request for a block announced before it was written can be answered.
BOOST_FIXTURE_TEST_CASE(wait_for_block_store, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto pblock{std::make_shared<const CBlock>(CreateBlock({}, CScript{} << OP_TRUE))};
    const CBlockHeader& header{*pblock};
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state));

    // Returns right away for a block that is not being stored, known or not.
    chainman.WaitForBlockStore(pblock->GetHash());
    chainman.WaitForBlockStore(uint256::ONE);

    CBlockIndex* pindex{nullptr};
    std::optional<int> store_height;
    {
        LOCK(::cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(pblock->GetHash());
        BOOST_REQUIRE(chainman.PrepareAcceptBlock(pblock, state, pindex, /*fRequested=*/true, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true, store_height));
        BOOST_REQUIRE(store_height);
    }

    std::atomic<bool> waited{false};
    bool stored_when_done{false};
    std::thread waiter{[&] {
        chainman.WaitForBlockStore(pblock->GetHash());
        stored_when_done = chainman.m_blockman.GetStatus(*pindex) & BLOCK_HAVE_DATA;
        waited = true;
    }};
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    BOOST_CHECK(!waited);

    BOOST_CHECK(chainman.StoreAcceptedBlock(pblock, state, pindex, *store_height, /*dbp=*/nullptr));
    waiter.join();
    BOOST_CHECK(waited);
    // The block is recorded by the time the wait is over.
    BOOST_CHECK(stored_when_done);
}

//! A block invalidated while its data is written must be acceptable again once it is reconsidered.
BOOST_FIXTURE_TEST_CASE(reconsider_after_invalidate_while_storing, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const CBlock block{CreateBlock({}, CScript{} << OP_TRUE)};
    const auto pblock{std::make_shared<const CBlock>(block)};
    const CBlockHeader& header{block};
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state));

    CBlockIndex* pindex{nullptr};
    std::optional<int> store_height;
    {
        LOCK(::cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE(chainman.PrepareAcceptBlock(pblock, state, pindex, /*fRequested=*/true, nullptr, /*min_pow_checked=*/true, store_height));
    }
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(state, pindex));
    BOOST_CHECK(!chainman.StoreAcceptedBlock(pblock, state, pindex, *store_height, /*dbp=*/nullptr));

    // Clearing the failure flags also recalculates the best header.
    {
        LOCK(::cs_main);
        chainman.ActiveChainstate().ResetBlockFailureFlags(pindex);
    }
    BOOST_REQUIRE(chainman.ActiveChainstate().ActivateBestChain(state));
    bool new_block{false};
    BOOST_CHECK(chainman.ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(new_block);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()), pindex);
}

BOOST_AUTO_TEST_SUITE_END()
