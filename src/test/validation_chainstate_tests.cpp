// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
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
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
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
        LOCK(::cs_main);
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(
            pblockone, state, &pindex, true, nullptr, &newblock, true);
        BOOST_CHECK(accepted);
    }

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

//! Add `count` headers on top of `base`, each on top of the previous one, and return their entries.
static std::vector<CBlockIndex*> AddHeaderBranch(ChainstateManager& chainman, const CBlockIndex& base, int count)
{
    std::vector<CBlockIndex*> branch;
    const CBlockIndex* prev{&base};
    for (int i = 0; i < count; ++i) {
        const CBlockHeader header{MineHeader(chainman, *prev)};
        BlockValidationState state;
        BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state));
        CBlockIndex* index{chainman.m_blockman.LookupBlockIndex(header.GetHash())};
        BOOST_REQUIRE(index);
        branch.push_back(index);
        prev = index;
    }
    return branch;
}

//! MarkFailed() flags a block and all its descendants, and moves the best header off the failed branch. It does so
//! in one critical section of the tree lock: someone who looks at the tree in the meantime never sees a descendant
//! of a failed block that is not failed, nor the best header on a failed branch.
BOOST_FIXTURE_TEST_CASE(mark_failed_flags_descendants_and_best_header, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};

    // A branch of headers from the middle of the chain. It has more work than the tip, so its tip is the best header.
    CBlockIndex* const fork_point{WITH_LOCK(::cs_main, return chainman.ActiveChain()[50])};
    const std::vector<CBlockIndex*> branch{AddHeaderBranch(chainman, *fork_point, 300)};
    BOOST_REQUIRE_EQUAL(blockman.GetBestHeader(), branch.back());

    // Fail a block in the middle of the branch. Its descendants must be failed with it, and the best header must
    // fall back to its parent: the most work among the entries that are not failed.
    constexpr int FAILED_POS{100};
    CBlockIndex* const failed{branch[FAILED_POS]};
    std::atomic<bool> observer_ready{false};
    std::atomic<bool> done{false};
    std::atomic<int> inconsistent_views{0};
    std::thread observer([&] {
        observer_ready = true;
        while (!done) {
            LOCK(blockman.m_tree_mutex);
            const bool failed_is_failed{(blockman.GetValidityStatusLocked(*failed) & BLOCK_FAILED_VALID) != 0};
            for (size_t i{FAILED_POS}; i < branch.size(); ++i) {
                if (((blockman.GetValidityStatusLocked(*branch[i]) & BLOCK_FAILED_VALID) != 0) != failed_is_failed) ++inconsistent_views;
            }
            const CBlockIndex* const best{blockman.GetBestHeaderLocked()};
            if (failed_is_failed ? best->GetAncestor(failed->nHeight) == failed : best != branch.back()) ++inconsistent_views;
        }
    });
    while (!observer_ready) std::this_thread::yield();
    {
        LOCK(::cs_main);
        blockman.MarkFailed(*failed, chainman.ActiveChain().Tip());
    }
    done = true;
    observer.join();
    BOOST_CHECK_EQUAL(inconsistent_views, 0);

    for (size_t i{0}; i < branch.size(); ++i) {
        BOOST_CHECK_EQUAL((blockman.GetValidityStatus(*branch[i]) & BLOCK_FAILED_VALID) != 0, i >= FAILED_POS);
    }
    BOOST_CHECK_EQUAL(blockman.GetBestHeader(), branch[FAILED_POS - 1]);

    // Resetting the failure clears the flags again, and the best header goes back to the end of the branch.
    {
        LOCK(::cs_main);
        const auto cleared{blockman.ResetFailed(*failed, chainman.ActiveChain().Tip())};
        BOOST_CHECK_EQUAL(cleared.size(), branch.size() - FAILED_POS);
    }
    for (const CBlockIndex* index : branch) {
        BOOST_CHECK(!(blockman.GetValidityStatus(*index) & BLOCK_FAILED_VALID));
    }
    BOOST_CHECK_EQUAL(blockman.GetBestHeader(), branch.back());
}

//! A setup that does not check the block index after every operation. CheckBlockIndex() takes cs_main, which would
//! get in the way of tests about code that does not need it.
struct TestChain100SetupNoCheckBlockIndex : public TestChain100Setup {
    TestChain100SetupNoCheckBlockIndex() : TestChain100Setup{ChainType::REGTEST, {.check_block_index = 0}} {}
};

//! Hold `mutex` on one thread, and check that a header is accepted on another one in the meantime.
template <typename MutexType>
static void CheckHeaderAcceptedWhileLocked(ChainstateManager& chainman, MutexType& mutex)
{
    const CBlockIndex* const tip{WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    const CBlockHeader header{MineHeader(chainman, *tip)};

    std::promise<void> locked;
    std::promise<void> release;
    std::thread holder{[&] {
        LOCK(mutex);
        locked.set_value();
        release.get_future().wait();
    }};
    locked.get_future().wait();

    // If accepting a header needed the lock, this would not finish before the lock is released below.
    std::future<bool> accepted{std::async(std::launch::async, [&] {
        BlockValidationState state;
        return chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state);
    })};
    const bool finished{accepted.wait_for(std::chrono::seconds{30}) == std::future_status::ready};
    release.set_value();
    holder.join();

    BOOST_REQUIRE(finished);
    BOOST_CHECK(accepted.get());
    BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(header.GetHash()) != nullptr);
}

//! Headers are accepted while another thread holds cs_main, which is held while a block is connected.
BOOST_FIXTURE_TEST_CASE(headers_are_accepted_while_cs_main_is_held, TestChain100SetupNoCheckBlockIndex)
{
    CheckHeaderAcceptedWhileLocked(*Assert(m_node.chainman), ::cs_main);
}

//! Headers are accepted while another thread holds the store lock, which is held while a block is written to
//! disk or a block file is synced.
BOOST_FIXTURE_TEST_CASE(headers_are_accepted_while_store_lock_is_held, TestChain100SetupNoCheckBlockIndex)
{
    auto& chainman{*Assert(m_node.chainman)};
    CheckHeaderAcceptedWhileLocked(chainman, chainman.m_blockman.m_store_mutex);
}

//! A header built on a failed block is rejected with bad-prevblk and not added to the block index, and the best
//! header does not descend from the failed block.
BOOST_FIXTURE_TEST_CASE(header_on_failed_block_is_rejected, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const CBlock block{CreateBlock({}, CScript{} << OP_TRUE)};
    const CBlockHeader& header{block};
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ProcessNewBlockHeaders({&header, 1}, /*min_pow_checked=*/true, state));
    CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
    BOOST_REQUIRE(pindex);
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(state, pindex));
    BOOST_CHECK(chainman.m_blockman.GetValidityStatus(*pindex) & BLOCK_FAILED_VALID);

    const CBlockHeader child{MineHeader(chainman, *pindex)};
    BlockValidationState child_state;
    BOOST_CHECK(!chainman.ProcessNewBlockHeaders({&child, 1}, /*min_pow_checked=*/true, child_state));
    BOOST_CHECK_EQUAL(child_state.GetRejectReason(), "bad-prevblk");

    BOOST_CHECK(!chainman.m_blockman.LookupBlockIndex(child.GetHash()));
    const CBlockIndex* best{chainman.m_blockman.GetBestHeader()};
    BOOST_REQUIRE(best);
    BOOST_CHECK(best->GetAncestor(pindex->nHeight) != pindex);
}

//! Records the BlockChecked notifications: the hash of the block, and "valid" or the rejection reason.
struct BlockCheckedRecorder final : public CValidationInterface {
    std::vector<std::pair<uint256, std::string>> m_checked;
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
    {
        m_checked.emplace_back(block->GetHash(), state.IsValid() ? "valid" : state.GetRejectReason());
    }
};

//! Replace the coinbase of `block`, fix up its merkle root and solve it.
static std::shared_ptr<const CBlock> ReplaceCoinbase(const ChainstateManager& chainman, CBlock block, const CScript& script_sig, const std::optional<uint256>& merkle_root = std::nullopt)
{
    CMutableTransaction coinbase{*block.vtx[0]};
    coinbase.vin[0].scriptSig = script_sig;
    block.vtx[0] = MakeTransactionRef(coinbase);
    block.hashMerkleRoot = merkle_root ? *merkle_root : BlockMerkleRoot(block);
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) ++block.nNonce;
    return std::make_shared<const CBlock>(block);
}

//! AcceptNewBlock() followed by ActivateNewBlock() does what ProcessNewBlock() does: the same result, the same
//! new_block, and the same BlockChecked notification, which is sent at the same point of the processing.
BOOST_FIXTURE_TEST_CASE(accept_and_activate_block_like_process_new_block, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto recorder_ptr{std::make_shared<BlockCheckedRecorder>()};
    BlockCheckedRecorder& recorder{*recorder_ptr};
    m_node.validation_signals->RegisterSharedValidationInterface(recorder_ptr);
    const int height{WITH_LOCK(::cs_main, return chainman.ActiveHeight())};

    // A valid block. It is accepted and stored, and BlockChecked is only sent when it is connected.
    const auto valid{std::make_shared<const CBlock>(CreateBlock({}, CScript{} << OP_TRUE))};
    {
        const auto accepted{chainman.AcceptNewBlock(valid, /*force_processing=*/true, /*min_pow_checked=*/true)};
        BOOST_CHECK(accepted.accepted);
        BOOST_CHECK(accepted.new_block);
        BOOST_CHECK(recorder.m_checked.empty());
        BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveHeight()), height);
        BOOST_CHECK(chainman.ActivateNewBlock(valid));
        BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveHeight()), height + 1);
        BOOST_REQUIRE_EQUAL(recorder.m_checked.size(), 1U);
        BOOST_CHECK(recorder.m_checked[0] == std::make_pair(valid->GetHash(), std::string{"valid"}));
    }

    // The same block again is accepted, but it is not new, and it is not checked again.
    {
        recorder.m_checked.clear();
        const auto accepted{chainman.AcceptNewBlock(valid, /*force_processing=*/true, /*min_pow_checked=*/true)};
        BOOST_CHECK(accepted.accepted);
        BOOST_CHECK(!accepted.new_block);
        BOOST_CHECK(chainman.ActivateNewBlock(valid));
        BOOST_CHECK(recorder.m_checked.empty());
        bool new_block{true};
        BOOST_CHECK(chainman.ProcessNewBlock(valid, true, true, &new_block));
        BOOST_CHECK(!new_block);
        BOOST_CHECK(recorder.m_checked.empty());
    }

    // A block that fails CheckBlock() (here, its merkle root) is rejected by the first half, which reports it.
    const CBlock template_block{CreateBlock({}, CScript{} << OP_TRUE)};
    const auto bad_merkle_root{ReplaceCoinbase(chainman, template_block, template_block.vtx[0]->vin[0].scriptSig, uint256::ONE)};
    // A block that fails AcceptBlock() (here, the height in its coinbase).
    const auto bad_height{ReplaceCoinbase(chainman, template_block, CScript{} << 1 << OP_0)};
    // The same two, as different blocks since a block that failed AcceptBlock() is known to be invalid afterwards.
    const auto bad_merkle_root2{ReplaceCoinbase(chainman, template_block, template_block.vtx[0]->vin[0].scriptSig, uint256::ZERO)};
    const auto bad_height2{ReplaceCoinbase(chainman, template_block, CScript{} << 2 << OP_0)};
    for (const auto& [block, block2, reason] : {std::tuple{bad_merkle_root, bad_merkle_root2, "bad-txnmrklroot"}, std::tuple{bad_height, bad_height2, "bad-cb-height"}}) {
        recorder.m_checked.clear();
        const auto accepted{chainman.AcceptNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true)};
        BOOST_CHECK(!accepted.accepted);
        BOOST_CHECK(!accepted.new_block);
        BOOST_REQUIRE_EQUAL(recorder.m_checked.size(), 1U);
        BOOST_CHECK(recorder.m_checked[0] == std::make_pair(block->GetHash(), std::string{reason}));

        // ProcessNewBlock() gives the same answer.
        recorder.m_checked.clear();
        bool new_block{true};
        BOOST_CHECK(!chainman.ProcessNewBlock(block2, true, true, &new_block));
        BOOST_CHECK(!new_block);
        BOOST_REQUIRE_EQUAL(recorder.m_checked.size(), 1U);
        BOOST_CHECK(recorder.m_checked[0] == std::make_pair(block2->GetHash(), std::string{reason}));
    }
    m_node.validation_signals->UnregisterSharedValidationInterface(recorder_ptr);
}

BOOST_AUTO_TEST_SUITE_END()
