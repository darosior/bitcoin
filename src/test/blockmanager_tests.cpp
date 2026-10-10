// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <set>
#include <thread>
#include <vector>

using kernel::CBlockFileInfo;
using node::STORAGE_HEADER_BYTES;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;
using node::UNDOFILE_CHUNK_SIZE;

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    // simulate adding a genesis block normally
    LOCK(::cs_main);
    const FlatFilePos genesis_pos{blockman.WriteBlock(params->GenesisBlock(), 0)};
    blockman.FinishBlockWrite(genesis_pos);
    BOOST_CHECK_EQUAL(genesis_pos.nPos, STORAGE_HEADER_BYTES);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    const FlatFilePos pos{0, STORAGE_HEADER_BYTES};
    blockman.UpdateBlockInfo(params->GenesisBlock(), 0, pos);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.WriteBlock(params->GenesisBlock(), 1)};
    blockman.FinishBlockWrite(actual);
    BOOST_CHECK_EQUAL(actual.nPos, STORAGE_HEADER_BYTES + ::GetSerializeSize(TX_WITH_WITNESS(params->GenesisBlock())) + STORAGE_HEADER_BYTES);
}

//! The files of the blocks and undo data recorded in the block index are synced by the next flush, which
//! syncs them before it writes the index.
BOOST_FIXTURE_TEST_CASE(flush_syncs_files_of_indexed_data, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};
    chainman.ActiveChainstate().ForceFlushStateToDisk();
    BOOST_CHECK(blockman.GetUnsyncedBlockFiles().empty());
    BOOST_CHECK(blockman.GetUnsyncedUndoFiles().empty());

    // The block and its undo data are recorded in the block index when it is processed and connected.
    const CBlock block{CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()))};
    const int file{blockman.GetBlockPos(*Assert(blockman.LookupBlockIndex(block.GetHash()))).nFile};
    BOOST_CHECK((blockman.GetUnsyncedBlockFiles() == std::set<int>{file}));
    BOOST_CHECK((blockman.GetUnsyncedUndoFiles() == std::set<int>{file}));

    chainman.ActiveChainstate().ForceFlushStateToDisk();
    BOOST_CHECK(blockman.GetUnsyncedBlockFiles().empty());
    BOOST_CHECK(blockman.GetUnsyncedUndoFiles().empty());
}

struct FastPruneSetup : public TestChain100Setup {
    FastPruneSetup() : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-fastprune"}}} {}
};

//! When the undo data keeps up with the blocks, the undo file of a block file that is left behind is
//! truncated to its data once the next block is connected.
BOOST_FIXTURE_TEST_CASE(undo_file_finalized_when_keeping_up, FastPruneSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};
    const auto tip_file{[&] { return blockman.GetBlockPos(*WITH_LOCK(::cs_main, return chainman.ActiveTip())).nFile; }};
    const int first_file{tip_file()};
    // Large outputs fill the 64 KiB block files of -fastprune with a few blocks. Each block is connected
    // right after it is written, so the undo data keeps up with the blocks.
    const CScript big_output{CScript() << OP_RETURN << std::vector<unsigned char>(8000)};
    while (tip_file() == first_file) {
        CreateAndProcessBlock({}, big_output);
    }

    const uint32_t undo_size{WITH_LOCK(blockman.m_block_storage_mutex, return blockman.GetBlockFileInfo(first_file)->nUndoSize)};
    // The file is preallocated in chunks, so it is only that small if it was truncated.
    BOOST_REQUIRE(undo_size % UNDOFILE_CHUNK_SIZE != 0);
    BOOST_CHECK_EQUAL(fs::file_size(m_args.GetBlocksDirPath() / fs::PathFromString(strprintf("rev%05u.dat", first_file))), undo_size);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};
    const CBlockIndex* old_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    const int old_tip_file{WITH_LOCK(chainman.GetMutex(), return blockman.GetBlockPos(*old_tip).nFile)};
    WITH_LOCK(blockman.m_block_storage_mutex, blockman.GetBlockFileInfo(old_tip_file)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Prune the older block file, but don't unlink it
    const int file_number{WITH_LOCK(chainman.GetMutex(), return blockman.GetBlockPos(*old_tip).nFile)};
    {
        LOCK2(chainman.GetMutex(), blockman.m_block_storage_mutex);
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman.GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    WITH_LOCK(blockman.m_block_storage_mutex, blockman.m_have_pruned = true);
    WITH_LOCK(chainman.GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman.GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman.GetMutex(), return blockman.GetBlockPos(*new_tip).nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && blockman.GetStatus(*it) & BLOCK_HAVE_DATA) {
            blockman.ModifyIndex(*it, [](auto& f) { f.nStatus &= ~BLOCK_HAVE_DATA; });
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(&blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Ensure we don't fail due to the expected absence of undo data in the genesis block
    CBlockIndex* upper_block = chainman->ActiveChain()[2];
    CBlockIndex* genesis = chainman->ActiveChain()[0];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(*upper_block, *genesis, BlockStatus{BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO}));
    // Ensure we detect absence of undo data in the first block
    blockman.ModifyIndex(*chainman->ActiveChain()[1], [](auto& f) { f.nStatus &= ~BLOCK_HAVE_UNDO; });
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *genesis, BlockStatus{BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO}));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(&blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));

    // Simulate that the first available block is missing undo data and
    // detect this by using a status mask.
    blockman.ModifyIndex(*first_available_block, [](auto& f) { f.nStatus &= ~BLOCK_HAVE_UNDO; });
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *first_available_block, BlockStatus{BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO}));
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block, BlockStatus{BLOCK_HAVE_DATA}));
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_part, TestChain100Setup)
{
    LOCK(::cs_main);
    auto& chainman{m_node.chainman};
    auto& blockman{chainman->m_blockman};
    const CBlockIndex& tip{*chainman->ActiveTip()};
    const FlatFilePos tip_block_pos{blockman.GetBlockPos(tip)};

    auto block{blockman.ReadRawBlock(tip_block_pos)};
    BOOST_REQUIRE(block);
    BOOST_REQUIRE_GE(block->size(), 200);

    const auto expect_part{[&](size_t offset, size_t size) {
        auto res{blockman.ReadRawBlock(tip_block_pos, std::pair{offset, size})};
        BOOST_CHECK(res);
        const auto& part{res.value()};
        BOOST_CHECK_EQUAL_COLLECTIONS(part.begin(), part.end(), block->begin() + offset, block->begin() + offset + size);
    }};

    expect_part(0, 20);
    expect_part(0, block->size() - 1);
    expect_part(0, block->size() - 10);
    expect_part(0, block->size());
    expect_part(1, block->size() - 1);
    expect_part(10, 20);
    expect_part(block->size() - 1, 1);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_part_error, TestChain100Setup)
{
    LOCK(::cs_main);
    auto& chainman{m_node.chainman};
    auto& blockman{chainman->m_blockman};
    const CBlockIndex& tip{*chainman->ActiveTip()};
    const FlatFilePos tip_block_pos{blockman.GetBlockPos(tip)};

    auto block{blockman.ReadRawBlock(tip_block_pos)};
    BOOST_REQUIRE(block);
    BOOST_REQUIRE_GE(block->size(), 200);

    const auto expect_part_error{[&](size_t offset, size_t size) {
        auto res{blockman.ReadRawBlock(tip_block_pos, std::pair{offset, size})};
        BOOST_CHECK(!res);
        BOOST_CHECK_EQUAL(res.error(), node::ReadRawError::BadPartRange);
    }};

    expect_part_error(0, 0);
    expect_part_error(0, block->size() + 1);
    expect_part_error(0, std::numeric_limits<size_t>::max());
    expect_part_error(1, block->size());
    expect_part_error(2, block->size() - 1);
    expect_part_error(block->size() - 1, 2);
    expect_part_error(block->size() - 2, 3);
    expect_part_error(block->size() + 1, 0);
    expect_part_error(block->size() + 1, 1);
    expect_part_error(block->size() + 2, 2);
    expect_part_error(block->size(), 0);
    expect_part_error(block->size(), 1);
    expect_part_error(std::numeric_limits<size_t>::max(), 1);
    expect_part_error(std::numeric_limits<size_t>::max(), std::numeric_limits<size_t>::max());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_readblock_hash_mismatch, TestingSetup)
{
    CBlockIndex index;
    {
        LOCK(cs_main);
        auto& blockman{m_node.chainman->m_blockman};
        const auto tip{m_node.chainman->ActiveTip()};
        const uint32_t status{blockman.GetStatus(*tip)};
        const unsigned int data_pos{blockman.GetDataOffset(*tip)};
        blockman.ModifyIndex(index, [&](auto& f) { f.nStatus = status; f.nDataPos = data_pos; });
        index.phashBlock = &uint256::ONE; // mismatched block hash
    }

    ASSERT_DEBUG_LOG("GetHash() doesn't match index");
    CBlock block;
    BOOST_CHECK(!m_node.chainman->m_blockman.ReadBlock(block, index));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    // Test blocks with no transactions, not even a coinbase
    CBlock block1;
    block1.nVersion = 1;
    CBlock block2;
    block2.nVersion = 2;
    CBlock block3;
    block3.nVersion = 3;

    // They are 80 bytes header + 1 byte 0x00 for vtx length
    constexpr int TEST_BLOCK_SIZE{81};

    // Blockstore is empty
    LOCK(::cs_main);
    BOOST_CHECK_EQUAL(WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CalculateCurrentUsage()), 0);

    // Write the first block to a new location.
    FlatFilePos pos1{blockman.WriteBlock(block1, /*nHeight=*/1)};
    blockman.FinishBlockWrite(pos1);

    // Write second block
    FlatFilePos pos2{blockman.WriteBlock(block2, /*nHeight=*/2)};
    blockman.FinishBlockWrite(pos2);

    // Two blocks in the file
    BOOST_CHECK_EQUAL(WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CalculateCurrentUsage()), (TEST_BLOCK_SIZE + STORAGE_HEADER_BYTES) * 2);

    // First two blocks are written as expected
    // Errors are expected because block data is junk, thrown AFTER successful read
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    {
        ASSERT_DEBUG_LOG("Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos1, {}));
        BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    }
    {
        ASSERT_DEBUG_LOG("Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos2, {}));
        BOOST_CHECK_EQUAL(read_block.nVersion, 2);
    }

    // During reindex, the flat file block storage will not be written to.
    // UpdateBlockInfo will, however, update the blockfile metadata.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = WITH_LOCK(blockman.m_block_storage_mutex, return blockman.GetBlockFileInfo(0));
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    blockman.UpdateBlockInfo(block3, /*nHeight=*/3, /*pos=*/pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CalculateCurrentUsage()), (TEST_BLOCK_SIZE + STORAGE_HEADER_BYTES) * 2);

    // Block 2 was not overwritten:
    BOOST_CHECK(!blockman.ReadBlock(read_block, pos2, {}));
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

BOOST_FIXTURE_TEST_CASE(prune_lock_update_and_delete, TestingSetup)
{
    LOCK(::cs_main);
    auto& chainman{*Assert(m_node.chainman)};
    auto& blockman{chainman.m_blockman};

    // Create a prune lock
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 100});

    // Update it to a new height
    blockman.UpdatePruneLock("test_lock", node::PruneLockInfo{.height_first = 200});

    // Delete existing prune lock
    BOOST_CHECK(blockman.DeletePruneLock("test_lock"));

    // Verify deletion worked by trying to delete the same lock again
    BOOST_CHECK(!blockman.DeletePruneLock("test_lock"));

    // Deleting a non-existent lock returns false
    BOOST_CHECK(!blockman.DeletePruneLock("nonexistent"));
}

BOOST_AUTO_TEST_CASE(blockmanager_storage_without_cs_main)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    // Block file state is guarded by m_block_storage_mutex, not cs_main, so the
    // block storage functions below must not require cs_main.
    const CBlock& block{params->GenesisBlock()};
    const auto block_size{static_cast<uint64_t>(::GetSerializeSize(TX_WITH_WITNESS(block)))};
    const auto usage_before{WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CalculateCurrentUsage())};

    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/0)};
    blockman.FinishBlockWrite(pos);
    BOOST_CHECK(!pos.IsNull());
    BOOST_CHECK_EQUAL(WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CalculateCurrentUsage()),
                      usage_before + block_size + STORAGE_HEADER_BYTES);

    blockman.UpdatePruneLock("storage_without_cs_main", node::PruneLockInfo{.height_first = 1});
    BOOST_CHECK(blockman.DeletePruneLock("storage_without_cs_main"));
    BOOST_CHECK(!blockman.DeletePruneLock("storage_without_cs_main"));
}

BOOST_AUTO_TEST_CASE(blockmanager_concurrent_write_block)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    const CBlock& block{params->GenesisBlock()};
    const auto block_size{static_cast<uint64_t>(::GetSerializeSize(TX_WITH_WITNESS(block)))};
    constexpr int NUM_THREADS{4};
    constexpr int BLOCKS_PER_THREAD{25};

    // Concurrent writers must never be handed overlapping positions. This relies
    // on m_block_storage_mutex serializing the allocation of block file space.
    std::vector<std::vector<FlatFilePos>> positions(NUM_THREADS);
    std::vector<std::thread> threads;
    for (int t{0}; t < NUM_THREADS; ++t) {
        threads.emplace_back([&blockman, &block, &positions, t] {
            for (int i{0}; i < BLOCKS_PER_THREAD; ++i) {
                const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/0)};
                blockman.FinishBlockWrite(pos);
                positions[t].push_back(pos);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    std::set<std::pair<int, uint32_t>> seen;
    for (const auto& thread_positions : positions) {
        for (const FlatFilePos& pos : thread_positions) {
            BOOST_CHECK(!pos.IsNull());
            BOOST_CHECK(seen.emplace(pos.nFile, pos.nPos).second);
        }
    }
    BOOST_CHECK_EQUAL(seen.size(), static_cast<size_t>(NUM_THREADS * BLOCKS_PER_THREAD));
    BOOST_CHECK_EQUAL(WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CalculateCurrentUsage()),
                      NUM_THREADS * BLOCKS_PER_THREAD * (block_size + STORAGE_HEADER_BYTES));
}

//! A block file cannot be pruned while a block is being written to it. Once a block file is pruned,
//! no block is written to it any more, since block writes do not hold cs_main and could otherwise
//! write to it between pruning it and unlinking it.
BOOST_AUTO_TEST_CASE(blockmanager_prune_block_file_being_written)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    const CBlock& block{params->GenesisBlock()};

    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    BOOST_REQUIRE_EQUAL(pos.nFile, 0);
    BOOST_CHECK(!WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CanPruneBlockFile(0)));
    blockman.FinishBlockWrite(pos);
    BOOST_CHECK(WITH_LOCK(blockman.m_block_storage_mutex, return blockman.CanPruneBlockFile(0)));

    // File 0 is the file the cursor points to. Once it is pruned, the next block goes to a new file.
    {
        LOCK2(::cs_main, blockman.m_block_storage_mutex);
        blockman.PruneOneBlockFile(0);
    }
    const FlatFilePos next_pos{blockman.WriteBlock(block, /*nHeight=*/2)};
    blockman.FinishBlockWrite(next_pos);
    BOOST_CHECK_EQUAL(next_pos.nFile, 1);
}

BOOST_AUTO_TEST_SUITE_END()
