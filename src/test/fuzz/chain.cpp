// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

FUZZ_TARGET(chain)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::optional<CDiskBlockIndex> disk_block_index = ConsumeDeserializable<CDiskBlockIndex>(fuzzed_data_provider);
    if (!disk_block_index) {
        return;
    }
    (void)disk_block_index->ConstructBlockHash();

    // What is read is written back as it was.
    DataStream written;
    written << *disk_block_index;
    CDiskBlockIndex read_back;
    DataStream to_read{written};
    to_read >> read_back;
    DataStream rewritten;
    rewritten << read_back;
    assert(std::ranges::equal(written, rewritten));

    // An in-memory entry built from the fields of the disk entry.
    CBlockHeader header;
    header.nVersion = disk_block_index->nVersion;
    header.hashMerkleRoot = disk_block_index->hashMerkleRoot;
    header.nTime = disk_block_index->nTime;
    header.nBits = disk_block_index->nBits;
    header.nNonce = disk_block_index->nNonce;
    CBlockIndex block_index{header};
    const uint256 zero{};
    block_index.phashBlock = &zero;
    block_index.nHeight = disk_block_index->nHeight;
    {
        LOCK(g_block_index_mutex);
        block_index.nStatus = disk_block_index->nStatus;
        block_index.nTx = disk_block_index->nTx;
        block_index.nFile = disk_block_index->nFile;
        block_index.nDataPos = disk_block_index->nDataPos;
        block_index.nUndoPos = disk_block_index->nUndoPos;

        (void)block_index.GetBlockPos();
        (void)block_index.GetUndoPos();
        (void)block_index.IsValid(BLOCK_VALID_TRANSACTIONS);

        // Writing the entry again gives the same status word.
        CDiskBlockIndex from_memory{&block_index};
        assert(from_memory.nStatus == disk_block_index->nStatus);
    }
    {
        LOCK(::cs_main);
        (void)block_index.GetBlockHash();
        (void)block_index.GetBlockTime();
        (void)block_index.GetBlockTimeMax();
        (void)block_index.GetMedianTimePast();
        (void)block_index.HaveNumChainTxs();
        (void)block_index.GetBlockHeader();
    }
    (void)block_index.ToString();
}
