// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

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

    const uint256 zero{};
    disk_block_index->phashBlock = &zero;
    {
        LOCK(::cs_main);
        (void)disk_block_index->ConstructBlockHash();
        (void)disk_block_index->GetBlockTime();
        (void)disk_block_index->GetBlockTimeMax();
        (void)disk_block_index->GetMedianTimePast();
        (void)disk_block_index->HaveNumChainTxs();
    }

    const CBlockHeader block_header = disk_block_index->GetBlockHeader();
    (void)CDiskBlockIndex{*disk_block_index};
    (void)disk_block_index->BuildSkip();

    CBlockIndex block_index{block_header};
    block_index.phashBlock = &zero;
    (void)block_index.GetBlockHash();
    (void)block_index.ToString();
}
