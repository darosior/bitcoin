// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <node/blockstorage.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/thread.h>

void init_leak()
{
    SelectParams(ChainType::MAIN);
}

FUZZ_TARGET(leak_test, .init = init_leak)
{
    kernel::BlockTreeDB block_tree{DBParams{
        .path = "", // Memory-only.
        .cache_bytes = 0,
        .memory_only = true,
    }};
}
