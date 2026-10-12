// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/check.h>
#include <validation.h>
#include <validation_jobs.h>

#include <boost/test/unit_test.hpp>

#include <memory>

BOOST_FIXTURE_TEST_SUITE(validation_jobs_tests, TestChain100Setup)

//! The continuation of a job is called exactly once, before the job returns, with the id of the peer the work
//! was for.
BOOST_AUTO_TEST_CASE(block_jobs_call_the_continuation_once_with_the_node_id)
{
    auto& chainman{*Assert(m_node.chainman)};
    const ValidationJobs jobs{chainman, *Assert(m_node.mempool)};
    constexpr NodeId PEER{42};

    const auto block{std::make_shared<const CBlock>(CreateBlock({}, CScript{} << OP_TRUE))};
    int accepted_calls{0}, activated_calls{0};
    jobs.AcceptBlock(PEER, block, /*force_processing=*/true, /*min_pow_checked=*/true, [&](const ValidationJobs::BlockAccepted& accepted) {
        ++accepted_calls;
        BOOST_CHECK_EQUAL(accepted.from, PEER);
        BOOST_CHECK(accepted.block->GetHash() == block->GetHash());
        BOOST_CHECK(accepted.accepted);
        BOOST_CHECK(accepted.new_block);
    });
    BOOST_CHECK_EQUAL(accepted_calls, 1);
    // The block is stored, and not connected before it is activated.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash() == block->hashPrevBlock));
    jobs.ActivateBlock(PEER, block, [&](const ValidationJobs::BlockActivated& activated) {
        ++activated_calls;
        BOOST_CHECK_EQUAL(activated.from, PEER);
        BOOST_CHECK(activated.success);
    });
    BOOST_CHECK_EQUAL(activated_calls, 1);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash()) == block->GetHash());

    int chain_calls{0};
    jobs.ActivateBestChain(block, [&](const ValidationJobs::ChainActivated& activated) {
        ++chain_calls;
        BOOST_CHECK(activated.success);
    });
    BOOST_CHECK_EQUAL(chain_calls, 1);
}

BOOST_AUTO_TEST_CASE(transaction_and_package_jobs_call_the_continuation_once_with_the_node_id)
{
    auto& chainman{*Assert(m_node.chainman)};
    const ValidationJobs jobs{chainman, *Assert(m_node.mempool)};
    constexpr NodeId PEER{7};

    // A transaction that spends an output that does not exist.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    const CTransactionRef tx{MakeTransactionRef(mtx)};

    int tx_calls{0}, package_calls{0};
    LOCK(::cs_main);
    jobs.ProcessTransaction(PEER, tx, /*test_accept=*/false, [&](const ValidationJobs::TxProcessed& processed) {
        ++tx_calls;
        BOOST_CHECK_EQUAL(processed.from, PEER);
        BOOST_CHECK(processed.tx->GetHash() == tx->GetHash());
        BOOST_CHECK(processed.result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    });
    BOOST_CHECK_EQUAL(tx_calls, 1);
    jobs.ProcessPackage(PEER, {tx}, [&](const ValidationJobs::PackageProcessed& processed) {
        ++package_calls;
        BOOST_CHECK_EQUAL(processed.from, PEER);
        BOOST_CHECK_EQUAL(processed.txns.size(), 1U);
    });
    BOOST_CHECK_EQUAL(package_calls, 1);
}

BOOST_AUTO_TEST_SUITE_END()
