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
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validation_jobs_tests, TestChain100Setup)

//! Submitting a job posts exactly one result, of the type that goes with it, with the id of the peer the work was for.
BOOST_AUTO_TEST_CASE(block_jobs_post_one_result_with_the_node_id)
{
    auto& chainman{*Assert(m_node.chainman)};
    std::vector<ValidationJobs::Result> results;
    const ValidationJobs jobs{chainman, *Assert(m_node.mempool), [&](ValidationJobs::Result&& result) {
        AssertLockNotHeld(::cs_main);
        results.push_back(std::move(result));
    }};
    constexpr NodeId PEER{42};

    const auto block{std::make_shared<const CBlock>(CreateBlock({}, CScript{} << OP_TRUE))};
    // Whoever received the block accepts and stores it, with no job. The block is not connected before validation
    // processes it.
    const auto accepted{chainman.AcceptNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true)};
    BOOST_REQUIRE(accepted.accepted);
    BOOST_REQUIRE(accepted.new_block);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash() == block->hashPrevBlock));

    jobs.Submit(ValidationJobs::ProcessStoredBlock{PEER, block, accepted.pindex, accepted.new_block});
    BOOST_REQUIRE_EQUAL(results.size(), 1U);
    const auto* processed{std::get_if<ValidationJobs::StoredBlockProcessed>(&results.back())};
    BOOST_REQUIRE(processed);
    BOOST_CHECK_EQUAL(processed->from, PEER);
    BOOST_CHECK(processed->block_hash == block->GetHash());
    BOOST_CHECK(processed->new_block);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash()) == block->GetHash());

    jobs.Submit(ValidationJobs::ActivateBestChain{block});
    BOOST_REQUIRE_EQUAL(results.size(), 2U);
    BOOST_CHECK(std::holds_alternative<ValidationJobs::ChainActivated>(results.back()));
}

BOOST_AUTO_TEST_CASE(transaction_and_package_jobs_post_one_result_with_the_node_id)
{
    auto& chainman{*Assert(m_node.chainman)};
    std::vector<ValidationJobs::Result> results;
    // The results of the jobs for the mempool are posted with cs_main held, see ValidationJobs::Submit().
    const ValidationJobs jobs{chainman, *Assert(m_node.mempool), [&](ValidationJobs::Result&& result) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        results.push_back(std::move(result));
    }};
    constexpr NodeId PEER{7};

    // A transaction that spends an output that does not exist.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    const CTransactionRef tx{MakeTransactionRef(mtx)};

    jobs.Submit(ValidationJobs::ProcessTransaction{PEER, tx});
    BOOST_REQUIRE_EQUAL(results.size(), 1U);
    const auto* processed{std::get_if<ValidationJobs::TxProcessed>(&results.back())};
    BOOST_REQUIRE(processed);
    BOOST_CHECK_EQUAL(processed->from, PEER);
    BOOST_CHECK(processed->tx->GetHash() == tx->GetHash());
    BOOST_CHECK(processed->result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    // The result of the same work for an orphan is a different type.
    jobs.Submit(ValidationJobs::ReconsiderOrphan{PEER, tx});
    BOOST_REQUIRE_EQUAL(results.size(), 2U);
    const auto* reconsidered{std::get_if<ValidationJobs::OrphanReconsidered>(&results.back())};
    BOOST_REQUIRE(reconsidered);
    BOOST_CHECK_EQUAL(reconsidered->from, PEER);
    BOOST_CHECK(reconsidered->tx->GetHash() == tx->GetHash());
    BOOST_CHECK(reconsidered->result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    const node::PackageToValidate package{tx, tx, PEER, PEER};
    jobs.Submit(ValidationJobs::ProcessPackage{PEER, package});
    BOOST_REQUIRE_EQUAL(results.size(), 3U);
    const auto* package_processed{std::get_if<ValidationJobs::PackageProcessed>(&results.back())};
    BOOST_REQUIRE(package_processed);
    BOOST_CHECK_EQUAL(package_processed->from, PEER);
    BOOST_CHECK_EQUAL(package_processed->package.m_txns.size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
