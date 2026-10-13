// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation_jobs.h>

#include <logging.h>
#include <txmempool.h>
#include <util/overloaded.h>
#include <validation.h>

#include <optional>

void ValidationJobs::Submit(Job job) const
{
    std::visit(util::Overloaded{
        [&](const ProcessStoredBlock& job) {
            AssertLockNotHeld(::cs_main);
            m_chainman.ActivateNewBlock(job.block);
            m_post_result(StoredBlockProcessed{job.from, job.block->GetHash(), job.new_block});
        },
        // The results of the jobs for the mempool are posted with cs_main held: a tip change is notified under it, so
        // that their order in the queue is the order of the changes of the chain and of the decisions of the mempool.
        [&](const ProcessTransaction& job) {
            AssertLockNotHeld(::cs_main);
            LOCK(::cs_main);
            m_post_result(TxProcessed{job.from, job.tx, m_chainman.ProcessTransaction(job.tx)});
        },
        [&](const ReconsiderOrphans& job) {
            AssertLockNotHeld(::cs_main);
            // The orphans are tried in order until one has a result other than missing inputs, with cs_main held
            // across the loop, as the loop of the message handler always did.
            LOCK(::cs_main);
            std::optional<MempoolAcceptResult> last;
            size_t num_tried{0};
            for (const CTransactionRef& tx : job.txs) {
                last.emplace(m_chainman.ProcessTransaction(tx));
                ++num_tried;
                if (last->m_result_type == MempoolAcceptResult::ResultType::VALID ||
                    last->m_state.GetResult() != TxValidationResult::TX_MISSING_INPUTS) break;
            }
            m_post_result(OrphansReconsidered{job.from, job.txs, num_tried, Assert(std::move(last)).value()});
        },
        [&](const ProcessPackage& job) {
            AssertLockNotHeld(::cs_main);
            LOCK(::cs_main);
            m_post_result(PackageProcessed{job.from, job.package, ProcessNewPackage(m_chainman.ActiveChainstate(), m_mempool, job.package.m_txns, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt)});
        },
        [&](const TestAcceptTransactions& job) {
            AssertLockNotHeld(::cs_main);
            std::vector<MempoolAcceptResult> results;
            results.reserve(job.txs.size());
            for (const CTransactionRef& tx : job.txs) {
                // Only hold the lock for a single transaction
                LOCK(::cs_main);
                results.push_back(m_chainman.ProcessTransaction(tx, /*test_accept=*/true));
            }
            m_post_result(TransactionsTestAccepted{job.txs, std::move(results)});
        },
    }, job);
}
