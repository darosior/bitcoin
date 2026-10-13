// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation_jobs.h>

#include <logging.h>
#include <txmempool.h>
#include <util/overloaded.h>
#include <validation.h>

void ValidationJobs::Submit(Job job) const
{
    std::visit(util::Overloaded{
        [&](const AcceptBlock& job) {
            AssertLockNotHeld(::cs_main);
            const auto result{m_chainman.AcceptNewBlock(job.block, job.force_processing, job.min_pow_checked)};
            m_post_result(BlockAccepted{job.from, job.block, result.accepted, result.new_block});
        },
        [&](const ActivateBlock& job) {
            AssertLockNotHeld(::cs_main);
            m_chainman.ActivateNewBlock(job.block);
            m_post_result(BlockActivated{job.from, job.block->GetHash(), job.new_block});
        },
        [&](const ActivateBestChain& job) {
            AssertLockNotHeld(::cs_main);
            BlockValidationState state;
            if (!m_chainman.ActiveChainstate().ActivateBestChain(state, job.block)) {
                LogDebug(BCLog::NET, "failed to activate chain (%s)\n", state.ToString());
            }
            m_post_result(ChainActivated{});
        },
        // The results of the jobs for the mempool are posted with cs_main held: a tip change is notified under it, so
        // that their order in the queue is the order of the changes of the chain and of the decisions of the mempool.
        [&](const ProcessTransaction& job) {
            AssertLockNotHeld(::cs_main);
            LOCK(::cs_main);
            m_post_result(TxProcessed{job.from, job.tx, m_chainman.ProcessTransaction(job.tx)});
        },
        [&](const ReconsiderOrphan& job) {
            AssertLockNotHeld(::cs_main);
            LOCK(::cs_main);
            m_post_result(OrphanReconsidered{job.from, job.tx, m_chainman.ProcessTransaction(job.tx)});
        },
        [&](const ProcessPackage& job) {
            AssertLockNotHeld(::cs_main);
            LOCK(::cs_main);
            m_post_result(PackageProcessed{job.from, job.package, ProcessNewPackage(m_chainman.ActiveChainstate(), m_mempool, job.package.m_txns, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt)});
        },
    }, job);
}
