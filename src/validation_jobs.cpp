// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation_jobs.h>

#include <txmempool.h>
#include <validation.h>

void ValidationJobs::AcceptBlock(NodeId from, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked,
                                 const std::function<void(const BlockAccepted&)>& done) const
{
    const auto result{m_chainman.AcceptNewBlock(block, force_processing, min_pow_checked)};
    done({from, block, result.accepted, result.new_block});
}

void ValidationJobs::ActivateBlock(NodeId from, const std::shared_ptr<const CBlock>& block,
                                   const std::function<void(const BlockActivated&)>& done) const
{
    done({from, block, m_chainman.ActivateNewBlock(block)});
}

void ValidationJobs::ActivateBestChain(const std::shared_ptr<const CBlock>& block, const std::function<void(const ChainActivated&)>& done) const
{
    BlockValidationState state;
    const bool success{m_chainman.ActiveChainstate().ActivateBestChain(state, block)};
    done({success, std::move(state)});
}

void ValidationJobs::ProcessTransaction(NodeId from, const CTransactionRef& tx, bool test_accept, const std::function<void(const TxProcessed&)>& done) const
{
    AssertLockHeld(::cs_main);
    done({from, tx, m_chainman.ProcessTransaction(tx, test_accept)});
}

void ValidationJobs::ProcessPackage(NodeId from, const Package& txns, const std::function<void(const PackageProcessed&)>& done) const
{
    AssertLockHeld(::cs_main);
    done({from, txns, ProcessNewPackage(m_chainman.ActiveChainstate(), m_mempool, txns, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt)});
}
