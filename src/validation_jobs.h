// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_JOBS_H
#define BITCOIN_VALIDATION_JOBS_H

#include <kernel/cs_main.h>
#include <net.h>
#include <policy/packages.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <validation.h>

#include <functional>
#include <memory>

class CTxMemPool;

/**
 * The work that network processing asks validation to do, as jobs.
 *
 * A job is the work itself and a continuation: the function that is called with the result when the work is
 * done, and that holds everything the requester wants to do with it. The result says which peer the work was
 * for with a NodeId, never with a CNode&, since the peer can be gone by the time the result is available.
 *
 * For now a job is run right away, on the thread that submits it, and its continuation is called before the
 * submitting function returns. Callers rely on nothing of that but the order in which a continuation is
 * called after the job's work, and on being called exactly once. The point is that they do not need to know
 * which thread does the work, so that it can later be done by another one.
 *
 * The locks the caller holds when it submits a job are still held when its continuation is called, which is
 * what the continuations of the transaction and package jobs rely on for now (they are called with cs_main
 * and the transaction download mutex held, as the code that handles the result requires). That stops being
 * true when jobs are not run inline anymore: the continuations will then have to take the locks they need.
 */
class ValidationJobs
{
public:
    ValidationJobs(ChainstateManager& chainman, CTxMemPool& mempool) : m_chainman{chainman}, m_mempool{mempool} {}

    /** What became of a block that was given to AcceptBlock(). */
    struct BlockAccepted {
        NodeId from;
        std::shared_ptr<const CBlock> block;
        //! False if the block was rejected. BlockChecked has been sent with the reason.
        bool accepted;
        //! Whether the block was first received, and stored, by this job.
        bool new_block;
    };
    /** Check a block, add its header and store it (the first half of ChainstateManager::ProcessNewBlock()). */
    void AcceptBlock(NodeId from, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked,
                     const std::function<void(const BlockAccepted&)>& done) const
        LOCKS_EXCLUDED(::cs_main);

    /** What became of a block that was given to ActivateBlock(). */
    struct BlockActivated {
        NodeId from;
        std::shared_ptr<const CBlock> block;
        //! False if an error stopped the activation of the best chain.
        bool success;
    };
    /** Activate the best chain after a block was accepted (the second half of ChainstateManager::ProcessNewBlock()). */
    void ActivateBlock(NodeId from, const std::shared_ptr<const CBlock>& block,
                       const std::function<void(const BlockActivated&)>& done) const
        LOCKS_EXCLUDED(::cs_main);

    /** What became of a call of ActivateBestChain(). */
    struct ChainActivated {
        bool success;
        //! The state to log if it did not.
        BlockValidationState state;
    };
    /**
     * Make sure the active chainstate is on its best chain, for requests that must be served from it. `block` is a
     * block that was recently accepted, if there is one, which saves reading it back from disk.
     */
    void ActivateBestChain(const std::shared_ptr<const CBlock>& block, const std::function<void(const ChainActivated&)>& done) const
        LOCKS_EXCLUDED(::cs_main);

    /** What became of a transaction that was given to ProcessTransaction(). */
    struct TxProcessed {
        //! The peer that sent the transaction, or -1 if it did not come from a peer.
        NodeId from;
        CTransactionRef tx;
        MempoolAcceptResult result;
    };
    /** Submit a transaction to the mempool, or only check that it would be accepted if `test_accept`. */
    void ProcessTransaction(NodeId from, const CTransactionRef& tx, bool test_accept, const std::function<void(const TxProcessed&)>& done) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** What became of a package that was given to ProcessPackage(). */
    struct PackageProcessed {
        NodeId from;
        Package txns;
        PackageMempoolAcceptResult result;
    };
    /** Submit a package of transactions to the mempool. */
    void ProcessPackage(NodeId from, const Package& txns, const std::function<void(const PackageProcessed&)>& done) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

private:
    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;
};

#endif // BITCOIN_VALIDATION_JOBS_H
