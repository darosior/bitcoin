// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_JOBS_H
#define BITCOIN_VALIDATION_JOBS_H

#include <kernel/cs_main.h>
#include <net.h>
#include <node/txdownloadman.h>
#include <policy/packages.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <validation.h>

#include <functional>
#include <memory>
#include <variant>

class CTxMemPool;

/**
 * The work that network processing asks validation to do, as jobs, and what validation answers, as results.
 *
 * A job is a message with everything validation needs to do the work, and a result is a message with everything
 * the requester needs to handle the outcome. Each kind of work has its own types, and a different type for each
 * purpose: the result of a transaction that a peer sent and that of an orphan that is reconsidered are different
 * even though validation does the same for both. Nothing travels with a job but data, so that jobs that are waiting
 * can be looked at: to give some priority over others, or to drop those of a peer that is gone. Results carry a
 * NodeId, never a CNode&, since the peer can be gone by the time the result is handled.
 *
 * For now Submit() does the work right away, on the thread that calls it, and the result is posted before it
 * returns. Callers rely on nothing of that but the order of the results: those of a job are posted after the
 * results of the notifications that the work caused, in the order they were made. The point is that they do not
 * need to know which thread does the work, so that it can later be done by another one.
 */
class ValidationJobs
{
public:
    /**
     * Validation's half of the processing of a block that was accepted and stored by whoever received it (see
     * ChainstateManager::AcceptNewBlock()): if the block is new, its chain selection bookkeeping, then the activation of
     * the best chain (the second half of ChainstateManager::ProcessNewBlock()).
     */
    struct ProcessStoredBlock {
        NodeId from;
        std::shared_ptr<const CBlock> block;
        //! The entry of the block.
        CBlockIndex* pindex;
        //! Whether the block was first received, and stored, by whoever received it.
        bool new_block;
    };
    /** A stored block was processed, or the activation failed and was logged. */
    struct StoredBlockProcessed {
        NodeId from;
        uint256 block_hash;
        bool new_block;
    };

    /** Submit a transaction that a peer sent us to the mempool. */
    struct ProcessTransaction {
        NodeId from;
        CTransactionRef tx;
    };
    struct TxProcessed {
        NodeId from;
        CTransactionRef tx;
        MempoolAcceptResult result;
    };

    /** Submit an orphan of a peer to the mempool again, now that a parent may be known. */
    struct ReconsiderOrphan {
        NodeId from;
        CTransactionRef tx;
    };
    struct OrphanReconsidered {
        NodeId from;
        CTransactionRef tx;
        MempoolAcceptResult result;
    };

    /** Submit a package of transactions to the mempool. */
    struct ProcessPackage {
        NodeId from;
        node::PackageToValidate package;
    };
    struct PackageProcessed {
        NodeId from;
        node::PackageToValidate package;
        PackageMempoolAcceptResult result;
    };

    using Job = std::variant<ProcessStoredBlock, ProcessTransaction, ReconsiderOrphan, ProcessPackage>;
    using Result = std::variant<StoredBlockProcessed, TxProcessed, OrphanReconsidered, PackageProcessed>;

    /** `post_result` is called with the result of every job. */
    ValidationJobs(ChainstateManager& chainman, CTxMemPool& mempool, std::function<void(Result&&)> post_result)
        : m_chainman{chainman}, m_mempool{mempool}, m_post_result{std::move(post_result)} {}

    /**
     * Do the work of a job, and post its result. Jobs are submitted without cs_main, and take it themselves. The
     * results of the jobs for the mempool are posted with it held, so that they are in the queue where the changes of
     * the chain that came before the decision of the mempool are before them, and the later ones are after.
     */
    void Submit(Job job) const LOCKS_EXCLUDED(::cs_main);

private:
    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;
    const std::function<void(Result&&)> m_post_result;
};

#endif // BITCOIN_VALIDATION_JOBS_H
