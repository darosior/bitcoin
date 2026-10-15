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

#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <thread>
#include <variant>
#include <vector>

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
 * The jobs are done by a thread of their own once Start() was called, in the order they were submitted, except that
 * the jobs for blocks go before those for transactions. Without it (the fuzz targets and the unit tests that do not
 * start it, to be deterministic) Submit() does the work right away, on the thread that calls it, and the result is
 * posted before it returns. Callers rely on nothing of that but the order of the results: those of a job are posted
 * after the results of the notifications that the work caused, in the order they were made.
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
    /** A stored block was processed, or the activation failed and was logged. Network processing posts it as well for
     * a block it rejected, which has no job: the outcome of a block is handled once, in the order of the events. */
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

    /**
     * Submit the orphans of a peer to the mempool again, now that a parent may be known: the whole work set of the
     * peer, in order. Validation stops at the first that has a result other than missing inputs, and does not try the
     * ones after it. `txs` is not empty.
     */
    struct ReconsiderOrphans {
        NodeId from;
        std::vector<CTransactionRef> txs;
    };
    /**
     * `txs` are the orphans of the job. The first `num_tried` were reconsidered, and `last_result` is the result of the
     * last of them, txs[num_tried - 1]: it is not missing inputs unless all of them were tried and missed inputs. The
     * results of the ones before it were missing inputs, and are not kept.
     */
    struct OrphansReconsidered {
        NodeId from;
        std::vector<CTransactionRef> txs;
        size_t num_tried;
        MempoolAcceptResult last_result;
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

    /**
     * Check whether transactions would be accepted to the mempool, without adding them to it. No peer is behind this
     * work, so the job and its result carry no NodeId, and nothing is paused: it is not on behalf of a message. cs_main is
     * taken for each transaction in turn, so the submitter holds nothing.
     */
    struct TestAcceptTransactions {
        std::vector<CTransactionRef> txs;
    };
    /** `results[i]` is the result of the check of `txs[i]`. */
    struct TransactionsTestAccepted {
        std::vector<CTransactionRef> txs;
        std::vector<MempoolAcceptResult> results;
    };

    using Job = std::variant<ProcessStoredBlock, ProcessTransaction, ReconsiderOrphans, ProcessPackage, TestAcceptTransactions>;
    using Result = std::variant<StoredBlockProcessed, TxProcessed, OrphansReconsidered, PackageProcessed, TransactionsTestAccepted>;

    /** `post_result` is called with the result of every job, on the thread that does it. With `test_delay`, the
     * thread waits a random time of up to MAX_TEST_DELAY before each job, which shifts the interleavings of the
     * threads that it works with: for tests that look for races. */
    ValidationJobs(ChainstateManager& chainman, CTxMemPool& mempool, std::function<void(Result&&)> post_result, bool test_delay = false)
        : m_chainman{chainman}, m_mempool{mempool}, m_post_result{std::move(post_result)}, m_test_delay{test_delay} {}
    static constexpr std::chrono::milliseconds MAX_TEST_DELAY{50};
    ~ValidationJobs();

    /** Start the thread that does the jobs. The jobs submitted before were done by their submitters. */
    void Start() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Stop the thread, and drop the jobs that were not started. The job that is being done is not interrupted, which
     * the interrupt of the ChainstateManager does. Nothing is done by submitted jobs after this.
     */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Have the work of a job done, and its result posted. Jobs are submitted without cs_main, and take it themselves.
     * The results of the jobs for the mempool are posted with it held, so that they are in the queue where the
     * changes of the chain that came before the decision of the mempool are before them, and the later ones are after.
     * The check of transactions posts its result without it.
     */
    void Submit(Job job) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) LOCKS_EXCLUDED(::cs_main);

    /**
     * Drop the jobs for transactions of a peer that did not start. The jobs for blocks stay, whoever sent the block:
     * validation has to learn of it.
     * @returns How many jobs were dropped, which will not post a result.
     */
    size_t Drop(NodeId from) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    /** Do the work of a job, and post its result. */
    void Do(const Job& job) const LOCKS_EXCLUDED(::cs_main);
    void ThreadMain() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;
    const std::function<void(Result&&)> m_post_result;
    const bool m_test_delay;

    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    //! The jobs that wait, for blocks and for the others, which go after them.
    std::deque<Job> m_block_jobs GUARDED_BY(m_mutex);
    std::deque<Job> m_tx_jobs GUARDED_BY(m_mutex);
    bool m_stopped GUARDED_BY(m_mutex){false};
    std::thread m_thread;
};

#endif // BITCOIN_VALIDATION_JOBS_H
