// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation_jobs.h>

#include <logging.h>
#include <random.h>
#include <txmempool.h>
#include <util/overloaded.h>
#include <util/thread.h>
#include <validation.h>

#include <optional>

ValidationJobs::~ValidationJobs()
{
    Stop();
}

void ValidationJobs::Start()
{
    LOCK(m_mutex);
    assert(!m_thread.joinable() && !m_stopped);
    m_thread = std::thread(util::TraceThread, "validation", [this] { ThreadMain(); });
}

void ValidationJobs::Stop()
{
    std::thread thread;
    {
        LOCK(m_mutex);
        m_stopped = true;
        m_block_jobs.clear();
        m_tx_jobs.clear();
        thread = std::move(m_thread);
    }
    m_cv.notify_all();
    if (thread.joinable()) thread.join();
}

void ValidationJobs::Submit(Job job)
{
    {
        LOCK(m_mutex);
        if (m_stopped) return;
        if (m_thread.joinable()) {
            (std::holds_alternative<ProcessStoredBlock>(job) ? m_block_jobs : m_tx_jobs).push_back(std::move(job));
            m_cv.notify_one();
            return;
        }
    }
    Do(job);
}

size_t ValidationJobs::Drop(NodeId from)
{
    LOCK(m_mutex);
    return std::erase_if(m_tx_jobs, [from](const Job& job) {
        // The jobs that no peer sent have nobody to be dropped for.
        return std::visit([from](const auto& j) {
            if constexpr (requires { j.from; }) return j.from == from;
            return false;
        }, job);
    });
}

void ValidationJobs::ThreadMain()
{
    while (true) {
        Job job;
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_stopped || !m_block_jobs.empty() || !m_tx_jobs.empty(); });
            if (m_stopped) return;
            // The blocks go first: what they do is what the other work depends on, and what peers wait for.
            auto& queue{m_block_jobs.empty() ? m_tx_jobs : m_block_jobs};
            job = std::move(queue.front());
            queue.pop_front();
        }
        if (m_test_delay) {
            std::this_thread::sleep_for(FastRandomContext{}.randrange<std::chrono::milliseconds>(MAX_TEST_DELAY));
        }
        Do(job);
    }
}

void ValidationJobs::Do(const Job& job) const
{
    std::visit(util::Overloaded{
        [&](const ProcessStoredBlock& job) {
            AssertLockNotHeld(::cs_main);
            if (job.new_block) WITH_LOCK(::cs_main, m_chainman.BlockStored(job.pindex));
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
