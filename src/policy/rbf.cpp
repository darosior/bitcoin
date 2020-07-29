// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/rbf.h>
#include <util/rbf.h>

namespace {
RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool* const pool) NO_THREAD_SAFETY_ANALYSIS
{
    if (pool) AssertLockHeld(pool->cs);

    CTxMemPool::setEntries setAncestors;

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool || !pool->exists(tx.GetHash())) {
        return RBFTransactionState::UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CTxMemPoolEntry entry = *pool->mapTx.find(tx.GetHash());
    pool->CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    for (CTxMemPool::txiter it : setAncestors) {
        if (SignalsOptInRBF(it->GetTx())) {
            return RBFTransactionState::REPLACEABLE_BIP125;
        }
    }
    return RBFTransactionState::FINAL;
}
} // namespace

RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool) { return IsRBFOptIn(tx, &pool); }
RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx) { return IsRBFOptIn(tx, nullptr); }
