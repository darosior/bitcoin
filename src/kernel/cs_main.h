// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CS_MAIN_H
#define BITCOIN_KERNEL_CS_MAIN_H

#include <sync.h>

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
extern RecursiveMutex cs_main;

/**
 * The block index lock. It guards the block index and the state of the block files, which cs_main used to guard
 * on its own. It is declared here, next to cs_main, because the fields it guards are fields of CBlockIndex, which
 * is lower than the code that uses it and cannot name a member of it.
 *
 * This lock guards:
 * - CBlockIndex::nStatus, nFile, nDataPos, nUndoPos and nTx;
 * - the block index map itself (BlockManager::m_block_index): looking an entry up, iterating over all entries and
 *   inserting new ones. Entries are never erased while the node runs, so a pointer to one stays valid;
 * - the best header and the last notified header (ChainstateManager::m_best_header and
 *   m_last_notified_header);
 * - the set of dirty entries (BlockManager::m_dirty_blockindex);
 * - the state of the block files: the block file info, the blockfile cursors, and the set of dirty block files;
 * - the prune locks, the flag that requests a check for pruning, whether files were ever pruned, and the
 *   snapshot height that segments the block files.
 *
 * The other fields of an entry do not need this lock. The header fields, phashBlock, pprev, pskip, nHeight,
 * nChainWork and nTimeMax never change once the entry is inserted. nSequenceId, m_chain_tx_count and
 * m_blocks_unlinked belong to chain selection and are guarded by cs_main.
 *
 * Lock order: cs_main, then this lock.
 *
 * This is a leaf lock. The code that holds it:
 * - does not take cs_main, nor any other lock. That includes the functions that take cs_main themselves, such as
 *   ActiveChain(), ActiveTip() and ActiveChainstate(): their results are computed before taking this lock.
 *   Logging is the exception: LogDebug and the like take the logger's own mutex, which is a leaf too;
 * - does not call a notification or a callback. Errors found under it are reported once it is released, see
 *   BlockManager::DeferredNotifications;
 * - does not wait for anything: no condition variable, no future, no draining of the validation queue.
 * Nothing can wait for a thread that holds it, so it cannot be part of a deadlock, whatever the order a caller
 * takes its other locks in.
 *
 * It is global, like cs_main: all the BlockManagers of a process share it, which costs contention and nothing
 * else, since nothing is taken under it. It is non-recursive. GlobalMutex is the type for a Mutex that is a
 * global (see sync.h). The functions that take it are annotated LOCKS_EXCLUDED(g_block_index_mutex), and clang
 * rejects a call made while the caller is known to hold it. It does not follow that requirement through callers
 * that are not annotated, so the leaf rule above is also checked by review and by the lock order checks.
 *
 * Reading and writing block and undo files runs under this lock, as it runs under cs_main on master: whoever
 * needs the block index waits for a block that is being written or a file that is being flushed. The lock could
 * later be split in one for the index and one for the storage, if measurements show that this wait matters. The
 * annotations on the fields would then point to the code that has to change.
 *
 * The block tree database handle (BlockManager::m_block_tree_db) is not guarded: it is set once in the
 * constructor, and the database is safe to use from several threads. What it stores is guarded by this lock, and
 * a batch is built while holding it, see BlockManager::WriteBlockIndexDB().
 *
 * A block is written and recorded in its entry (BlockManager::StoreBlock()) in one hold of this lock, which does
 * not need cs_main (AcceptBlock() holds it when it calls it, for now). Everything else that changes an existing
 * entry also holds cs_main. A change has to be flagged as dirty in the same hold (BlockManager::MarkDirty()), or it
 * is not written to disk.
 *
 * The flush (BlockManager::WriteBlockIndexDB()) flushes the files that blocks are written to and captures the
 * dirty entries in one hold, so that the entries it writes do not refer to data that is not on disk. FindFilesToPrune()
 * selects files to prune under cs_main, and the cursors that write to them are moved to a new file in the same
 * hold (PruneOneBlockFile()), so that no block is written to a file that is unlinked afterwards.
 *
 * The paths that change the block index without cs_main are the insertion of new entries (which are fully built
 * before they become visible), the storage of a block, the best header, the last notified header and the prune
 * locks.
 */
extern GlobalMutex g_block_index_mutex ACQUIRED_AFTER(::cs_main);

#endif // BITCOIN_KERNEL_CS_MAIN_H
