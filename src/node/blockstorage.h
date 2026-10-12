// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKSTORAGE_H
#define BITCOIN_NODE_BLOCKSTORAGE_H

#include <attributes.h>
#include <chain.h>
#include <dbwrapper.h>
#include <flatfile.h>
#include <kernel/blockmanager_opts.h>
#include <kernel/chainparams.h>
#include <kernel/cs_main.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/expected.h>
#include <util/fs.h>
#include <util/hasher.h>
#include <util/obfuscation.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class BlockValidationState;
class CBlockUndo;
class Chainstate;
class ChainstateManager;
namespace Consensus {
struct Params;
}
namespace util {
class SignalInterrupt;
} // namespace util

namespace kernel {
class CBlockFileInfo
{
public:
    uint32_t nBlocks{};      //!< number of blocks stored in file
    uint32_t nSize{};        //!< number of used bytes of block file
    uint32_t nUndoSize{};    //!< number of used bytes in the undo file
    uint32_t nHeightFirst{}; //!< lowest height of block in file
    uint32_t nHeightLast{};  //!< highest height of block in file
    uint64_t nTimeFirst{};   //!< earliest time of block in file
    uint64_t nTimeLast{};    //!< latest time of block in file

    SERIALIZE_METHODS(CBlockFileInfo, obj)
    {
        READWRITE(VARINT(obj.nBlocks));
        READWRITE(VARINT(obj.nSize));
        READWRITE(VARINT(obj.nUndoSize));
        READWRITE(VARINT(obj.nHeightFirst));
        READWRITE(VARINT(obj.nHeightLast));
        READWRITE(VARINT(obj.nTimeFirst));
        READWRITE(VARINT(obj.nTimeLast));
    }

    CBlockFileInfo() = default;

    std::string ToString() const;

    /** update statistics (does not update nSize) */
    void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn)
    {
        if (nBlocks == 0 || nHeightFirst > nHeightIn)
            nHeightFirst = nHeightIn;
        if (nBlocks == 0 || nTimeFirst > nTimeIn)
            nTimeFirst = nTimeIn;
        nBlocks++;
        if (nHeightIn > nHeightLast)
            nHeightLast = nHeightIn;
        if (nTimeIn > nTimeLast)
            nTimeLast = nTimeIn;
    }
};

/** Access to the block database (blocks/index/) */
class BlockTreeDB : public CDBWrapper
{
public:
    using CDBWrapper::CDBWrapper;
    /**
     * Serialize the given file infos, last file number and block index entries into `batch`, which must have been
     * created for this database. The entries are live objects, so the caller must hold the locks that guard their
     * fields while this runs.
     */
    void FillBatch(CDBBatch& batch, const std::vector<std::pair<int, const CBlockFileInfo*>>& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) const;
    /** Write a batch filled by FillBatch() and sync it to disk. It reads no entry, so it can run without any lock. */
    void WriteBatchSync(CDBBatch& batch);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo& info);
    bool ReadLastBlockFile(int& nFile);
    void WriteReindexing(bool fReindexing);
    void ReadReindexing(bool& fReindexing);
    void WriteFlag(const std::string& name, bool fValue);
    bool ReadFlag(const std::string& name, bool& fValue);
    /**
     * Load the block index entries into memory. It writes the fields of the entries directly, so the caller
     * must hold the locks that guard them: the tree mutex for the validity part, the store mutex for the rest.
     */
    bool LoadBlockIndexGuts(Mutex& tree_mutex, Mutex& store_mutex, const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex, const util::SignalInterrupt& interrupt)
        EXCLUSIVE_LOCKS_REQUIRED(tree_mutex, store_mutex);
};
} // namespace kernel

namespace node {
using kernel::CBlockFileInfo;
using kernel::BlockTreeDB;

/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
inline constexpr unsigned int BLOCKFILE_CHUNK_SIZE{16_MiB};
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
inline constexpr unsigned int UNDOFILE_CHUNK_SIZE{1_MiB};
/** The maximum size of a blk?????.dat file (since 0.8) */
inline constexpr unsigned int MAX_BLOCKFILE_SIZE{128_MiB};

/** Size of header written by WriteBlock before a serialized CBlock (8 bytes) */
inline constexpr uint32_t STORAGE_HEADER_BYTES{std::tuple_size_v<MessageStartChars> + sizeof(unsigned int)};

/** Total overhead when writing undo data: header (8 bytes) plus checksum (32 bytes) */
inline constexpr uint32_t UNDO_DATA_DISK_OVERHEAD{STORAGE_HEADER_BYTES + uint256::size()};

// Because validation code takes pointers to the map's CBlockIndex objects, if
// we ever switch to another associative container, we need to either use a
// container that has stable addressing (true of all std associative
// containers), or make the key a `std::unique_ptr<CBlockIndex>`
using BlockMap = std::unordered_map<uint256, CBlockIndex, BlockHasher>;

struct CBlockIndexWorkComparator {
    bool operator()(const CBlockIndex* pa, const CBlockIndex* pb) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    using is_transparent = void;
};

struct CBlockIndexHeightOnlyComparator {
    /* Only compares the height of two block indices, doesn't try to tie-break */
    bool operator()(const CBlockIndex* pa, const CBlockIndex* pb) const;
};

struct PruneLockInfo {
    /// Height of earliest block that should be kept and not pruned
    int height_first{std::numeric_limits<int>::max()};
};

enum BlockfileType {
    // Values used as array indexes - do not change carelessly.
    NORMAL = 0,
    ASSUMED = 1,
    NUM_TYPES = 2,
};

std::ostream& operator<<(std::ostream& os, const BlockfileType& type);

struct BlockfileCursor {
    // The latest blockfile number.
    int file_num{0};

    // Track the height of the highest block in file_num whose undo
    // data has been written. Block data is written to block files in download
    // order, but is written to undo files in validation order, which is
    // usually in order by height. To avoid wasting disk space, undo files will
    // be trimmed whenever the corresponding block file is finalized and
    // the height of the highest block written to the block file equals the
    // height of the highest block written to the undo file. This is a
    // heuristic and can sometimes preemptively trim undo files that will write
    // more data later, and sometimes fail to trim undo files that can't have
    // more data written later.
    int undo_height{0};
};

std::ostream& operator<<(std::ostream& os, const BlockfileCursor& cursor);

enum class ReadRawError {
    IO,
    BadPartRange,
};

/**
 * Maintains a tree of blocks (stored in `m_block_index`) which is consulted
 * to determine where the most-work tip is.
 *
 * This data is used mostly in `Chainstate` - information about, e.g.,
 * candidate tips is not maintained here.
 */
class BlockManager
{
    friend Chainstate;
    friend ChainstateManager;

private:
    const CChainParams& GetParams() const { return m_opts.chainparams; }
    const Consensus::Params& GetConsensus() const { return m_opts.chainparams.GetConsensus(); }
    /**
     * Load the blocktree off disk and into memory. Populate certain metadata
     * per index entry (nValidityStatus, nStorageStatus, nChainWork, nTimeMax, etc.) as well as peripheral
     * collections like m_dirty_blockindex.
     */
    bool LoadBlockIndex(const std::optional<uint256>& snapshot_blockhash)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_tree_mutex, !m_store_mutex);

    /**
     * Notifications (fatal and flush errors) raised by code that holds the store mutex. Handlers must not run
     * under that mutex, so they are collected here and sent when this object is destroyed. Declare it before
     * the LOCK() of the mutex, so that it is destroyed after the mutex is released. The destructor asserts that
     * neither service mutex is held.
     */
    class DeferredNotifications
    {
    public:
        explicit DeferredNotifications(BlockManager& blockman) : m_blockman{blockman} {}
        ~DeferredNotifications();
        DeferredNotifications(const DeferredNotifications&) = delete;
        DeferredNotifications& operator=(const DeferredNotifications&) = delete;

        void FatalError(const bilingual_str& message) { m_pending.emplace_back(Kind::FATAL, message); }
        void FlushError(const bilingual_str& message) { m_pending.emplace_back(Kind::FLUSH, message); }

    private:
        enum class Kind { FATAL, FLUSH };
        BlockManager& m_blockman;
        std::vector<std::pair<Kind, bilingual_str>> m_pending;
    };

    /** Return false if block file or undo file flushing fails. Errors are added to `notifications`. */
    [[nodiscard]] bool FlushBlockFile(int blockfile_num, bool fFinalize, bool finalize_undo, DeferredNotifications& notifications) EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    /** Return false if undo file flushing fails. Errors are added to `notifications`. */
    [[nodiscard]] bool FlushUndoFile(int block_file, bool finalize, DeferredNotifications& notifications) EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    /**
     * Helper function performing various preparations before a block can be saved to disk:
     * Returns the correct position for the block to be saved, which may be in the current or a new
     * block file depending on nAddSize. May flush the previous blockfile to disk if full, updates
     * blockfile info, and checks if there is enough disk space to save the block.
     *
     * The nAddSize argument passed to this function should include not just the size of the serialized CBlock, but also the size of
     * separator fields (STORAGE_HEADER_BYTES).
     *
     * Errors are added to `notifications`.
     */
    [[nodiscard]] FlatFilePos FindNextBlockPos(unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, DeferredNotifications& notifications) EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    [[nodiscard]] bool FindUndoPos(BlockValidationState& state, int nFile, FlatFilePos& pos, unsigned int nAddSize, DeferredNotifications& notifications) EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    AutoFile OpenUndoFile(const FlatFilePos& pos, bool fReadOnly = false) const;

    /**
     * Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain.
     * `chain_prune_range` is the result of Chainstate::GetPruneRange() for `chain`, without a height limit. The caller
     * computes it, because GetPruneRange() looks up block index entries, which takes the tree mutex.
     */
    void FindFilesToPruneManual(
        std::set<int>& setFilesToPrune,
        int nManualPruneHeight,
        const std::pair<int, int>& chain_prune_range,
        const Chainstate& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_tree_mutex, m_store_mutex);

    /**
     * Prune block and undo files (blk???.dat and rev???.dat) so that the disk space used is less than a user-defined target.
     * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
     * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
     * (which in this case means the blockchain must be re-downloaded.)
     *
     * Pruning functions are called from FlushStateToDisk when the m_check_for_pruning flag has been set.
     * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
     * Pruning cannot take place until the longest chain is at least a certain length (CChainParams::nPruneAfterHeight).
     * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
     * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
     * A db flag records the fact that at least some block files have been pruned.
     *
     * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
     * @param        last_prune        The last height we're able to prune, according to the prune locks
     * @param        chain_prune_range The result of Chainstate::GetPruneRange() for `chain`, without a height limit.
     *                                 The caller computes it, because GetPruneRange() looks up block index entries,
     *                                 which takes the tree mutex.
     */
    void FindFilesToPrune(
        std::set<int>& setFilesToPrune,
        int last_prune,
        const std::pair<int, int>& chain_prune_range,
        const Chainstate& chain,
        ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_tree_mutex, m_store_mutex);

    //! Since assumedvalid chainstates may be syncing a range of the chain that is very
    //! far away from the normal/background validation process, we should segment blockfiles
    //! for assumed chainstates. Otherwise, we might have wildly different height ranges
    //! mixed into the same block files, which would impair our ability to prune
    //! effectively.
    //!
    //! This data structure maintains separate blockfile number cursors for each
    //! BlockfileType. The ASSUMED state is initialized, when necessary, in FindNextBlockPos().
    //!
    //! The first element is the NORMAL cursor, second is ASSUMED.
    std::array<std::optional<BlockfileCursor>, BlockfileType::NUM_TYPES>
        m_blockfile_cursors GUARDED_BY(m_store_mutex) = {
            BlockfileCursor{},
            std::nullopt,
    };
    int MaxBlockfileNum() const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex)
    {
        AssertLockHeld(m_store_mutex);
        static const BlockfileCursor empty_cursor;
        const auto& normal = m_blockfile_cursors[BlockfileType::NORMAL].value_or(empty_cursor);
        const auto& assumed = m_blockfile_cursors[BlockfileType::ASSUMED].value_or(empty_cursor);
        return std::max(normal.file_num, assumed.file_num);
    }

    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool m_check_for_pruning GUARDED_BY(m_store_mutex) = false;

    const bool m_prune_mode;

    const Obfuscation m_obfuscation;

    /**
     * Map from external index name to oldest block that must not be pruned.
     *
     * @note Internally, only blocks at height (height_first - PRUNE_LOCK_BUFFER - 1) and
     * below will be pruned, but callers should avoid assuming any particular buffer size.
     */
    std::unordered_map<std::string, PruneLockInfo> m_prune_locks GUARDED_BY(m_store_mutex);

    BlockfileType BlockfileTypeForHeight(int height) EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    const kernel::BlockManagerOpts m_opts;

    const FlatFileSeq m_block_file_seq;
    const FlatFileSeq m_undo_file_seq;

    //! See GetBestHeader().
    CBlockIndex* m_best_header GUARDED_BY(m_tree_mutex){nullptr};

    //! The last header for which a headerTip notification was issued.
    CBlockIndex* m_last_notified_header GUARDED_BY(m_tree_mutex){nullptr};

    //! Set the best header to the most-work entry that is not known to be invalid, or to `active_tip` if it has more work.
    void RecalculateBestHeaderLocked(CBlockIndex* active_tip) EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);

protected:
    std::vector<CBlockFileInfo> m_blockfile_info GUARDED_BY(m_store_mutex);

    //! Block index entries that changed on the tree side (validity) and were not written yet. Entries are marked
    //! dirty by the lock that guards the change, in the same critical section, so that a flush that holds both
    //! locks always writes a consistent entry. An entry is written if it is in either set.
    std::set<CBlockIndex*> m_dirty_tree_index GUARDED_BY(m_tree_mutex);

    //! Block index entries that changed on the store side (storage status and position) and were not written yet.
    std::set<CBlockIndex*> m_dirty_store_index GUARDED_BY(m_store_mutex);

    /** Dirty block file entries. */
    std::set<int> m_dirty_fileinfo GUARDED_BY(m_store_mutex);

public:
    using Options = kernel::BlockManagerOpts;
    using ReadRawBlockResult = util::Expected<std::vector<std::byte>, ReadRawError>;

    explicit BlockManager(const util::SignalInterrupt& interrupt, Options opts);

    const util::SignalInterrupt& m_interrupt;
    std::atomic<bool> m_importing{false};

    /**
     * Whether all blockfiles have been added to the block tree database.
     * Normally true, but set to false when a reindex is requested and the
     * database is wiped. The value is persisted in the database across restarts
     * and will be false until reindexing completes.
     */
    std::atomic_bool m_blockfiles_indexed{true};

    /**
     * The block tree lock. With the block store lock below, it guards the block index and the state of the block
     * files. These two locks are the "block services".
     *
     * This lock guards:
     * - m_block_index, the map of block index entries: looking an entry up, iterating over all entries and
     *   inserting new ones. Entries are never erased while the node runs, so a pointer to one stays valid.
     * - the validity part of each entry's status (nValidityStatus): the BLOCK_VALID_* levels and the failure flags.
     * - the best header and the last notified header.
     * - the tree's set of dirty entries.
     *
     * The other fields of an entry do not need this lock. The header fields, phashBlock, pprev, pskip, nHeight,
     * nChainWork and nTimeMax never change once the entry is inserted. The storage fields are guarded by the
     * store lock. nSequenceId, m_chain_tx_count and m_blocks_unlinked belong to chain selection and are guarded
     * by cs_main.
     *
     * Lock order: cs_main, then this lock, then the store lock. A function that needs both takes the tree
     * lock first, never the other way around.
     *
     * The tree and the store locks are leaves. The code that holds either of them:
     * - does not take cs_main, nor any lock outside of these two. Logging is the exception: it takes the logger's
     *   own mutex, which is itself a leaf;
     * - does not call a notification or a callback. Errors found under the store lock are reported once it is
     *   released, see DeferredNotifications;
     * - does not wait for anything: no condition variable, no future, no draining of the validation queue.
     * Nothing can wait for a thread that holds one of them, so they cannot be part of a deadlock, whatever the
     * order a caller takes its other locks in.
     *
     * Every accessor comes in two forms. The one with the Locked suffix requires the lock, so that a caller can
     * read or change several things in one critical section. The other takes the lock itself. Two calls of the
     * second form in a row are not atomic. Loops and compound updates therefore take the lock once and use the
     * Locked form.
     */
    mutable Mutex m_tree_mutex ACQUIRED_AFTER(::cs_main);

    /**
     * The block store lock. It guards the state of the block files and of the data on disk:
     * - the storage part of each entry's status (nStorageStatus, which has BLOCK_HAVE_DATA, BLOCK_HAVE_UNDO and
     *   BLOCK_OPT_WITNESS) and its nFile, nDataPos, nUndoPos and nTx;
     * - the block file info, the blockfile cursors, and the set of dirty block files;
     * - the prune locks, the flag that requests a check for pruning, whether files were ever pruned, and the
     *   snapshot height that segments the block files;
     * - the store's set of dirty entries.
     *
     * Reading and writing block and undo files runs under this lock, and not under the tree lock: headers can be
     * accepted while a block is being written or a file is being flushed.
     *
     * The block tree database handle (m_block_tree_db) is not guarded: it is set once in the constructor, and the
     * database is safe to use from several threads. What it stores is guarded by the locks above, and a batch
     * is built while holding them, see WriteBlockIndexDB().
     *
     * For now, the block and undo writers (WriteBlock, UpdateBlockInfo, WriteBlockUndo, FlushChainstateBlockFile) and
     * everything that changes an existing entry also hold cs_main, which is why they are annotated as requiring
     * it. Pruning depends on that: FindFilesToPrune() selects the files and UnlinkPrunedFiles() unlinks them in
     * the same cs_main critical section of FlushStateToDisk(), so no block or undo data can be written to a
     * file between the two, only because every writer holds cs_main. Whoever lets a writer go without cs_main
     * has to make sure it cannot write to a file that was selected for pruning.
     *
     * The paths that change the block index without cs_main are the insertion of new entries (which are fully
     * built before they become visible), the best header, the last notified header and the prune locks.
     */
    mutable Mutex m_store_mutex ACQUIRED_AFTER(::cs_main, m_tree_mutex);

    BlockMap m_block_index GUARDED_BY(m_tree_mutex);

    /**
     * The height of the base block of an assumeutxo snapshot, if one is in use.
     *
     * This controls how blockfiles are segmented by chainstate type to avoid
     * comingling different height regions of the chain when an assumedvalid chainstate
     * is in use. If heights are drastically different in the same blockfile, pruning
     * suffers.
     *
     * This is set during ActivateSnapshot() or upon LoadBlockIndex() if a snapshot
     * had been previously loaded. After the snapshot is validated, this is unset to
     * restore normal LoadBlockIndex behavior.
     */
    std::optional<int> m_snapshot_height GUARDED_BY(m_store_mutex);

    std::vector<CBlockIndex*> GetAllBlockIndices() EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    std::vector<CBlockIndex*> GetAllBlockIndicesLocked() EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);

    //! Number of entries in the block index.
    size_t BlockIndexSize() const EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    size_t BlockIndexSizeLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);

    /**
     * Best header we've seen so far for which the block is not known to be invalid
     * (used, among others, for getheaders queries' starting points).
     * In case of multiple best headers with the same work, it could point to any
     * because CBlockIndexWorkComparator tiebreaker rules are not applied.
     * Read it once per function: two reads can return different headers.
     */
    CBlockIndex* GetBestHeader() const EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    CBlockIndex* GetBestHeaderLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);
    void SetBestHeader(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    void SetBestHeaderLocked(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);
    //! Set the best header to `index`, unless one is already set. Atomic, unlike a read followed by a write.
    void SetBestHeaderIfUnset(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    //! Return the best header and remember it as the last one that was notified, unless it already was.
    //! Returns nullptr if the last notified header is the best header.
    CBlockIndex* UpdateLastNotifiedHeader() EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);

    /** The mutable fields of a block index entry, passed to ModifyIndex(). */
    struct IndexFields {
        uint32_t& nValidityStatus;
        uint32_t& nStorageStatus;
        int& nFile;
        unsigned int& nDataPos;
        unsigned int& nUndoPos;
        unsigned int& nTx;
    };

    //! The validity part of the status (BLOCK_VALID_* levels and failure flags), owned by the block tree.
    uint32_t GetValidityStatus(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    uint32_t GetValidityStatusLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);
    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(const CBlockIndex& index, enum BlockStatus nUpTo) const EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    bool IsValidLocked(const CBlockIndex& index, enum BlockStatus nUpTo) const EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);
    //! Raise the validity level of this block index entry, and flag it for writing if it changed. Returns true if the validity was changed.
    bool RaiseValidity(CBlockIndex& index, enum BlockStatus nUpTo) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_tree_mutex);
    bool RaiseValidityLocked(CBlockIndex& index, enum BlockStatus nUpTo) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_tree_mutex);

    /** Mark a block as failed (BLOCK_FAILED_VALID), and flag it for writing. Its descendants and the best header are left alone. */
    void SetFailedLocked(CBlockIndex& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_tree_mutex);

    /**
     * Mark a block and all its descendants as failed, and flag them for writing. If the best header was on the
     * failed branch, recalculate it, with `active_tip` as the fallback. The block, its descendants and the best
     * header are updated in one critical section of the tree lock, so nobody sees the best header on a failed
     * chain, nor a descendant of a failed block that is not failed.
     *
     * The descendants are found by walking the whole block index, which is what has always been done, and
     * which holds the tree lock for the duration of the walk. Headers cannot be added in the meantime.
     */
    void MarkFailed(CBlockIndex& block, CBlockIndex* active_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_tree_mutex);

    /**
     * Remove the failure flag from a block, its descendants and its ancestors, flag them for writing, and
     * recalculate the best header, with `active_tip` as the fallback, in one critical section. Returns the
     * entries that were failed.
     */
    std::vector<CBlockIndex*> ResetFailed(CBlockIndex& block, CBlockIndex* active_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_tree_mutex);

    //! The storage part of the status (BLOCK_HAVE_DATA, BLOCK_HAVE_UNDO, BLOCK_OPT_WITNESS), and the position and
    //! number of transactions of the block, owned by the block store.
    uint32_t GetStorageStatus(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    uint32_t GetStorageStatusLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    unsigned int GetNumTx(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    unsigned int GetNumTxLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    //! Raw file and offset fields, which are only meaningful if the matching status flag is set.
    int GetFileNum(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    int GetFileNumLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    unsigned int GetDataOffset(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    unsigned int GetDataOffsetLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    unsigned int GetUndoOffset(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    unsigned int GetUndoOffsetLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    FlatFilePos GetBlockPos(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    FlatFilePos GetBlockPosLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);
    FlatFilePos GetUndoPos(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    FlatFilePos GetUndoPosLocked(const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    /** Set BLOCK_OPT_WITNESS on a block, and flag it for writing. */
    void SetOptWitness(CBlockIndex& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_store_mutex);
    void SetOptWitnessLocked(CBlockIndex& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_store_mutex);

    /**
     * Record that the full data of a block was written at `pos`: its position, its number of transactions and
     * BLOCK_HAVE_DATA (with BLOCK_OPT_WITNESS if `opt_witness`), and raise its validity to BLOCK_VALID_TRANSACTIONS. This
     * is a single operation that takes the tree lock, then the store lock, and holds both until it is done: nobody
     * sees a block that has transactions but no data, or the reverse, nor a flush that writes half of it. The undo
     * position is reset: this is also how a pruned block that is downloaded again is recorded.
     *
     * This does not touch chain selection (sequence id, chain transaction count, unlinked blocks and candidates):
     * that is up to ChainstateManager::ReceivedBlockTransactions().
     */
    void RecordBlockData(CBlockIndex& index, unsigned int num_tx, const FlatFilePos& pos, bool opt_witness) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_tree_mutex, !m_store_mutex);

    /**
     * Change the mutable state of a block index entry, under both locks. `modify` must not call back into
     * BlockManager. It does not flag the entry for writing, nor does it check that the entry is part of the
     * block index: it is meant for tests, and for the load of the block index.
     */
    template <typename F>
    void ModifyIndex(CBlockIndex& index, F&& modify) EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex, !m_store_mutex)
    {
        LOCK2(m_tree_mutex, m_store_mutex);
        ModifyIndexLocked(index, std::forward<F>(modify));
    }

    template <typename F>
    void ModifyIndexLocked(CBlockIndex& index, F&& modify) EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex, m_store_mutex)
    {
        AssertLockHeld(m_tree_mutex);
        AssertLockHeld(m_store_mutex);
        IndexFields fields{index.nValidityStatus, index.nStorageStatus, index.nFile, index.nDataPos, index.nUndoPos, index.nTx};
        std::forward<F>(modify)(fields);
    }

    /**
     * All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     */
    //! Unlinked blocks feed the candidates for chain selection, so this is guarded by cs_main.
    std::multimap<CBlockIndex*, CBlockIndex*> m_blocks_unlinked GUARDED_BY(::cs_main);
    //! The caller makes sure that `block` has data.
    void AddUnlinkedBlock(CBlockIndex* block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! The block tree database. The handle is set once, in the constructor. See m_store_mutex.
    const std::unique_ptr<BlockTreeDB> m_block_tree_db;

    /**
     * Write the dirty block index entries and block file info to the block tree database, in a synced write.
     *
     * The batch is built while holding the tree and store locks, since the entries are live objects, and the
     * synced write happens after they are released, so that neither headers nor block I/O wait for the disk.
     * The caller must hold cs_main for the whole of FlushStateToDisk(): every change to an existing entry holds
     * it too, so nothing can change an entry between the capture and the write. Entries that are inserted in the
     * meantime stay dirty, and are written by the next flush.
     */
    void WriteBlockIndexDB() EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_tree_mutex, !m_store_mutex);
    bool LoadBlockIndexDB(const std::optional<uint256>& snapshot_blockhash)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_tree_mutex, !m_store_mutex);

    /**
     * Remove any pruned block & undo files that are still on disk.
     * This could happen on some systems if the file was still being read while unlinked,
     * or if we crash before unlinking.
     */
    void ScanAndUnlinkAlreadyPrunedFiles() EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);

    //! Add a header to the block index, and make it the best header if it has more work. Returns the existing entry if the header is already known.
    CBlockIndex* AddToBlockIndex(const CBlockHeader& block) EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    CBlockIndex* AddToBlockIndexLocked(const CBlockHeader& block) EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);
    /** Create a new block index entry for a given block hash */
    CBlockIndex* InsertBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);

    //! Mark one block file as pruned (modify associated database entries)
    void PruneOneBlockFile(int fileNumber) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_tree_mutex, m_store_mutex);

    CBlockIndex* LookupBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    CBlockIndex* LookupBlockIndexLocked(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);
    const CBlockIndex* LookupBlockIndex(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!m_tree_mutex);
    const CBlockIndex* LookupBlockIndexLocked(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(m_tree_mutex);

    /** Get block file info entry for one block file. The pointer is only valid while the store lock is held. */
    CBlockFileInfo* GetBlockFileInfo(size_t n) EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    /** Write the undo data of a block, and record its position in the block's entry. Requires cs_main, see m_store_mutex. */
    bool WriteBlockUndo(const CBlockUndo& blockundo, BlockValidationState& state, CBlockIndex& block)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_store_mutex);

    /** Store block on disk and update block file statistics. Requires cs_main, see m_store_mutex.
     *
     * @param[in]  block        the block to be stored
     * @param[in]  nHeight      the height of the block
     *
     * @returns in case of success, the position to which the block was written to
     *          in case of an error, an empty FlatFilePos
     */
    FlatFilePos WriteBlock(const CBlock& block, int nHeight) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_store_mutex);

    /** Update blockfile info while processing a block during reindex. The block must be available on disk.
     * Requires cs_main, see m_store_mutex.
     *
     * @param[in]  block        the block being processed
     * @param[in]  nHeight      the height of the block
     * @param[in]  pos          the position of the serialized CBlock on disk
     */
    void UpdateBlockInfo(const CBlock& block, unsigned int nHeight, const FlatFilePos& pos) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_store_mutex);

    /** Flush the block and undo file the chainstate with the given tip height is writing to. Requires cs_main, see m_store_mutex. */
    [[nodiscard]] bool FlushChainstateBlockFile(int tip_height) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !m_store_mutex);

    /** Whether running in -prune mode. */
    [[nodiscard]] bool IsPruneMode() const { return m_prune_mode; }

    /** Attempt to stay below this number of bytes of block files. */
    [[nodiscard]] uint64_t GetPruneTarget() const { return m_opts.prune_target; }
    static constexpr auto PRUNE_TARGET_MANUAL{std::numeric_limits<uint64_t>::max()};

    [[nodiscard]] bool LoadingBlocks() const { return m_importing || !m_blockfiles_indexed; }

    /** Calculate the amount of disk space the block & undo files currently use */
    uint64_t CalculateCurrentUsage() EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    //! Check if all blocks in the [upper_block, lower_block] range have data available as
    //! defined by the status mask.
    //! The caller is responsible for ensuring that lower_block is an ancestor of upper_block
    //! (part of the same chain).
    bool CheckBlockDataAvailability(const CBlockIndex& upper_block, const CBlockIndex& lower_block, BlockStatus block_status = BLOCK_HAVE_DATA) EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);

    /**
     * @brief Returns the earliest block with specified `status_mask` flags set after
     * the latest block _not_ having those flags.
     *
     * This function starts from `upper_block`, which must have all
     * `status_mask` flags set, and iterates backwards through its ancestors. It
     * continues as long as each block has all `status_mask` flags set, until
     * reaching the oldest ancestor or `lower_block`. The flags must be storage
     * flags (see BLOCK_STORAGE_MASK).
     *
     * @pre `upper_block` must have all `status_mask` flags set.
     * @pre `lower_block` must be null or an ancestor of `upper_block`
     *
     * @param upper_block The starting block for the search, which must have all
     *                    `status_mask` flags set.
     * @param status_mask Bitmask specifying required status flags.
     * @param lower_block The earliest possible block to return. If null, the
     *                    search can extend to the genesis block.
     *
     * @return A reference to the earliest block between `upper_block`
     *         and `lower_block`, inclusive, such that every block between the
     *         returned block and `upper_block` has `status_mask` flags set.
     */
    const CBlockIndex& GetFirstBlock(
        const CBlockIndex& upper_block LIFETIMEBOUND,
        uint32_t status_mask,
        const CBlockIndex* lower_block LIFETIMEBOUND = nullptr
    ) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    const CBlockIndex& GetFirstBlockLocked(
        const CBlockIndex& upper_block LIFETIMEBOUND,
        uint32_t status_mask,
        const CBlockIndex* lower_block LIFETIMEBOUND = nullptr
    ) const EXCLUSIVE_LOCKS_REQUIRED(m_store_mutex);

    /** True if any block files have ever been pruned. */
    bool m_have_pruned GUARDED_BY(m_store_mutex) = false;

    //! Check whether the block associated with this index entry is pruned or not.
    bool IsBlockPruned(const CBlockIndex& block) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);

    //! Create or update a prune lock identified by its name. Does not need cs_main.
    void UpdatePruneLock(const std::string& name, const PruneLockInfo& lock_info) EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);

    //! Delete a prune lock identified by its name. Returns true if the lock existed. Does not need cs_main.
    bool DeletePruneLock(const std::string& name) EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);

    /** Open a block file (blk?????.dat) */
    AutoFile OpenBlockFile(const FlatFilePos& pos, bool fReadOnly) const;

    /** Translation to a filesystem path */
    fs::path GetBlockPosFilename(const FlatFilePos& pos) const;

    /**
     *  Actually unlink the specified files
     */
    void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune) const;

    /** Functions for disk access for blocks */
    bool ReadBlock(CBlock& block, const FlatFilePos& pos, const std::optional<uint256>& expected_hash) const;
    bool ReadBlock(CBlock& block, const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);
    ReadRawBlockResult ReadRawBlock(const FlatFilePos& pos, std::optional<std::pair<size_t, size_t>> block_part = std::nullopt) const;

    bool ReadBlockUndo(CBlockUndo& blockundo, const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(!m_store_mutex);

    void CleanupBlockRevFiles() const;
};

// Calls ActivateBestChain() even if no blocks are imported.
void ImportBlocks(ChainstateManager& chainman, std::span<const fs::path> import_paths);
} // namespace node

#endif // BITCOIN_NODE_BLOCKSTORAGE_H
