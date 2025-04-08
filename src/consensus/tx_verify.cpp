// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <span.h>
#include <streams.h>
#include <util/check.h>
#include <util/moneystr.h>

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;

    // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
    // transaction is still considered final if all inputs' nSequence ==
    // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
    //
    // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
    // also check that the spending input's nSequence != SEQUENCE_FINAL,
    // ensuring that an unsatisfied nLockTime value will actually cause
    // IsFinalTx() to return false here:
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, uint32_t flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

//! Mask used to extract the constraint type from the output index.
static constexpr uint32_t CONSTRAINT_TYPE_MASK{0xFFU << 24};

/** Type of constraint to apply on the value of the output at the specified index. */
enum class ConstraintType: uint8_t {
    //! Transfer all this input's (remaining) value to the specified output.
    SWEEP,
    //! Transfer part of this input's value to the specified output.
    DEDUCT,
    NUM_TYPES,
};

/** A constraint applied on the transfer of an input's value. */
struct AmountConstraint {
    //! First 8 bits are the constraint type. Last 24 bits are the output index.
    uint32_t index;
    //! Amount covered by this constraint. Must be 0 if constraint type is SWEEP.
    uint64_t amount;

    // Of course a real implementation would use an optimized serialization. We use a simple one here
    // for demonstration purposes.
    SERIALIZE_METHODS(AmountConstraint, obj) { READWRITE(obj.index, obj.amount); }
};

/**
 * Quick and dirty "amount covenant" through the annex.
 *
 * This intends to replicate the semantics proposed by Salvatore Ingala for OP_CCV: https://delvingbitcoin.org/t/op-checkcontractverify-and-its-amount-semantic/1527.
 *
 * We interpret the annex as a list of constraints on how this input's value is transferred to the
 * transaction outputs (see AmountConstraint above). This is accomplished by keeping a list of the
 * minimum amount for each output in the transaction. By going through each constraint in each of
 * the transaction's inputs, we bump the minimum amount for the output at the specified index. Then
 * we'll assert the value of each output in the transaction is at least as much as specified in the
 * list.
 */
static bool RecordAmountConstraints(const CTxIn& txin, const CAmount pre_amount, std::vector<CAmount>& amounts, TxValidationState& state)
{
    const auto& stack{txin.scriptWitness.stack};
    if (stack.size() < 2) return true;

    const auto& annex{stack.back()};
    if (annex.empty() || annex.front() != ANNEX_TAG) return true;

    std::vector<AmountConstraint> amount_constraints;
    SpanReader{{&annex[1], annex.size() - 1}} >> amount_constraints; // FIXME: catch exception.

    auto in_amount{static_cast<uint64_t>(pre_amount)};
    for (const auto constraint: amount_constraints) {
        const auto type{static_cast<ConstraintType>((constraint.index & CONSTRAINT_TYPE_MASK) >> 24)};
        const auto out_index{constraint.index & ~CONSTRAINT_TYPE_MASK};

        if (type >= ConstraintType::NUM_TYPES) return true;
        if (out_index >= amounts.size()) {
            // FIXME: should we return true for upgradability reasons? The presence of the output should
            // be guaranteed by other means anyways.
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-annex-output-out-of-range");
        }

        if (type == ConstraintType::SWEEP) {
            if (constraint.amount != 0) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-annex-sweep-nonzero-amount");
            }
            amounts[out_index] += in_amount;
            in_amount = 0;
            return true;
        }

        if (type == ConstraintType::DEDUCT) {
            if (constraint.amount > in_amount) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-annex-deduct-overflow");
            }
            in_amount -= constraint.amount;
            amounts[out_index] += constraint.amount;
            continue;
        }

        assert(!"All constraint types must have been covered.");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    std::vector<CAmount> out_constraints(tx.vout.size(), 0); // Record the minimum value of each output in the transaction.
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }

        // If any amount constraint was set in this input, bump the minimum value of specified outputs.
        int wit_version;
        std::vector<unsigned char> wit_prog;
        if (coin.out.scriptPubKey.IsWitnessProgram(wit_version, wit_prog)
            && wit_version == 1 && wit_prog.size() == WITNESS_V1_TAPROOT_SIZE
            && !RecordAmountConstraints(tx.vin[i], coin.out.nValue, out_constraints, state)) {
            return false; // state filled in by RecordAmountConstraints()
        }
    }

    const CAmount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
    }

    // Make sure the outputs respect any constraint that was set in the transaction's inputs.
    for (size_t i{0}; i < tx.vout.size(); ++i) {
        if (tx.vout[i].nValue < out_constraints[i]) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-amount-constraint",
                strprintf("Output at index %u is constrained to have value at least %i but has value %i", i, out_constraints[i], tx.vout[i].nValue));
        }
    }

    txfee = txfee_aux;
    return true;
}
