// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_FEERATE_H
#define BITCOIN_POLICY_FEERATE_H

#include <amount.h>
#include <consensus/consensus.h>
#include <serialize.h>

#include <string>

const std::string CURRENCY_UNIT = "BTC"; // One formatted unit
const std::string CURRENCY_ATOM = "sat"; // One indivisible minimum value unit

/* Used to determine type of fee estimation requested */
enum class FeeEstimateMode {
    UNSET,        //!< Use default settings based on other criteria
    ECONOMICAL,   //!< Force estimateSmartFee to use non-conservative estimates
    CONSERVATIVE, //!< Force estimateSmartFee to use conservative estimates
    BTC_KB,       //!< Use explicit BTC/kB fee given in coin control
    SAT_B,        //!< Use explicit sat/B fee given in coin control
};

/**
 * Fee rate in satoshis per kiloweight: CAmount / kW
 */
class CFeeRate
{
private:
    CAmount nSatoshisPerK; // unit is satoshis-per-1,000-weight-units
    CAmount nSatoshisPerKVbyte() const;

public:
    /** Fee rate of 0 satoshis per kW */
    CFeeRate() : nSatoshisPerK(0) { }
    template<typename I>
    explicit CFeeRate(const I _nSatoshisPerK, bool vbyte=true): nSatoshisPerK(_nSatoshisPerK) {
        // We've previously had bugs creep in from silent double->int conversion...
        static_assert(std::is_integral<I>::value, "CFeeRate should be used without floats");
        // Round up if we're passed a feerate in vbytes.
        if (vbyte) nSatoshisPerK = (nSatoshisPerK /* FIXME + WITNESS_SCALE_FACTOR - 1*/) / WITNESS_SCALE_FACTOR;
    }
    /** Constructor for a fee rate either in satoshis per kB or per kW. The size must not exceed (2^63 - 1)*/
    CFeeRate(const CAmount& nFeePaid, size_t nSize, bool vbyte=true);
    /**
     * Return the fee in satoshis for the given size in bytes.
     */
    CAmount GetFee(size_t nSize, bool vbyte=true) const;
    /**
     * Return the fee in satoshis for a size of 1000 bytes
     */
    CAmount GetFeePerK() const { return GetFee(1000); }
    friend bool operator<(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK < b.nSatoshisPerK; }
    friend bool operator>(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK > b.nSatoshisPerK; }
    friend bool operator==(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK == b.nSatoshisPerK; }
    friend bool operator<=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK <= b.nSatoshisPerK; }
    friend bool operator>=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK >= b.nSatoshisPerK; }
    friend bool operator!=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK != b.nSatoshisPerK; }
    CFeeRate& operator+=(const CFeeRate& a) { nSatoshisPerK += a.nSatoshisPerK; return *this; }
    std::string ToString(const FeeEstimateMode& fee_estimate_mode = FeeEstimateMode::BTC_KB) const;

    SERIALIZE_METHODS(CFeeRate, obj) { READWRITE(obj.nSatoshisPerK); }
};

#endif //  BITCOIN_POLICY_FEERATE_H
