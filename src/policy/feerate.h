// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_FEERATE_H
#define BITCOIN_POLICY_FEERATE_H

#include <amount.h>
#include <serialize.h>

#include <string>

extern const std::string CURRENCY_UNIT;

/**
 * Fee rate in satoshis per weight: CAmount / kW
 */
class CFeeRate
{
private:
    CAmount nSatoshisPerK; // unit is satoshis-per-1,000-weight

public:
    /** Fee rate of 0 satoshis per kW */
    CFeeRate() : nSatoshisPerK(0) { }
    template<typename I>
    explicit CFeeRate(const I _nSatoshisPerK): nSatoshisPerK(_nSatoshisPerK) {
        // We've previously had bugs creep in from silent double->int conversion...
        static_assert(std::is_integral<I>::value, "CFeeRate should be used without floats");
    }
    /** Constructor for a fee rate in satoshis per kW. The size in weight must not exceed (2^63 - 1)*/
    CFeeRate(const CAmount& nFeePaid, size_t nWeight);
    /**
     * Return the fee in satoshis for the given size in weight units.
     */
    CAmount GetFee(size_t nWeight) const;
    /**
     * Return the fee in satoshis for a size of 1000 weight units.
     */
    CAmount GetFeePerK() const { return GetFee(1000); }
    friend bool operator<(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK < b.nSatoshisPerK; }
    friend bool operator>(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK > b.nSatoshisPerK; }
    friend bool operator==(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK == b.nSatoshisPerK; }
    friend bool operator<=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK <= b.nSatoshisPerK; }
    friend bool operator>=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK >= b.nSatoshisPerK; }
    friend bool operator!=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK != b.nSatoshisPerK; }
    CFeeRate& operator+=(const CFeeRate& a) { nSatoshisPerK += a.nSatoshisPerK; return *this; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSatoshisPerK);
    }
};

#endif //  BITCOIN_POLICY_FEERATE_H
