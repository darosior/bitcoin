// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/feerate.h>

#include <tinyformat.h>

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nSize_, bool vbyte)
{
    if (vbyte) nSize_ *= WITNESS_SCALE_FACTOR;
    assert(nSize_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nSize_);

    if (nSize > 0)
        nSatoshisPerK = nFeePaid * 1000 / nSize;
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::nSatoshisPerKVbyte() const
{
    return nSatoshisPerK * WITNESS_SCALE_FACTOR;
}

CAmount CFeeRate::GetFee(size_t nSize_, bool vbyte) const
{
    if (vbyte) nSize_ *= WITNESS_SCALE_FACTOR;
    assert(nSize_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nSize_);

    CAmount nFee = nSatoshisPerK * nSize / 1000;

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0)
            nFee = CAmount(1);
        if (nSatoshisPerK < 0)
            nFee = CAmount(-1);
    }

    return nFee;
}

std::string CFeeRate::ToString(const FeeEstimateMode& fee_estimate_mode) const
{
    switch (fee_estimate_mode) {
    case FeeEstimateMode::SAT_B:  return strprintf("%d.%03d %s/B", nSatoshisPerKVbyte() / 1000, nSatoshisPerKVbyte() % 1000, CURRENCY_ATOM);
    default:                      return strprintf("%d.%08d %s/kB", nSatoshisPerKVbyte() / COIN, nSatoshisPerKVbyte() % COIN, CURRENCY_UNIT);
    }
}
