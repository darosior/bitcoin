// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/feerate.h>

#include <tinyformat.h>

const std::string CURRENCY_UNIT = "BTC";

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nWeight_)
{
    assert(nWeight_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nWU = int64_t(nWeight_);

    if (nWU > 0)
        nSatoshisPerK = nFeePaid * 1000 / nWU;
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nWeight_) const
{
    assert(nWeight_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nWU = int64_t(nWeight_);

    CAmount nFee = nSatoshisPerK * nWU / 1000;

    if (nFee == 0 && nWeight_ != 0) {
        if (nSatoshisPerK > 0)
            nFee = CAmount(1);
        if (nSatoshisPerK < 0)
            nFee = CAmount(-1);
    }

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%08d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}
