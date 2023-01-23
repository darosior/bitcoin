// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BENCH_UTIL_WALLET_COMMON_H
#define BITCOIN_BENCH_UTIL_WALLET_COMMON_H

#include <wallet/context.h>
#include <wallet/wallet.h>

using wallet::CWallet;
using wallet::DatabaseOptions;
using wallet::WalletContext;
using wallet::WalletDatabase;

const std::string ADDRESS_BCRT1_UNSPENDABLE = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj";

std::shared_ptr<CWallet> BenchLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, DatabaseOptions& options);
void BenchUnloadWallet(std::shared_ptr<CWallet>&& wallet);

#endif // BITCOIN_BENCH_UTIL_WALLET_COMMON_H
