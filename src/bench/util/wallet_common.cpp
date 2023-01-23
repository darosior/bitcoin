// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <bench/util/wallet_common.h>

#include <validationinterface.h>

std::shared_ptr<CWallet> BenchLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, DatabaseOptions& options)
{
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CWallet::Create(context, "", std::move(database), options.create_flags, error, warnings);
    NotifyWalletLoaded(context, wallet);
    if (context.chain) {
        wallet->postInitProcess();
    }
    return wallet;
}

void BenchUnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    SyncWithValidationInterfaceQueue();
    wallet->m_chain_notifications_handler.reset();
    UnloadWallet(std::move(wallet));
}
