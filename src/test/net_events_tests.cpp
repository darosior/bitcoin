// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <banman.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <net.h>
#include <net_processing.h>
#include <node/context.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <memory>

namespace {
struct PeerManagerSetup : public TestChain100Setup {
    std::unique_ptr<BanMan> banman;
    std::unique_ptr<ConnmanTestMsg> connman;
    std::unique_ptr<PeerManager> peerman;

    PeerManagerSetup()
    {
        banman = std::make_unique<BanMan>(m_args.GetDataDirBase() / "banlist", nullptr, DEFAULT_MISBEHAVING_BANTIME);
        connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params());
        peerman = PeerManager::make(*connman, *m_node.addrman, banman.get(), *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
        connman->SetMsgProc(peerman.get());
        // The notifications of validation reach the peer manager as events.
        m_node.validation_signals->RegisterValidationInterface(peerman.get());
    }

    ~PeerManagerSetup()
    {
        m_node.validation_signals->UnregisterValidationInterface(peerman.get());
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
    }

    //! A peer that completed the handshake.
    std::unique_ptr<CNode> MakePeer(NodeId id) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        auto peer{std::make_unique<CNode>(id,
                                          /*sock=*/nullptr,
                                          CAddress{CService{CNetAddr{in_addr{htonl(0xa0b0c000 + id)}}, Params().GetDefaultPort()}, NODE_NONE},
                                          /*nKeyedNetGroupIn=*/0,
                                          /*nLocalHostNonceIn=*/0,
                                          CAddress(),
                                          /*addrNameIn=*/"",
                                          ConnectionType::OUTBOUND_FULL_RELAY,
                                          /*inbound_onion=*/false,
                                          /*network_key=*/0)};
        connman->Handshake(*peer, /*successfully_connected=*/true, ServiceFlags(NODE_NETWORK | NODE_WITNESS), ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                           PROTOCOL_VERSION, /*relay_txs=*/true);
        return peer;
    }

    //! Send a message to the peer, and have it processed.
    void Send(CNode& peer, CSerializedNetMsg&& msg) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        connman->FlushSendBuffer(peer); // Drop messages we sent, the transport is shared with the fake peer.
        BOOST_REQUIRE(connman->ReceiveMsgFrom(peer, std::move(msg)));
        peer.fPauseSend = false;
        connman->ProcessMessagesOnce(peer);
    }
};

//! Replace the coinbase script of `block`, and solve it again.
std::shared_ptr<const CBlock> WithCoinbaseScript(const ChainstateManager& chainman, CBlock block, const CScript& script_sig)
{
    CMutableTransaction coinbase{*block.vtx[0]};
    coinbase.vin[0].scriptSig = script_sig;
    block.vtx[0] = MakeTransactionRef(coinbase);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) ++block.nNonce;
    return std::make_shared<const CBlock>(block);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(net_events_tests, PeerManagerSetup)

//! What validation notifies is only processed when the message handler thread processes its events, whichever
//! thread the notifications are made by (here, the scheduler thread), and in the order they came in.
BOOST_AUTO_TEST_CASE(events_from_another_thread_are_processed_on_drain_in_order)
{
    const auto consensus{m_node.chainman->GetParams().GetConsensus()};
    const ServiceFlags limited{NODE_NETWORK_LIMITED | NODE_WITNESS};
    const ServiceFlags full{NODE_NETWORK | NODE_WITNESS};
    // Peers that only serve the last blocks are only useful if our tip is recent.
    SetMockTime(std::chrono::seconds{1'700'000'000});
    const uint256 stale_hash{uint256::ONE}, recent_hash{uint256::FromUserHex("02").value()};
    const auto make_block_index{[&](std::chrono::seconds time, const uint256& hash) {
        CBlockHeader header;
        header.nTime = time.count();
        auto index{std::make_unique<CBlockIndex>(header)};
        index->nHeight = 1000;
        index->phashBlock = &hash;
        return index;
    }};
    const auto stale{make_block_index(std::chrono::seconds{1'700'000'000} - 1000 * std::chrono::seconds{consensus.nPowTargetSpacing}, stale_hash)};
    const auto recent{make_block_index(std::chrono::seconds{1'700'000'000}, recent_hash)};

    // Nothing is known about the tip yet.
    BOOST_CHECK(peerman->GetDesirableServiceFlags(limited) == full);

    // A stale tip, then a recent one. The notifications are queued to the scheduler thread, which makes them.
    m_node.validation_signals->UpdatedBlockTip(stale.get(), nullptr, /*fInitialDownload=*/true);
    m_node.validation_signals->UpdatedBlockTip(recent.get(), stale.get(), /*fInitialDownload=*/true);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // They have no effect until they are processed.
    BOOST_CHECK(peerman->GetDesirableServiceFlags(limited) == full);
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        peerman->ProcessPendingEvents();
    }
    // The recent tip came last, so that is the one we know.
    BOOST_CHECK(peerman->GetDesirableServiceFlags(limited) == limited);

    // The other way around: the stale tip came last. Nothing happens a second time on a second drain.
    m_node.validation_signals->UpdatedBlockTip(recent.get(), nullptr, /*fInitialDownload=*/true);
    m_node.validation_signals->UpdatedBlockTip(stale.get(), recent.get(), /*fInitialDownload=*/true);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(peerman->GetDesirableServiceFlags(limited) == limited);
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        peerman->ProcessPendingEvents();
        BOOST_CHECK(peerman->GetDesirableServiceFlags(limited) == full);
        peerman->ProcessPendingEvents();
    }
    BOOST_CHECK(peerman->GetDesirableServiceFlags(limited) == full);
}

//! When a peer sends an invalid block, BlockChecked punishes it while its message is processed, and not later: it is
//! discouraged as soon as the processing of its next message has finished.
BOOST_AUTO_TEST_CASE(block_checked_punishes_the_peer_before_its_next_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const auto peer{MakePeer(0)};
    const CNetAddr addr{peer->addr};

    // A block with a valid proof of work and merkle root that is invalid because of the height in its coinbase.
    const CBlock template_block{CreateBlock({}, CScript{} << OP_TRUE)};
    const auto bad_block{WithCoinbaseScript(*m_node.chainman, template_block, CScript{} << 1 << OP_0)};

    BOOST_CHECK(!banman->IsDiscouraged(addr));
    Send(*peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*bad_block)));
    // No call to ProcessPendingEvents() in between: the message processing handled the event on its own.
    BOOST_CHECK(peerman->SendMessages(*peer));
    BOOST_CHECK(banman->IsDiscouraged(addr));
    peerman->FinalizeNode(*peer);
}

//! When a peer sends a block that changes the tip, ActiveTipChange resets the filter of rejected transactions
//! while its message is processed, so that the next message of the peer is evaluated with the new tip: here, a
//! transaction that was not final yet is accepted when the peer sends it again.
BOOST_AUTO_TEST_CASE(active_tip_change_resets_the_reject_filter_before_the_next_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const auto peer{MakePeer(0)};

    // Mature coins that anybody can spend.
    const CScript anyone_can_spend{GetScriptForDestination(ScriptHash{CScript{} << OP_TRUE})};
    const CTransactionRef funding{MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/1, coinbaseKey, anyone_can_spend, 10 * COIN, /*submit=*/false))};
    CreateAndProcessBlock({CMutableTransaction{*funding}}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    const int height{WITH_LOCK(::cs_main, return m_node.chainman->ActiveHeight())};

    // A transaction that is only final in the block after the next one.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{funding->GetHash(), 0}, CScript{} << std::vector<unsigned char>{OP_TRUE}, /*nSequenceIn=*/0);
    mtx.vout.emplace_back(10 * COIN - 10000, anyone_can_spend);
    mtx.nLockTime = height + 1;
    const CTransactionRef tx{MakeTransactionRef(mtx)};

    // The transaction is rejected, and the node remembers it.
    Send(*peer, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)));
    BOOST_CHECK(!m_node.mempool->exists(tx->GetHash()));
    // It is not tried again as long as the filter is not reset.
    Send(*peer, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)));
    BOOST_CHECK(!m_node.mempool->exists(tx->GetHash()));

    // The peer sends a block, which makes the transaction final.
    const auto block{std::make_shared<const CBlock>(CreateBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())))};
    Send(*peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*block)));
    BOOST_REQUIRE_EQUAL(WITH_LOCK(::cs_main, return m_node.chainman->ActiveHeight()), height + 1);

    // No call to ProcessPendingEvents(): the next message of the peer already sees the filter reset.
    Send(*peer, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)));
    BOOST_CHECK(m_node.mempool->exists(tx->GetHash()));
    peerman->FinalizeNode(*peer);
}

BOOST_AUTO_TEST_SUITE_END()
