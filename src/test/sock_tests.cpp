// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <compat/compat.h>
#include <netbase.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifndef WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(sock_tests, BasicTestingSetup)

static bool SocketIsClosed(const SOCKET& s)
{
    // Notice that if another thread is running and creates its own socket after `s` has been
    // closed, it may be assigned the same file descriptor number. In this case, our test will
    // wrongly pretend that the socket is not closed.
    int type;
    socklen_t len = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &len) == SOCKET_ERROR;
}

static SOCKET CreateSocket()
{
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(s != static_cast<SOCKET>(SOCKET_ERROR));
#ifdef SO_NOSIGPIPE
    const int on{1};
    BOOST_REQUIRE_EQUAL(setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&on), sizeof(on)), 0);
#endif
    return s;
}

BOOST_AUTO_TEST_CASE(constructor_and_destructor)
{
    const SOCKET s = CreateSocket();
    Sock* sock = new Sock(s);
    BOOST_CHECK(*sock == s);
    BOOST_CHECK(!SocketIsClosed(s));
    delete sock;
    BOOST_CHECK(SocketIsClosed(s));
}

BOOST_AUTO_TEST_CASE(move_constructor)
{
    const SOCKET s = CreateSocket();
    Sock* sock1 = new Sock(s);
    Sock* sock2 = new Sock(std::move(*sock1));
    delete sock1;
    BOOST_CHECK(!SocketIsClosed(s));
    BOOST_CHECK(*sock2 == s);
    delete sock2;
    BOOST_CHECK(SocketIsClosed(s));
}

BOOST_AUTO_TEST_CASE(move_assignment)
{
    const SOCKET s1 = CreateSocket();
    const SOCKET s2 = CreateSocket();
    Sock* sock1 = new Sock(s1);
    Sock* sock2 = new Sock(s2);

    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(!SocketIsClosed(s2));

    *sock2 = std::move(*sock1);
    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
    BOOST_CHECK(*sock2 == s1);

    delete sock1;
    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
    BOOST_CHECK(*sock2 == s1);

    delete sock2;
    BOOST_CHECK(SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
}

struct TcpSocketPair {
    Sock sender;
    Sock receiver;

    TcpSocketPair()
        : sender{Sock{CreateSocket()}},
        receiver{Sock{CreateSocket()}}
    {
        connect_pair();
    }

    TcpSocketPair(const TcpSocketPair&) = delete;
    TcpSocketPair& operator= (const TcpSocketPair&) = delete;
    TcpSocketPair(TcpSocketPair&&) = default;
    TcpSocketPair& operator= (TcpSocketPair&&) = default;

    void connect_pair()
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        BOOST_REQUIRE_EQUAL(receiver.Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        BOOST_REQUIRE_EQUAL(receiver.Listen(1), 0);

        // Get the address of the listener.
        sockaddr_in bound{};
        socklen_t blen = sizeof(bound);
        BOOST_REQUIRE_EQUAL(receiver.GetSockName(reinterpret_cast<sockaddr*>(&bound), &blen), 0);
        BOOST_REQUIRE_EQUAL(blen, sizeof(bound));

        BOOST_REQUIRE_EQUAL(sender.Connect(reinterpret_cast<sockaddr*>(&bound), sizeof(bound)), 0);

        std::unique_ptr<Sock> accepted = receiver.Accept(nullptr, nullptr);
        BOOST_REQUIRE(accepted != nullptr);

        receiver = std::move(*accepted);
    }

    void send_and_receive()
    {
        const char* msg = "abcd";
        constexpr ssize_t msg_len = 4;
        char recv_buf[10];

        BOOST_CHECK_EQUAL(sender.Send(msg, msg_len, 0), msg_len);
        BOOST_CHECK_EQUAL(receiver.Recv(recv_buf, sizeof(recv_buf), 0), msg_len);
        BOOST_CHECK_EQUAL(strncmp(msg, recv_buf, msg_len), 0);
    }
};

BOOST_AUTO_TEST_CASE(send_and_receive)
{
    TcpSocketPair socks{};
    socks.send_and_receive();

    // Sockets are still connected after being moved.
    TcpSocketPair socks_moved = std::move(socks);
    socks_moved.send_and_receive();
}

BOOST_AUTO_TEST_CASE(recv_until_terminator_limit)
{
    constexpr auto timeout = 1min; // High enough so that it is never hit.
    CThreadInterrupt interrupt;

    TcpSocketPair socks = TcpSocketPair{};

    std::thread receiver([&socks, &timeout, &interrupt]() {
        constexpr size_t max_data{10};
        bool threw_as_expected{false};
        // BOOST_CHECK_EXCEPTION() writes to some variables shared with the main thread which
        // creates a data race. So mimic it manually.
        try {
            (void)socks.receiver.RecvUntilTerminator('\n', timeout, interrupt, max_data);
        } catch (const std::runtime_error& e) {
            threw_as_expected = HasReason("too many bytes without a terminator")(e);
        }
        assert(threw_as_expected);
    });

    BOOST_REQUIRE_NO_THROW(socks.sender.SendComplete("1234567", timeout, interrupt));
    BOOST_REQUIRE_NO_THROW(socks.sender.SendComplete("89a\n", timeout, interrupt));

    receiver.join();
}

// Pin down what the callers of Sock::Wait() and Sock::WaitMany() rely on, against the real OS
// over loopback TCP. Our end of each connection is a non-blocking Sock created with
// CreateSockOS(), or accepted from one, like the sockets of net.cpp and httpserver.cpp, so that it
// has the same socket options. The remote end is a bare OS socket driven with plain socket calls,
// so that it can do whatever a remote peer can.
//
// Readiness is level-triggered: once something has arrived, a wait with a zero timeout reports
// it, and a wait that does not report it proves that it is not reported. So the tests below first make
// sure that what the peer did has arrived, and then check what is reported. They never rely on
// something not happening within some time.

namespace {

constexpr Sock::Event NONE{0};
constexpr Sock::Event RECV{Sock::RecvEvent};
constexpr Sock::Event SEND{Sock::SendEvent};
constexpr Sock::Event ERR{Sock::ErrorEvent};
constexpr Sock::Event RECV_SEND{RECV | SEND};

/*
 * Where the backends of Sock::WaitMany() legitimately differ: poll() (USE_POLL, only Linux) and
 * select() (all other platforms). Callers cope with these, except with known quirks. A change
 * of backend must update them and check that the callers still cope.
 */
#ifdef USE_POLL
constexpr bool POLL{true};
#else
constexpr bool POLL{false};
#endif
#ifdef WIN32
constexpr bool WINDOWS{true};
#else
constexpr bool WINDOWS{false};
#endif
#ifdef __linux__
constexpr bool LINUX{true};
#else
constexpr bool LINUX{false};
#endif
// poll() reports a reset connection (POLLERR, POLLHUP) whatever was requested, even nothing.
// select() reports it only through the read and write sets.
constexpr bool RESET_REPORTS_ERROR{POLL};
// Urgent data is received inline (SO_OOBINLINE), but on POSIX systems select() also signals it in
// exceptfds until it is read. A wait for RecvEvent then reports ErrorEvent along with RecvEvent.
constexpr bool URGENT_DATA_REPORTS_ERROR{!POLL && !WINDOWS};
// Windows' select() fails if no socket requests any event, as all three sets are then empty.
// Callers sleep for their timeout when the wait fails.
constexpr bool NOTHING_REQUESTED_FAILS{!POLL && WINDOWS};
// select() only supports descriptors below FD_SETSIZE, except on Windows where an fd_set is an
// array of handles. Callers drop the sockets for which IsSelectable() is false.
[[maybe_unused]] constexpr bool HIGH_DESCRIPTOR_WAITABLE{POLL || WINDOWS};
// What a failed non-blocking connect() reports. Callers only check that something occurred and
// then read SO_ERROR. Windows' select() signals it only in exceptfds.
constexpr Sock::Event FAILED_CONNECT_EVENTS{POLL ? RECV | SEND | ERR : WINDOWS ? ERR : RECV | SEND};


/*
 * Where platforms differ in the sockets that accept() returns. CreateSockOS() sockets are
 * non-blocking, with TCP_NODELAY, SO_OOBINLINE and, where it exists, SO_NOSIGPIPE.
 */
// Linux's accept() does not pass O_NONBLOCK on to the new socket, unlike macOS, the BSDs and
// Windows. net.cpp and httpserver.cpp do not set it again: they pass MSG_DONTWAIT instead.
constexpr bool ACCEPT_INHERITS_NONBLOCKING{!LINUX};
// Where MSG_DONTWAIT does not exist (Windows), accepted sockets must be non-blocking by themselves.
static_assert(MSG_DONTWAIT != 0 || ACCEPT_INHERITS_NONBLOCKING);

// Wait this long for something that is expected to happen. A wait ends as soon as it happens.
constexpr auto LONG_WAIT{60s};

#ifdef WIN32
constexpr int SHUT_WRITE{SD_SEND};
constexpr int CONNECTION_REFUSED{WSAECONNREFUSED};
#else
constexpr int SHUT_WRITE{SHUT_WR};
constexpr int CONNECTION_REFUSED{ECONNREFUSED};
#endif

std::string EventsStr(Sock::Event events)
{
    std::string s;
    if (events & RECV) s += "|Recv";
    if (events & SEND) s += "|Send";
    if (events & ERR) s += "|Error";
    if (events & ~(RECV | SEND | ERR)) s += "|garbage";
    return s.empty() ? "0" : s.substr(1);
}

void SetIntOption(SOCKET s, int level, int name, int value)
{
    BOOST_REQUIRE_EQUAL(setsockopt(s, level, name, reinterpret_cast<const char*>(&value), sizeof(value)), 0);
}

void CloseSocket(SOCKET s)
{
#ifdef WIN32
    closesocket(s);
#else
    close(s);
#endif
}

/** A non-owning shared_ptr, to use as a key of Sock::EventsPerSock. */
std::shared_ptr<const Sock> Key(const Sock& sock)
{
    return std::shared_ptr<const Sock>{std::shared_ptr<const Sock>{}, &sock};
}

/**
 * Wait on `sock` for `requested` until all of `expected` occurred, or poll once if nothing is
 * expected.
 * @return what occurred in the last wait.
 */
Sock::Event AwaitEvents(const Sock& sock, Sock::Event requested, Sock::Event expected)
{
    const auto deadline{std::chrono::steady_clock::now() + LONG_WAIT};
    for (;;) {
        const auto remaining{std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())};
        Sock::Event occurred{0xff};
        BOOST_REQUIRE(sock.Wait(expected == NONE ? 0ms : std::max(remaining, 0ms), requested, &occurred));
        if ((occurred & expected) == expected || remaining <= 0ms) return occurred;
        // Something else is ready already. Give the rest time to arrive.
        std::this_thread::sleep_for(1ms);
    }
}

/** recv() or send() made progress or failed for good, so that a caller that was woken up does not spin. */
bool Progressed(ssize_t ret)
{
    return ret >= 0 || IOErrorIsPermanent(WSAGetLastError());
}

/** recv() or send() would block. */
bool WouldBlock(ssize_t ret)
{
    return ret < 0 && !IOErrorIsPermanent(WSAGetLastError());
}

/** Our end of a Connection. It counts calls, to detect busy loops in its higher level methods. */
class AcceptedSock : public Sock
{
public:
    explicit AcceptedSock(Sock&& sock) : Sock{std::move(sock)} {}
    using Sock::operator=;

    SOCKET Fd() const { return m_socket; }

    bool Wait(std::chrono::milliseconds timeout, Event requested, Event* occurred = nullptr) const override
    {
        ++m_waits;
        return Sock::Wait(timeout, requested, occurred);
    }

    ssize_t Send(const void* data, size_t len, int flags) const override
    {
        const ssize_t ret{Sock::Send(data, len, flags)};
        if (WouldBlock(ret)) ++m_blocked_sends;
        return ret;
    }

    mutable int m_waits{0};
    mutable int m_blocked_sends{0};
};

/**
 * A socket of ours, with the options that Core sets. Not with CreateSock(), which a fixture may
 * replace with a mock.
 */
std::unique_ptr<Sock> CreateOurSock()
{
    auto sock{CreateSockOS(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    BOOST_REQUIRE(sock);
    return sock;
}

/** A non-blocking listening socket on a loopback port chosen by the OS. */
struct Listener {
    const std::unique_ptr<Sock> sock_ptr{CreateOurSock()};
    const Sock& sock{*sock_ptr};
    sockaddr_in addr{};

    Listener()
    {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE_EQUAL(sock.Bind(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
        BOOST_REQUIRE_EQUAL(sock.Listen(SOMAXCONN), 0);
        socklen_t len{sizeof(addr)};
        BOOST_REQUIRE_EQUAL(sock.GetSockName(reinterpret_cast<sockaddr*>(&addr), &len), 0);
    }
};

/**
 * A loopback TCP connection between our non-blocking Sock, which is accepted like an inbound
 * peer's, and a bare OS socket that plays the remote peer.
 */
struct Connection {
    // Small buffers make our send buffer quick to fill, as the peer never reads.
    static constexpr int SMALL_BUFFER{4096};

    SOCKET peer;
    std::unique_ptr<AcceptedSock> sock;

    /**
     * @param[in] set_options Set the options that net.cpp and httpserver.cpp do not set on an
     *                        accepted socket but that the tests rely on: O_NONBLOCK, and
     *                        TCP_NODELAY in case it was not inherited. Without it, our socket is
     *                        as accept() returned it, except for a small send buffer.
     */
    explicit Connection(const Listener& listener, bool set_options = true) : peer{CreateSocket()}
    {
        // Set before connecting: the receive window is negotiated in the handshake.
        SetIntOption(peer, SOL_SOCKET, SO_RCVBUF, SMALL_BUFFER);
        BOOST_REQUIRE_EQUAL(connect(peer, reinterpret_cast<const sockaddr*>(&listener.addr), sizeof(listener.addr)), 0);

        BOOST_REQUIRE_EQUAL(AwaitEvents(listener.sock, RECV, RECV), RECV);
        auto accepted{listener.sock.Accept(nullptr, nullptr)};
        BOOST_REQUIRE(accepted);
        sock = std::make_unique<AcceptedSock>(std::move(*accepted));
        if (set_options) {
            BOOST_REQUIRE(sock->SetNonBlocking());
            SetIntOption(sock->Fd(), IPPROTO_TCP, TCP_NODELAY, 1);
        }
        SetIntOption(sock->Fd(), SOL_SOCKET, SO_SNDBUF, SMALL_BUFFER);
    }

    ~Connection() { ClosePeer(); }

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    void PeerSend(std::string_view data, int flags = 0) const
    {
        BOOST_REQUIRE_EQUAL(send(peer, data.data(), data.size(), flags), static_cast<ssize_t>(data.size()));
    }

    /** Send one byte of urgent (out-of-band) data. */
    void PeerSendUrgent() const { PeerSend("U", MSG_OOB); }

    /** Shut down the peer's sending side: it sends FIN. */
    void PeerShutdown() const { BOOST_REQUIRE_EQUAL(shutdown(peer, SHUT_WRITE), 0); }

    /** Close the peer's socket. It sends FIN, or RST if it has unread data. */
    void ClosePeer()
    {
        if (peer != INVALID_SOCKET) CloseSocket(peer);
        peer = INVALID_SOCKET;
    }

    /** Close the peer's socket so that it sends RST. */
    void ResetPeer()
    {
        linger lin{};
        lin.l_onoff = 1;
        lin.l_linger = 0;
        BOOST_REQUIRE_EQUAL(setsockopt(peer, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lin), sizeof(lin)), 0);
        ClosePeer();
    }

    /** Write to our socket until it would block. */
    void FillSendBuffer(int flags = MSG_NOSIGNAL) const
    {
        const std::vector<char> data(SMALL_BUFFER, 'x');
        size_t sent{0};
        for (;;) {
            const ssize_t ret{sock->Send(data.data(), data.size(), flags)};
            if (ret < 0) {
                BOOST_REQUIRE(WouldBlock(ret));
                return;
            }
            sent += ret;
            // Far more than any socket buffer.
            BOOST_REQUIRE_LT(sent, 64U << 20);
        }
    }

    /**
     * Wait until normal data, the end of the stream or a reset has arrived. Any event will do, so
     * that a backend that misreports it fails the checks of the test rather than this wait.
     */
    void AwaitReadable() const
    {
        Sock::Event occurred{0};
        BOOST_REQUIRE(sock->Wait(LONG_WAIT, RECV, &occurred));
        BOOST_REQUIRE(occurred != NONE);
    }
};

/** What the peer did last. */
enum class Last {
    NOTHING,
    URGENT,   //!< sent one byte of urgent data
    SHUTDOWN, //!< shut down its sending side
    CLOSE,    //!< closed its socket
    RESET,    //!< closed its socket with SO_LINGER {1, 0}
};

struct Scenario {
    bool data;   //!< the peer sent normal data
    Last last;
    bool full;   //!< our send buffer is full
    std::unique_ptr<Connection> conn{};
    Sock::Event occurred_any{0};

    // A peer that closes its socket with unread data resets the connection.
    bool Reset() const { return last == Last::RESET || (last == Last::CLOSE && full); }
    bool EndOfStream() const { return last == Last::SHUTDOWN || (last == Last::CLOSE && !full); }
    // Urgent data is received inline, like normal data.
    bool Data() const { return data || last == Last::URGENT; }

    std::string Name() const
    {
        static constexpr const char* LAST[]{"nothing", "urgent", "shutdown", "close", "reset"};
        return strprintf("peer: %s%s, our send buffer: %s", data ? "data then " : "", LAST[static_cast<int>(last)], full ? "full" : "empty");
    }

    std::string Name(Sock::Event requested) const { return Name() + ", requested: " + EventsStr(requested); }
};

/** The events that must occur, and those that may in addition. */
struct Expected {
    Sock::Event must{0};
    Sock::Event may{0};
};

Expected Expect(const Scenario& s, Sock::Event requested)
{
    Expected e;
    if (requested & RECV) {
        // Data, including urgent data, the end of the stream or a reset: the next recv() does not
        // block.
        if (s.Data() || s.EndOfStream() || s.Reset()) e.must |= RECV;
        if (s.last == Last::URGENT && URGENT_DATA_REPORTS_ERROR) e.must |= ERR;
    }
    if (requested & SEND) {
        // A send() to a reset connection fails at once, so it is reported. When the send buffer is
        // full, the OS may still find room (Windows does after a while), which is fine as long as
        // the next send() then makes progress.
        if (!s.full || s.Reset()) {
            e.must |= SEND;
        } else {
            e.may |= SEND;
        }
    }
    if (s.Reset() && RESET_REPORTS_ERROR) e.must |= ERR;
    return e;
}

void CheckEvents(const std::string& name, Sock::Event occurred, const Expected& expected)
{
    BOOST_CHECK_MESSAGE((occurred & expected.must) == expected.must && (occurred & ~(expected.must | expected.may)) == 0,
                        name << ": occurred " << EventsStr(occurred) << ", expected " << EventsStr(expected.must)
                             << (expected.may ? " and maybe " + EventsStr(expected.may) : ""));
}

} // namespace

// What a wait reports, for every combination of what the peer did, whether our send buffer is
// full and what is requested. This covers:
// - Only requested events are reported, and ErrorEvent only as listed in Expect(). An unrequested
//   RecvEvent or an ErrorEvent from incoming data, urgent or not, would wake up a peer that net.cpp
//   paused for receiving (fPauseRecv, waits only for SendEvent), which then calls recv() on
//   ErrorEvent and so bypasses the backpressure. The same goes for httpserver.cpp's clients that
//   request nothing.
// - Data, including urgent data, the end of the stream and a reset are reported to a wait for
//   RecvEvent with RecvEvent, not only ErrorEvent: bitcoin-cli's HTTPClient::Recv() only looks at
//   RecvEvent.
// - A reset is reported to a wait for SendEvent with SendEvent: HTTPClient::SendRequest() only
//   calls send() on SendEvent, and waits again otherwise without sleeping.
// - What is reported is the same for Wait() and WaitMany() on many sockets.
// - Every reported event lets the next recv() or send() make progress or fail for good. Callers
//   act once per wake-up and wait again, so a would-block there is a busy loop.
BOOST_AUTO_TEST_CASE(readiness)
{
    Listener listener;
    std::vector<Scenario> scenarios;
    for (const bool data : {false, true}) {
        for (const Last last : {Last::NOTHING, Last::URGENT, Last::SHUTDOWN, Last::CLOSE, Last::RESET}) {
            for (const bool full : {false, true}) {
                scenarios.push_back({.data = data, .last = last, .full = full});
            }
        }
    }

    for (auto& s : scenarios) {
        s.conn = std::make_unique<Connection>(listener);
        if (s.full) s.conn->FillSendBuffer();
        if (s.data) s.conn->PeerSend("data");
        switch (s.last) {
        case Last::NOTHING: break;
        case Last::URGENT: s.conn->PeerSendUrgent(); break;
        case Last::SHUTDOWN: s.conn->PeerShutdown(); break;
        case Last::CLOSE: s.conn->ClosePeer(); break;
        case Last::RESET: s.conn->ResetPeer(); break;
        }
    }

    // Make sure that what the peers did has arrived. What arrives after that, like a reset that
    // follows a FIN, is waited for below.
    for (const auto& s : scenarios) {
        if (s.Data() || s.EndOfStream() || s.Reset()) s.conn->AwaitReadable();
    }

    for (const Sock::Event requested : {NONE, RECV, SEND, RECV_SEND}) {
        Sock::EventsPerSock events_per_sock;
        for (auto& s : scenarios) {
            const auto& sock{*s.conn->sock};
            const Expected expected{Expect(s, requested)};
            if (requested == NONE && NOTHING_REQUESTED_FAILS) {
                BOOST_CHECK_MESSAGE(!sock.Wait(0ms, requested), s.Name(requested));
            } else {
                const Sock::Event occurred{AwaitEvents(sock, requested, expected.must)};
                CheckEvents(s.Name(requested), occurred, expected);
                s.occurred_any |= occurred;
            }
            Sock::Events events{requested};
            // Stale values are overwritten.
            events.occurred = 0xff;
            events_per_sock.emplace(Key(sock), events);
        }

        // All of them in a single WaitMany(). Everything that must occur is ready already.
        const bool ok{listener.sock.WaitMany(0ms, events_per_sock)};
        if (requested == NONE && NOTHING_REQUESTED_FAILS) {
            BOOST_CHECK(!ok);
            continue;
        }
        BOOST_REQUIRE(ok);
        for (const auto& s : scenarios) {
            const Sock::Event occurred{events_per_sock.at(Key(*s.conn->sock)).occurred};
            CheckEvents(s.Name(requested) + " (WaitMany)", occurred, Expect(s, requested));
        }
    }

    for (const auto& s : scenarios) {
        const std::string name{s.Name()};
        const auto& sock{*s.conn->sock};

        char c;
        const ssize_t received{sock.Recv(&c, 1, MSG_PEEK)};
        if (s.occurred_any & RECV) BOOST_CHECK_MESSAGE(Progressed(received), name);
        if (!s.data && s.EndOfStream()) {
            BOOST_CHECK_MESSAGE(received == 0, name << ": recv() returned " << received << " errno " << WSAGetLastError());
        } else if (s.Reset()) {
            // Data received before a reset may or may not be returned first, depending on the OS.
            BOOST_CHECK_MESSAGE(Progressed(received), name);
        } else if (s.data) {
            BOOST_CHECK_MESSAGE(received == 1 && c == 'd', name);
        } else if (s.last == Last::URGENT) {
            BOOST_CHECK_MESSAGE(received == 1 && c == 'U', name);
        } else {
            BOOST_CHECK_MESSAGE(WouldBlock(received), name);
        }

        if (s.occurred_any & SEND) {
            BOOST_CHECK_MESSAGE(Progressed(sock.Send("x", 1, MSG_NOSIGNAL)), name);
        }
    }
}

// WaitMany() reports each socket's own events, for many sockets in random states.
BOOST_AUTO_TEST_CASE(wait_many_attribution)
{
    enum class State { IDLE, DATA, END_OF_STREAM };
    struct Entry {
        State state;
        Sock::Event requested;
        std::unique_ptr<Connection> conn;
    };

    Listener listener;
    std::vector<Entry> entries;
    for (int i{0}; i < 100; ++i) {
        const auto state{static_cast<State>(m_rng.randrange(3))};
        // At least one socket requests something, see NOTHING_REQUESTED_FAILS.
        const auto requested{i == 0 ? RECV_SEND : static_cast<Sock::Event>(m_rng.randrange(4))};
        entries.push_back({state, requested, std::make_unique<Connection>(listener)});
        if (state == State::DATA) entries.back().conn->PeerSend("data");
        if (state == State::END_OF_STREAM) entries.back().conn->PeerShutdown();
    }
    for (const auto& e : entries) {
        if (e.state != State::IDLE) e.conn->AwaitReadable();
    }

    Sock::EventsPerSock events_per_sock;
    for (const auto& e : entries) {
        events_per_sock.emplace(Key(*e.conn->sock), Sock::Events{e.requested});
    }
    BOOST_REQUIRE(listener.sock.WaitMany(LONG_WAIT, events_per_sock));
    for (const auto& e : entries) {
        const Sock::Event expected{static_cast<Sock::Event>((e.requested & SEND) | (e.state != State::IDLE ? e.requested & RECV : 0))};
        BOOST_CHECK_EQUAL(EventsStr(events_per_sock.at(Key(*e.conn->sock)).occurred), EventsStr(expected));
    }
}

// Without events, the wait lasts for the timeout and returns true with nothing occurred, also
// when a socket on which nothing is requested is readable. Callers rely on it to pace their loops
// (net.cpp, httpserver.cpp) and to detect a timeout (netbase.cpp's connect, i2p.cpp, pcp.cpp).
BOOST_AUTO_TEST_CASE(timeout)
{
    Listener listener;
    Connection idle{listener};
    Connection readable{listener};
    readable.PeerSend("data");
    readable.AwaitReadable();

    constexpr auto TIMEOUT{300ms};
    // Allow for the coarse timers of some platforms.
    constexpr auto MIN_ELAPSED{TIMEOUT * 9 / 10};

    auto start{std::chrono::steady_clock::now()};
    Sock::Event occurred{0xff};
    BOOST_REQUIRE(idle.sock->Wait(TIMEOUT, RECV, &occurred));
    BOOST_CHECK_GE(std::chrono::steady_clock::now() - start, MIN_ELAPSED);
    BOOST_CHECK_EQUAL(occurred, NONE);

    Sock::EventsPerSock events_per_sock;
    events_per_sock.emplace(Key(*idle.sock), Sock::Events{RECV});
    events_per_sock.emplace(Key(*readable.sock), Sock::Events{NONE});
    start = std::chrono::steady_clock::now();
    BOOST_REQUIRE(listener.sock.WaitMany(TIMEOUT, events_per_sock));
    BOOST_CHECK_GE(std::chrono::steady_clock::now() - start, MIN_ELAPSED);
    BOOST_CHECK_EQUAL(events_per_sock.at(Key(*idle.sock)).occurred, NONE);
    BOOST_CHECK_EQUAL(events_per_sock.at(Key(*readable.sock)).occurred, NONE);
}

// Timeouts longer than MAX_WAIT_TIMEOUT are capped rather than making the wait fail. bitcoin-cli
// waits for MAX_WAIT_TIMEOUT with -rpcclienttimeout=0.
BOOST_AUTO_TEST_CASE(large_timeout)
{
    Listener listener;
    for (const std::chrono::milliseconds timeout : {std::chrono::milliseconds{Sock::MAX_WAIT_TIMEOUT},
                                                    std::chrono::milliseconds{Sock::MAX_WAIT_TIMEOUT + 1s},
                                                    std::chrono::milliseconds::max()}) {
        Connection conn{listener};
        // Make it readable while waiting. If the wait failed to wait, it fails before that.
        ssize_t sent{0};
        std::thread peer{[&] {
            std::this_thread::sleep_for(100ms);
            sent = send(conn.peer, "x", 1, 0);
        }};
        Sock::Event occurred{0xff};
        const bool ok{conn.sock->Wait(timeout, RECV, &occurred)};
        peer.join();
        BOOST_REQUIRE_EQUAL(sent, 1);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(occurred, RECV);

        Sock::EventsPerSock events_per_sock;
        events_per_sock.emplace(Key(*conn.sock), Sock::Events{RECV});
        BOOST_CHECK(conn.sock->WaitMany(timeout, events_per_sock));
        BOOST_CHECK_EQUAL(events_per_sock.begin()->second.occurred, RECV);
    }
}

// The options that CreateSockOS() sets, and those that a socket accepted from it inherits. A
// socket that is not non-blocking makes a call without MSG_DONTWAIT wait, here until the test
// times out, rather than return would-block.
BOOST_AUTO_TEST_CASE(socket_options)
{
    const auto get{[](const Sock& sock, int level, int name) {
        int value{0};
        socklen_t len{sizeof(value)};
        BOOST_REQUIRE_EQUAL(sock.GetSockOpt(level, name, &value, &len), 0);
        return value != 0;
    }};

    Listener listener;
    const auto unconnected{CreateOurSock()};
    for (const Sock* sock : std::array<const Sock*, 2>{&listener.sock, unconnected.get()}) {
        BOOST_CHECK(sock->IsSelectable());
        BOOST_CHECK(get(*sock, IPPROTO_TCP, TCP_NODELAY));
        BOOST_CHECK(get(*sock, SOL_SOCKET, SO_OOBINLINE));
#ifdef SO_NOSIGPIPE
        BOOST_CHECK(get(*sock, SOL_SOCKET, SO_NOSIGPIPE));
#endif
    }
    BOOST_CHECK(!listener.sock.Accept(nullptr, nullptr));
    BOOST_CHECK(WouldBlock(-1));

    const Connection conn{listener, /*set_options=*/false};
    const Sock& accepted{*conn.sock};
    BOOST_CHECK(get(accepted, IPPROTO_TCP, TCP_NODELAY));
    BOOST_CHECK(get(accepted, SOL_SOCKET, SO_OOBINLINE));
#ifdef SO_NOSIGPIPE
    BOOST_CHECK(get(accepted, SOL_SOCKET, SO_NOSIGPIPE));
#endif
#ifndef WIN32
    const int flags{fcntl(conn.sock->Fd(), F_GETFL)};
    BOOST_REQUIRE_NE(flags, -1);
    BOOST_CHECK_EQUAL((flags & O_NONBLOCK) != 0, ACCEPT_INHERITS_NONBLOCKING);
#endif
    if (ACCEPT_INHERITS_NONBLOCKING) {
        char c;
        BOOST_CHECK(WouldBlock(accepted.Recv(&c, 1, 0)));
    }
}

// Recv() and Send() with MSG_DONTWAIT return would-block rather than wait on a socket as accept()
// returns it, which net.cpp and httpserver.cpp rely on: it is blocking on Linux, and MSG_DONTWAIT
// is 0 on Windows (see ACCEPT_INHERITS_NONBLOCKING).
BOOST_AUTO_TEST_CASE(accepted_socket_dontwait)
{
    Listener listener;
    Connection conn{listener, /*set_options=*/false};
    char c;
    BOOST_CHECK(WouldBlock(conn.sock->Recv(&c, 1, MSG_DONTWAIT)));
    conn.FillSendBuffer(MSG_NOSIGNAL | MSG_DONTWAIT);
    BOOST_CHECK(WouldBlock(conn.sock->Send("x", 1, MSG_NOSIGNAL | MSG_DONTWAIT)));
}
// Not relied on: on macOS, send() with MSG_DONTWAIT waits on a blocking socket. Accepted sockets
// are non-blocking there.

// A listening socket reports RecvEvent when accept() will succeed. net.cpp accepts one connection
// per wake-up and httpserver.cpp accepts until accept() fails.
BOOST_AUTO_TEST_CASE(listening_socket)
{
    Listener listener;
    BOOST_CHECK_EQUAL(AwaitEvents(listener.sock, RECV, NONE), NONE);
    BOOST_CHECK(!listener.sock.Accept(nullptr, nullptr));

    std::vector<SOCKET> clients;
    for (int i{0}; i < 3; ++i) {
        clients.push_back(CreateSocket());
        BOOST_REQUIRE_EQUAL(connect(clients.back(), reinterpret_cast<const sockaddr*>(&listener.addr), sizeof(listener.addr)), 0);
    }
    for (size_t i{0}; i < clients.size(); ++i) {
        BOOST_CHECK_EQUAL(AwaitEvents(listener.sock, RECV, RECV), RECV);
        BOOST_CHECK(listener.sock.Accept(nullptr, nullptr));
    }
    BOOST_CHECK_EQUAL(AwaitEvents(listener.sock, RECV, NONE), NONE);
    BOOST_CHECK(!listener.sock.Accept(nullptr, nullptr));
    // Not because of an error.
    BOOST_CHECK(WouldBlock(-1));

    for (const SOCKET s : clients) CloseSocket(s);
}
// Not tested: a connection reset before it is accepted may leave the listening socket readable
// while accept() fails, on some platforms. Callers then just wait again.

// A non-blocking connect() that succeeds wakes up a wait for RecvEvent | SendEvent with SendEvent
// and SO_ERROR is 0, as netbase.cpp's ConnectToSocket() expects.
BOOST_AUTO_TEST_CASE(connect_succeeds)
{
    Listener listener;
    const auto sock_ptr{CreateOurSock()};
    const Sock& sock{*sock_ptr};
    if (sock.Connect(reinterpret_cast<const sockaddr*>(&listener.addr), sizeof(listener.addr)) != 0) {
        const int err{WSAGetLastError()};
        BOOST_REQUIRE(err == WSAEINPROGRESS || err == WSAEWOULDBLOCK);
    }
    BOOST_CHECK_EQUAL(EventsStr(AwaitEvents(sock, RECV | SEND, SEND)), EventsStr(SEND));
    int error{-1};
    socklen_t len{sizeof(error)};
    BOOST_REQUIRE_EQUAL(sock.GetSockOpt(SOL_SOCKET, SO_ERROR, &error, &len), 0);
    BOOST_CHECK_EQUAL(error, 0);
}

// A non-blocking connect() that fails wakes up a wait for RecvEvent | SendEvent and SO_ERROR
// tells why, as netbase.cpp's ConnectToSocket() expects.
BOOST_AUTO_TEST_CASE(connect_refused)
{
    // A port that nothing is bound to: macOS does not answer a connection to a port that is bound
    // without listening. Something else could bind to it and listen in between, but that is unlikely.
    sockaddr_in addr;
    {
        Listener listener;
        addr = listener.addr;
    }

    const auto sock_ptr{CreateOurSock()};
    const Sock& sock{*sock_ptr};
    BOOST_REQUIRE_NE(sock.Connect(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    const int err{WSAGetLastError()};
    if (err != WSAEINPROGRESS && err != WSAEWOULDBLOCK) {
        // Refused right away, without waiting.
        BOOST_TEST_MESSAGE("connect() was refused right away");
        BOOST_CHECK_EQUAL(err, CONNECTION_REFUSED);
        return;
    }
    // Windows retries for about two seconds before giving up.
    BOOST_CHECK_EQUAL(EventsStr(AwaitEvents(sock, RECV | SEND, FAILED_CONNECT_EVENTS)), EventsStr(FAILED_CONNECT_EVENTS));
    int error{-1};
    socklen_t len{sizeof(error)};
    BOOST_REQUIRE_EQUAL(sock.GetSockOpt(SOL_SOCKET, SO_ERROR, &error, &len), 0);
    BOOST_CHECK_EQUAL(error, CONNECTION_REFUSED);
}
// Not tested, as it needs a peer that does not answer: a connect() that is still in progress is
// not reported, or ConnectToSocket() would take it for an established connection.

// Urgent data is received inline, like normal data. A lone urgent byte is reported to a wait for
// RecvEvent with RecvEvent and the next recv() returns it, so that a caller that was woken up does
// not spin. It is not reported to a wait without RecvEvent, so that it does not wake up a peer that
// is paused for receiving. Once read, it is not reported anymore. See URGENT_DATA_REPORTS_ERROR.
BOOST_AUTO_TEST_CASE(urgent_data)
{
    Listener listener;
    Connection conn{listener};
    const Sock::Event urgent_error{URGENT_DATA_REPORTS_ERROR ? ERR : NONE};

    conn.PeerSendUrgent();
    conn.AwaitReadable();
    BOOST_CHECK_EQUAL(EventsStr(AwaitEvents(*conn.sock, SEND, SEND)), EventsStr(SEND));
    BOOST_CHECK_EQUAL(EventsStr(AwaitEvents(*conn.sock, RECV, RECV | urgent_error)), EventsStr(RECV | urgent_error));
    char c{0};
    BOOST_CHECK_EQUAL(conn.sock->Recv(&c, 1, 0), 1);
    BOOST_CHECK_EQUAL(c, 'U');
    BOOST_CHECK_EQUAL(EventsStr(AwaitEvents(*conn.sock, RECV, NONE)), EventsStr(NONE));
    BOOST_CHECK(WouldBlock(conn.sock->Recv(&c, 1, 0)));

    // In the middle of normal data, it is received in order.
    conn.PeerSend("ab");
    conn.PeerSendUrgent();
    conn.PeerSend("cd");
    std::string received;
    while (received.size() < 5) {
        BOOST_REQUIRE(AwaitEvents(*conn.sock, RECV, RECV) & RECV);
        char buf[16];
        const ssize_t ret{conn.sock->Recv(buf, sizeof(buf), 0)};
        BOOST_REQUIRE_GT(ret, 0);
        received.append(buf, ret);
    }
    BOOST_CHECK_EQUAL(received, "abUcd");
    BOOST_CHECK_EQUAL(EventsStr(AwaitEvents(*conn.sock, RECV, NONE)), EventsStr(NONE));
}

// SendComplete() waits for room in the send buffer between attempts, without spinning, also when
// the peer has shut down its sending side, and fails at once on a reset connection. Tor control
// and I2P SAM commands are sent with it.
BOOST_AUTO_TEST_CASE(send_complete)
{
    Listener listener;
    CThreadInterrupt interrupt;
    // More than can ever be buffered while the peer does not read.
    const std::vector<unsigned char> data(16 << 20, 'x');

    {
        Connection conn{listener};
        conn.FillSendBuffer();
        conn.PeerShutdown();
        conn.AwaitReadable();
        conn.sock->m_blocked_sends = 0;
        constexpr auto TIMEOUT{1500ms};
        const auto start{std::chrono::steady_clock::now()};
        try {
            conn.sock->SendComplete(data, TIMEOUT, interrupt);
            // Windows keeps finding room for more data on a loopback connection, even when the
            // peer does not read.
        } catch (const std::runtime_error& e) {
            BOOST_CHECK_EQUAL(std::string{e.what()}.rfind("Send timeout", 0), 0U);
            BOOST_CHECK_GE(std::chrono::steady_clock::now() - start, TIMEOUT * 9 / 10);
        }
        // After a send() that would block, it waits until there is room again, or for at most
        // MAX_WAIT_FOR_IO. A busy loop would retry thousands of times.
        BOOST_CHECK_LE(conn.sock->m_blocked_sends, 10);
    }

    {
        Connection conn{listener};
        conn.FillSendBuffer();
        conn.ResetPeer();
        conn.AwaitReadable();
        BOOST_CHECK_EXCEPTION(conn.sock->SendComplete(data, LONG_WAIT, interrupt), std::runtime_error, HasReason("send(): "));
    }
}

// RecvUntilTerminator() waits for data between attempts and fails at once at the end of the
// stream or on a reset. I2P SAM replies are read with it.
BOOST_AUTO_TEST_CASE(recv_until_terminator)
{
    Listener listener;
    CThreadInterrupt interrupt;
    constexpr size_t MAX_DATA{1000};

    {
        Connection conn{listener};
        conn.PeerSend("abc");
        conn.PeerShutdown();
        conn.AwaitReadable();
        conn.sock->m_waits = 0;
        BOOST_CHECK_EXCEPTION((void)conn.sock->RecvUntilTerminator('\n', LONG_WAIT, interrupt, MAX_DATA), std::runtime_error,
                              HasReason("Connection unexpectedly closed by peer"));
        BOOST_CHECK_LE(conn.sock->m_waits, 1);
    }

    {
        Connection conn{listener};
        conn.ResetPeer();
        conn.AwaitReadable();
        conn.sock->m_waits = 0;
        BOOST_CHECK_EXCEPTION((void)conn.sock->RecvUntilTerminator('\n', LONG_WAIT, interrupt, MAX_DATA), std::runtime_error,
                              HasReason("recv(): "));
        BOOST_CHECK_EQUAL(conn.sock->m_waits, 0);
    }

    {
        // Urgent data is returned inline. Each wait ends when more data has arrived.
        Connection conn{listener};
        conn.PeerSend("ab");
        conn.PeerSendUrgent();
        conn.PeerSend("c\n");
        conn.sock->m_waits = 0;
        BOOST_CHECK_EQUAL(conn.sock->RecvUntilTerminator('\n', LONG_WAIT, interrupt, MAX_DATA), "abUc");
        BOOST_CHECK_LE(conn.sock->m_waits, 10);
    }
}

// IsConnected() tells a live connection from one that the peer closed or reset. Tor control
// checks it when waiting for data times out, I2P before reusing its control socket.
BOOST_AUTO_TEST_CASE(is_connected)
{
    Listener listener;
    std::string errmsg;
    {
        Connection conn{listener};
        BOOST_CHECK(conn.sock->IsConnected(errmsg));
        conn.PeerSend("data");
        conn.AwaitReadable();
        BOOST_CHECK(conn.sock->IsConnected(errmsg));
    }
    {
        Connection conn{listener};
        conn.PeerSendUrgent();
        conn.AwaitReadable();
        BOOST_CHECK(conn.sock->IsConnected(errmsg));
    }
    {
        Connection conn{listener};
        conn.PeerShutdown();
        conn.AwaitReadable();
        BOOST_CHECK(!conn.sock->IsConnected(errmsg));
        BOOST_CHECK_EQUAL(errmsg, "closed");
    }
    {
        Connection conn{listener};
        conn.ResetPeer();
        conn.AwaitReadable();
        BOOST_CHECK(!conn.sock->IsConnected(errmsg));
    }
}

// Readiness is level-triggered: what is left after a partial read, and then the end of the
// stream, are reported again. net.cpp reads at most 64 KiB per wake-up and relies on this.
BOOST_AUTO_TEST_CASE(level_triggered)
{
    Listener listener;
    Connection conn{listener};
    constexpr size_t SIZE{3000};
    conn.PeerSend(std::string(SIZE, 'x'));
    conn.PeerShutdown();

    size_t received{0};
    for (;;) {
        BOOST_REQUIRE_EQUAL(AwaitEvents(*conn.sock, RECV, RECV), RECV);
        char buf[1000];
        const ssize_t ret{conn.sock->Recv(buf, sizeof(buf), 0)};
        BOOST_REQUIRE_GE(ret, 0);
        if (ret == 0) break;
        received += ret;
    }
    BOOST_CHECK_EQUAL(received, SIZE);
    BOOST_CHECK_EQUAL(AwaitEvents(*conn.sock, RECV, RECV), RECV);
    char c;
    BOOST_CHECK_EQUAL(conn.sock->Recv(&c, 1, 0), 0);
}

#ifndef WIN32
// A socket whose descriptor is not below FD_SETSIZE can be waited on only if IsSelectable(). Else
// the whole wait fails, which is why callers drop such sockets (net.cpp, httpserver.cpp,
// netbase.cpp) and why init.cpp caps the number of descriptors at FD_SETSIZE without USE_POLL.
BOOST_AUTO_TEST_CASE(high_descriptor)
{
    constexpr int HIGH_FD{1100};
    static_assert(HIGH_FD >= FD_SETSIZE);

    rlimit limit;
    BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_NOFILE, &limit), 0);
    const rlimit original{limit};
    if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max <= HIGH_FD) {
        BOOST_TEST_MESSAGE("The hard limit on the number of descriptors is too low, skipping");
        return;
    }
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur <= HIGH_FD) {
        limit.rlim_cur = HIGH_FD + 1;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            BOOST_TEST_MESSAGE("Could not raise the limit on the number of descriptors, skipping");
            return;
        }
    }

    {
        Listener listener;
        Connection conn{listener};
        conn.PeerSend("data");
        conn.AwaitReadable();
        // Do not clobber a descriptor in use.
        if (fcntl(HIGH_FD, F_GETFD) != -1 || errno != EBADF) {
            BOOST_TEST_MESSAGE("Descriptor " << HIGH_FD << " is in use, skipping");
        } else {
            BOOST_REQUIRE_EQUAL(dup2(static_cast<int>(conn.sock->Fd()), HIGH_FD), HIGH_FD);
            // This owns and closes the duplicate. The connection stays open through the original.
            const Sock high{static_cast<SOCKET>(HIGH_FD)};
            BOOST_CHECK_EQUAL(high.IsSelectable(), HIGH_DESCRIPTOR_WAITABLE);
            Sock::Event occurred{0xff};
            BOOST_CHECK_EQUAL(high.Wait(0ms, RECV, &occurred), HIGH_DESCRIPTOR_WAITABLE);
            if (HIGH_DESCRIPTOR_WAITABLE) BOOST_CHECK_EQUAL(occurred, RECV);

            Sock::EventsPerSock events_per_sock;
            events_per_sock.emplace(Key(*conn.sock), Sock::Events{RECV});
            events_per_sock.emplace(Key(high), Sock::Events{SEND});
            BOOST_CHECK_EQUAL(high.WaitMany(0ms, events_per_sock), HIGH_DESCRIPTOR_WAITABLE);
            if (HIGH_DESCRIPTOR_WAITABLE) {
                BOOST_CHECK_EQUAL(events_per_sock.at(Key(*conn.sock)).occurred, RECV);
                BOOST_CHECK_EQUAL(events_per_sock.at(Key(high)).occurred, SEND);
            }
        }
    }

    BOOST_REQUIRE_EQUAL(setrlimit(RLIMIT_NOFILE, &original), 0);
}
#endif // WIN32

// Not tested, as the timing of signals is racy: a wait interrupted by a signal (EINTR) returns
// false. Callers treat that like a failed wait (net.cpp and httpserver.cpp sleep, others give up).
// Not tested, as it needs more than FD_SETSIZE sockets: on Windows, FD_SET() silently ignores
// sockets beyond FD_SETSIZE in a set. init.cpp caps the number of descriptors at FD_SETSIZE.
// Not tested: a negative timeout. poll() would wait forever and select() fails; no caller passes one.

BOOST_AUTO_TEST_SUITE_END()
