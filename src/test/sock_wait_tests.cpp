// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// These tests pin down the socket readiness semantics that Bitcoin Core relies
// on from Sock::Wait() and Sock::WaitMany(), independently of whether they are
// implemented with select(), poll() or WSAPoll(). They use real TCP
// connections over loopback.

#include <compat/compat.h>
#include <test/util/setup_common.h>
#include <util/sock.h>

#include <boost/test/unit_test.hpp>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32
#include <sys/resource.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(sock_wait_tests, BasicTestingSetup)

namespace {

// Wait this long for things that are expected to happen. This is generous
// because CI machines can be slow; the wait ends as soon as the event occurs.
constexpr auto LONG_WAIT{10s};
// Wait this long for things that are expected not to happen.
constexpr auto SHORT_WAIT{400ms};

SOCKET CreateSocket()
{
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(s != static_cast<SOCKET>(SOCKET_ERROR));
#ifdef SO_NOSIGPIPE
    int set{1};
    BOOST_REQUIRE_EQUAL(setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&set), sizeof(set)), 0);
#endif
    return s;
}

void SetBufferSize(const Sock& sock, int opt_name, int size)
{
    BOOST_REQUIRE_EQUAL(sock.SetSockOpt(SOL_SOCKET, opt_name, &size, sizeof(size)), 0);
}

int SocketError(const Sock& sock)
{
    int error{-1};
    socklen_t len{sizeof(error)};
    BOOST_REQUIRE_EQUAL(sock.GetSockOpt(SOL_SOCKET, SO_ERROR, &error, &len), 0);
    return error;
}

/** Wait on a socket, require that the wait itself succeeds and return the events that occurred. */
int WaitFor(const Sock& sock, std::chrono::milliseconds timeout, Sock::Event requested)
{
    Sock::Event occurred{0xff};
    BOOST_REQUIRE(sock.Wait(timeout, requested, &occurred));
    return occurred;
}

/** A shared_ptr that does not own the socket, for use as a key in EventsPerSock. */
std::shared_ptr<const Sock> Key(const Sock& sock)
{
    return std::shared_ptr<const Sock>{std::shared_ptr<const Sock>{}, &sock};
}

int Occurred(const Sock::EventsPerSock& events, const Sock& sock)
{
    const auto it{events.find(Key(sock))};
    BOOST_REQUIRE(it != events.end());
    return it->second.occurred;
}

/** A connected pair of TCP sockets over loopback. */
struct SocketPair {
    // The raw descriptors are kept for the calls that Sock does not wrap.
    SOCKET client_fd;
    SOCKET server_fd;
    std::unique_ptr<Sock> client;
    std::unique_ptr<Sock> server;

    /** @param[in] small_buffers Make the buffers tiny so that they can be filled up quickly. */
    explicit SocketPair(bool small_buffers = false)
    {
        constexpr int SMALL{4096};

        const SOCKET listener_fd{CreateSocket()};
        Sock listener{listener_fd};
        // The receive buffer of the accepted socket is inherited from the listening socket.
        if (small_buffers) SetBufferSize(listener, SO_RCVBUF, SMALL);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE_EQUAL(listener.Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        BOOST_REQUIRE_EQUAL(listener.Listen(1), 0);
        sockaddr_in bound{};
        socklen_t len{sizeof(bound)};
        BOOST_REQUIRE_EQUAL(listener.GetSockName(reinterpret_cast<sockaddr*>(&bound), &len), 0);

        client_fd = CreateSocket();
        client = std::make_unique<Sock>(client_fd);
        if (small_buffers) {
            SetBufferSize(*client, SO_SNDBUF, SMALL);
            SetBufferSize(*client, SO_RCVBUF, SMALL);
        }
        BOOST_REQUIRE_EQUAL(client->Connect(reinterpret_cast<sockaddr*>(&bound), sizeof(bound)), 0);

        // Accept with the raw call to learn the descriptor of the accepted socket.
        server_fd = accept(listener_fd, nullptr, nullptr);
        BOOST_REQUIRE(server_fd != static_cast<SOCKET>(INVALID_SOCKET));
        server = std::make_unique<Sock>(server_fd);
#ifdef SO_NOSIGPIPE
        int set{1};
        BOOST_REQUIRE_EQUAL(server->SetSockOpt(SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set)), 0);
#endif
        if (small_buffers) SetBufferSize(*server, SO_SNDBUF, SMALL);
    }

    SocketPair(const SocketPair&) = delete;
    SocketPair& operator=(const SocketPair&) = delete;
};

/** Send a byte of urgent (out-of-band) data on a socket. */
void SendUrgentByte(SOCKET fd)
{
    BOOST_REQUIRE_EQUAL(send(fd, "U", 1, MSG_OOB), 1);
}

/** Write to a socket until it keeps refusing more data. Nobody must be reading from the other end. */
void FillSendBuffer(const Sock& sock)
{
    BOOST_REQUIRE(sock.SetNonBlocking());
    const std::vector<char> data(1024, 'x');
    size_t sent{0};
    // The buffer is only really full if the writes keep failing for a while: the first refusals
    // can be transient, until the peer has acknowledged what was sent so far or has opened its
    // receive window again, which on Windows can take more than a second.
    std::optional<std::chrono::steady_clock::time_point> refused_since;
    while (!refused_since || std::chrono::steady_clock::now() - *refused_since < 2500ms) {
        // Far more than any sane socket buffer.
        BOOST_REQUIRE_LT(sent, 64 * 1024 * 1024);
        const ssize_t n{sock.Send(data.data(), data.size(), MSG_NOSIGNAL)};
        if (n >= 0) {
            sent += n;
            refused_since.reset();
        } else {
            BOOST_REQUIRE(!IOErrorIsPermanent(WSAGetLastError()));
            if (!refused_since) refused_since = std::chrono::steady_clock::now();
            std::this_thread::sleep_for(50ms);
        }
    }
}

/** Make `sock` start a non-blocking connect to `addr`. @return the error from connect() or 0. */
int StartConnect(const Sock& sock, const sockaddr_in& addr)
{
    BOOST_REQUIRE(sock.SetNonBlocking());
    if (sock.Connect(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0) return 0;
    return WSAGetLastError();
}

/** Same condition as in ConnectToSocket(): the connection is being established. */
bool ConnectInProgress(int err)
{
    return err == WSAEINPROGRESS || err == WSAEWOULDBLOCK || err == WSAEINVAL;
}

/** A loopback address on which nothing listens. */
sockaddr_in ClosedPortAddr()
{
    Sock sock{CreateSocket()};
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOST_REQUIRE_EQUAL(sock.Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    socklen_t len{sizeof(addr)};
    BOOST_REQUIRE_EQUAL(sock.GetSockName(reinterpret_cast<sockaddr*>(&addr), &len), 0);
    return addr;
}

} // namespace

// Data written by the peer wakes up a wait for RecvEvent, and only that socket is reported.
BOOST_AUTO_TEST_CASE(readable)
{
    SocketPair pair;
    SocketPair other;

    // Nothing was sent yet.
    BOOST_CHECK_EQUAL(WaitFor(*pair.server, SHORT_WAIT, Sock::RecvEvent), 0);

    BOOST_REQUIRE_EQUAL(pair.client->Send("a", 1, MSG_NOSIGNAL), 1);
    BOOST_CHECK_EQUAL(WaitFor(*pair.server, LONG_WAIT, Sock::RecvEvent), Sock::RecvEvent);

    // The data is not consumed by waiting, so the event is level-triggered.
    BOOST_CHECK_EQUAL(WaitFor(*pair.server, LONG_WAIT, Sock::RecvEvent), Sock::RecvEvent);

    // The unrelated connection is not readable.
    BOOST_CHECK_EQUAL(WaitFor(*other.server, SHORT_WAIT, Sock::RecvEvent), 0);

    char c;
    BOOST_CHECK_EQUAL(pair.server->Recv(&c, 1, 0), 1);
    BOOST_CHECK_EQUAL(c, 'a');
    // Once consumed, it is not readable anymore.
    BOOST_CHECK_EQUAL(WaitFor(*pair.server, SHORT_WAIT, Sock::RecvEvent), 0);
}

// A wait for SendEvent wakes up if there is room in the send buffer and does not if there is none.
BOOST_AUTO_TEST_CASE(writable)
{
    SocketPair pair{/*small_buffers=*/true};

    BOOST_CHECK_EQUAL(WaitFor(*pair.client, LONG_WAIT, Sock::SendEvent), Sock::SendEvent);

    FillSendBuffer(*pair.client);
    BOOST_CHECK_EQUAL(WaitFor(*pair.client, 500ms, Sock::SendEvent), 0);

    // Once the peer drains the data, there is room again.
    std::vector<char> buf(1024);
    while (WaitFor(*pair.server, 100ms, Sock::RecvEvent) == Sock::RecvEvent) {
        BOOST_REQUIRE(pair.server->Recv(buf.data(), buf.size(), 0) > 0);
    }
    BOOST_CHECK_EQUAL(WaitFor(*pair.client, LONG_WAIT, Sock::SendEvent), Sock::SendEvent);
}

// If nothing happens, the call returns after the timeout without reporting any event.
BOOST_AUTO_TEST_CASE(timeout)
{
    SocketPair pair;

    constexpr auto timeout{500ms};
    const auto wait_start{std::chrono::steady_clock::now()};
    BOOST_CHECK_EQUAL(WaitFor(*pair.server, timeout, Sock::RecvEvent), 0);
    BOOST_CHECK_GE(std::chrono::steady_clock::now() - wait_start, timeout * 9 / 10);

    // Same with WaitMany().
    Sock::EventsPerSock events;
    events.emplace(Key(*pair.server), Sock::Events{Sock::RecvEvent});
    events.emplace(Key(*pair.client), Sock::Events{Sock::RecvEvent});
    const auto start{std::chrono::steady_clock::now()};
    BOOST_REQUIRE(pair.server->WaitMany(timeout, events));
    BOOST_CHECK_GE(std::chrono::steady_clock::now() - start, timeout * 9 / 10);
    BOOST_CHECK_EQUAL(Occurred(events, *pair.server), 0);
    BOOST_CHECK_EQUAL(Occurred(events, *pair.client), 0);
}

// A peer that shuts down or closes its end makes the other end readable, with an end-of-stream.
BOOST_AUTO_TEST_CASE(peer_fin)
{
    char buf[8];

    {
        SocketPair pair;
#ifdef WIN32
        BOOST_REQUIRE_EQUAL(shutdown(pair.client_fd, SD_SEND), 0);
#else
        BOOST_REQUIRE_EQUAL(shutdown(pair.client_fd, SHUT_WR), 0);
#endif
        BOOST_CHECK(WaitFor(*pair.server, LONG_WAIT, Sock::RecvEvent) & Sock::RecvEvent);
        BOOST_CHECK_EQUAL(pair.server->Recv(buf, sizeof(buf), 0), 0);
    }

    {
        SocketPair pair;
        pair.client.reset();
        BOOST_CHECK(WaitFor(*pair.server, LONG_WAIT, Sock::RecvEvent) & Sock::RecvEvent);
        BOOST_CHECK_EQUAL(pair.server->Recv(buf, sizeof(buf), 0), 0);
    }
}

// A peer that resets the connection (RST) makes the other end wake up.
BOOST_AUTO_TEST_CASE(peer_rst)
{
    const auto reset_connection = [](SocketPair& pair) {
        linger lin{};
        lin.l_onoff = 1;
        lin.l_linger = 0;
        BOOST_REQUIRE_EQUAL(pair.client->SetSockOpt(SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)), 0);
        pair.client.reset();
    };

    {
        // Waiting for RecvEvent: either RecvEvent or ErrorEvent, and recv() fails.
        SocketPair pair;
        reset_connection(pair);
        BOOST_CHECK(WaitFor(*pair.server, LONG_WAIT, Sock::RecvEvent) & (Sock::RecvEvent | Sock::ErrorEvent));
        char buf[8];
        BOOST_CHECK_LT(pair.server->Recv(buf, sizeof(buf), 0), 0);
    }

    {
        // Waiting only for SendEvent: it wakes up and send() fails, so that the caller notices.
        SocketPair pair;
        reset_connection(pair);
        BOOST_CHECK(WaitFor(*pair.server, LONG_WAIT, Sock::SendEvent) != 0);
        bool failed{false};
        // The first send() may still be accepted by the stack.
        for (int i{0}; i < 5 && !failed; ++i) {
            failed = pair.server->Send("x", 1, MSG_NOSIGNAL) < 0;
            if (!failed) std::this_thread::sleep_for(100ms);
        }
        BOOST_CHECK(failed);
    }
}

// A non-blocking connect() that fails wakes up the wait that is done like in ConnectToSocket().
BOOST_AUTO_TEST_CASE(connect_refused)
{
    const sockaddr_in addr{ClosedPortAddr()};
    Sock sock{CreateSocket()};
    const int err{StartConnect(sock, addr)};
    if (!ConnectInProgress(err)) {
        // Some systems report a refused connection to loopback right away.
        BOOST_TEST_MESSAGE("connect() failed immediately with error " << err);
        BOOST_CHECK_NE(err, 0);
        return;
    }

    // Windows retries a refused connection a few times for about 2 seconds before failing.
    const auto occurred{WaitFor(sock, 10s, Sock::RecvEvent | Sock::SendEvent)};
    BOOST_CHECK_NE(occurred, 0);
    BOOST_CHECK_NE(SocketError(sock), 0);
}

// A non-blocking connect() that succeeds is reported as SendEvent.
BOOST_AUTO_TEST_CASE(connect_succeeds)
{
    const SOCKET listener_fd{CreateSocket()};
    Sock listener{listener_fd};
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOST_REQUIRE_EQUAL(listener.Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    BOOST_REQUIRE_EQUAL(listener.Listen(1), 0);
    socklen_t len{sizeof(addr)};
    BOOST_REQUIRE_EQUAL(listener.GetSockName(reinterpret_cast<sockaddr*>(&addr), &len), 0);

    Sock sock{CreateSocket()};
    const int err{StartConnect(sock, addr)};
    BOOST_REQUIRE(err == 0 || ConnectInProgress(err));

    BOOST_CHECK(WaitFor(sock, LONG_WAIT, Sock::RecvEvent | Sock::SendEvent) & Sock::SendEvent);
    BOOST_CHECK_EQUAL(SocketError(sock), 0);
}

// An incoming connection makes the listening socket readable.
BOOST_AUTO_TEST_CASE(listening_socket)
{
    const SOCKET listener_fd{CreateSocket()};
    Sock listener{listener_fd};
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOST_REQUIRE_EQUAL(listener.Bind(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    BOOST_REQUIRE_EQUAL(listener.Listen(1), 0);
    socklen_t len{sizeof(addr)};
    BOOST_REQUIRE_EQUAL(listener.GetSockName(reinterpret_cast<sockaddr*>(&addr), &len), 0);

    BOOST_CHECK_EQUAL(WaitFor(listener, SHORT_WAIT, Sock::RecvEvent), 0);

    Sock client{CreateSocket()};
    BOOST_REQUIRE_EQUAL(client.Connect(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    BOOST_CHECK_EQUAL(WaitFor(listener, LONG_WAIT, Sock::RecvEvent), Sock::RecvEvent);
    BOOST_CHECK(listener.Accept(nullptr, nullptr) != nullptr);
}

// WaitMany() attributes the events to the right sockets.
BOOST_AUTO_TEST_CASE(wait_many_attribution)
{
    SocketPair readable;
    SocketPair writable;
    SocketPair idle;

    BOOST_REQUIRE_EQUAL(readable.client->Send("a", 1, MSG_NOSIGNAL), 1);
    // Make sure that the data has arrived.
    BOOST_REQUIRE_EQUAL(WaitFor(*readable.server, LONG_WAIT, Sock::RecvEvent), Sock::RecvEvent);

    Sock::EventsPerSock events;
    events.emplace(Key(*readable.server), Sock::Events{Sock::RecvEvent});
    events.emplace(Key(*writable.client), Sock::Events{Sock::SendEvent});
    events.emplace(Key(*idle.server), Sock::Events{Sock::RecvEvent});

    BOOST_REQUIRE(readable.server->WaitMany(LONG_WAIT, events));
    BOOST_CHECK_EQUAL(Occurred(events, *readable.server), Sock::RecvEvent);
    BOOST_CHECK_EQUAL(Occurred(events, *writable.client), Sock::SendEvent);
    BOOST_CHECK_EQUAL(Occurred(events, *idle.server), 0);

    // Requesting both for each of them reports what is actually ready.
    events.clear();
    events.emplace(Key(*readable.server), Sock::Events{Sock::RecvEvent | Sock::SendEvent});
    events.emplace(Key(*writable.client), Sock::Events{Sock::RecvEvent | Sock::SendEvent});
    events.emplace(Key(*idle.server), Sock::Events{Sock::RecvEvent});
    BOOST_REQUIRE(readable.server->WaitMany(LONG_WAIT, events));
    BOOST_CHECK_EQUAL(Occurred(events, *readable.server), Sock::RecvEvent | Sock::SendEvent);
    BOOST_CHECK_EQUAL(Occurred(events, *writable.client), Sock::SendEvent);
    BOOST_CHECK_EQUAL(Occurred(events, *idle.server), 0);
}

// A socket for which no event is requested does not disturb the wait and never reports anything.
BOOST_AUTO_TEST_CASE(wait_many_nothing_requested)
{
    SocketPair unwanted;
    SocketPair pair;

    {
        // The wait returns when the other socket becomes readable.
        ssize_t sent{0};
        std::thread sender{[&pair, &sent] {
            std::this_thread::sleep_for(200ms);
            sent = pair.client->Send("a", 1, MSG_NOSIGNAL);
        }};

        Sock::EventsPerSock events;
        events.emplace(Key(*unwanted.server), Sock::Events{0});
        events.emplace(Key(*pair.server), Sock::Events{Sock::RecvEvent});
        const bool ok{pair.server->WaitMany(LONG_WAIT, events)};
        sender.join();
        BOOST_REQUIRE_EQUAL(sent, 1);
        BOOST_REQUIRE(ok);
        BOOST_CHECK_EQUAL(Occurred(events, *unwanted.server), 0);
        BOOST_CHECK_EQUAL(Occurred(events, *pair.server), Sock::RecvEvent);
    }

    {
        // If the other socket is idle, the wait times out normally.
        SocketPair idle;
        Sock::EventsPerSock events;
        events.emplace(Key(*unwanted.server), Sock::Events{0});
        events.emplace(Key(*idle.server), Sock::Events{Sock::RecvEvent});
        constexpr auto timeout{500ms};
        const auto start{std::chrono::steady_clock::now()};
        BOOST_REQUIRE(idle.server->WaitMany(timeout, events));
        BOOST_CHECK_GE(std::chrono::steady_clock::now() - start, timeout * 9 / 10);
        BOOST_CHECK_EQUAL(Occurred(events, *unwanted.server), 0);
        BOOST_CHECK_EQUAL(Occurred(events, *idle.server), 0);
    }
}

// A lone byte of urgent data must not make a wait for RecvEvent return, as it is not
// readable by a normal recv().
// NOTE: this is expected to FAIL with the select() backend, which reports urgent data as an
// exceptional condition of the socket (ErrorEvent), and to pass with poll().
BOOST_AUTO_TEST_CASE(urgent_data_does_not_wake_recv)
{
    SocketPair pair;
    SendUrgentByte(pair.client_fd);
    BOOST_CHECK_EQUAL(WaitFor(*pair.server, SHORT_WAIT, Sock::RecvEvent), 0);
}

// A lone byte of urgent data must not make a wait for SendEvent return when the send buffer is
// full, otherwise the caller would spin.
// NOTE: like above, this is expected to FAIL with the select() backend.
BOOST_AUTO_TEST_CASE(urgent_data_does_not_wake_send)
{
    SocketPair pair{/*small_buffers=*/true};
    FillSendBuffer(*pair.client);
    BOOST_REQUIRE_EQUAL(WaitFor(*pair.client, SHORT_WAIT, Sock::SendEvent), 0);

    // The peer sends us the urgent byte.
    SendUrgentByte(pair.server_fd);
    BOOST_CHECK_EQUAL(WaitFor(*pair.client, SHORT_WAIT, Sock::SendEvent), 0);
}

// Normal data followed by an urgent byte makes the socket readable, and the data that is read
// does not include the urgent byte.
BOOST_AUTO_TEST_CASE(urgent_data_after_normal_data)
{
    SocketPair pair;
    BOOST_REQUIRE_EQUAL(pair.client->Send("hello", 5, MSG_NOSIGNAL), 5);
    SendUrgentByte(pair.client_fd);

    BOOST_CHECK(WaitFor(*pair.server, LONG_WAIT, Sock::RecvEvent) & Sock::RecvEvent);
    char buf[16];
    const ssize_t n{pair.server->Recv(buf, sizeof(buf), 0)};
    BOOST_REQUIRE_GT(n, 0);
    BOOST_CHECK_EQUAL(std::string(buf, n), std::string("hello", n));
    BOOST_CHECK(std::memchr(buf, 'U', n) == nullptr);
}

#ifndef WIN32
// A socket whose descriptor is not below FD_SETSIZE (1024) can be waited on.
// NOTE: this is expected to FAIL with the select() backend and to pass with poll().
BOOST_AUTO_TEST_CASE(high_descriptor)
{
    constexpr int HIGH_FD{1100};

    rlimit limit;
    BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_NOFILE, &limit), 0);
    const rlimit original{limit};
    if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max <= HIGH_FD) {
        BOOST_TEST_MESSAGE("hard limit on the number of file descriptors is too low, skipping");
        return;
    }
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur <= HIGH_FD) {
        limit.rlim_cur = HIGH_FD + 1;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            BOOST_TEST_MESSAGE("could not raise the limit on the number of file descriptors, skipping");
            return;
        }
    }

    {
        SocketPair pair;
        // Make sure not to clobber a descriptor that is in use.
        if (fcntl(HIGH_FD, F_GETFD) != -1 || errno != EBADF) {
            BOOST_TEST_MESSAGE("descriptor " << HIGH_FD << " is in use, skipping");
        } else if (dup2(static_cast<int>(pair.server_fd), HIGH_FD) != HIGH_FD) {
            BOOST_TEST_MESSAGE("could not duplicate a descriptor to " << HIGH_FD << ", skipping");
        } else {
            // This owns and closes the high descriptor. The connection stays open through the
            // original descriptor.
            Sock high{static_cast<SOCKET>(HIGH_FD)};
            BOOST_CHECK_EQUAL(WaitFor(high, SHORT_WAIT, Sock::RecvEvent), 0);
            BOOST_REQUIRE_EQUAL(pair.client->Send("a", 1, MSG_NOSIGNAL), 1);
            BOOST_CHECK_EQUAL(WaitFor(high, LONG_WAIT, Sock::RecvEvent), Sock::RecvEvent);
            BOOST_CHECK_EQUAL(WaitFor(high, LONG_WAIT, Sock::SendEvent), Sock::SendEvent);
        }
    }

    BOOST_REQUIRE_EQUAL(setrlimit(RLIMIT_NOFILE, &original), 0);
}
#endif // WIN32

BOOST_AUTO_TEST_SUITE_END()
