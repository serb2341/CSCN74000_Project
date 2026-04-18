#include "pch.h"
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include "CppUnitTest.h"

#include "../Server/Server.h"
#include "../GroundControlClient/Packet.h"
#include "../Server/CRC32.h"
#include "../Server/VerificationPacket.h"
#include "../GroundControlClient/GroundControlClient.h"
#include "../InFlightClient/InFlightClient.h"
#include "../GroundControlClient/Handshake.h"

#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// ============================================================
//  Shared constants
// ============================================================
static const std::string TEST_SECRET = "TestSecret123";

// Each test class gets its own dedicated port to avoid TIME_WAIT
// conflicts. When a test closes its sockets, the OS holds the port
// in TIME_WAIT for up to 120 seconds. If the next test class tries
// to bind to the same port it fails silently, accept() hangs on
// INVALID_SOCKET, and the test runner aborts the entire run.
static constexpr unsigned short PORT_HANDSHAKE = 55500;
static constexpr unsigned short PORT_BIDIRECTIONAL = 55501;
static constexpr unsigned short PORT_BIDIRECTIONAL_A = 55502;   // Two-listener test
static constexpr unsigned short PORT_BIDIRECTIONAL_B = 55503;   // Two-listener test
static constexpr unsigned short PORT_DISCONNECTION = 55504;
static constexpr unsigned short PORT_FLIGHTID = 55505;
static constexpr unsigned short PORT_SESSION = 55506;

// Small pause to let a background thread reach accept() before
// the foreground thread calls connect().
static void WaitForThread()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
}


// ============================================================
//  TEST CLASS 1 — Handshake Integration
//
//  Server::PerformHandshake() against
//  InFlightClient::PerformHandshake() over a real TCP socket.
// ============================================================
TEST_CLASS(Test_Handshake_Integration)
{
    static SOCKET MakeListenSocket(unsigned short port = PORT_HANDSHAKE)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        int opt = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }

        (void)listen(s, 2);
        return s;
    }

    static SOCKET MakeClientSocket(unsigned short port = PORT_HANDSHAKE)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }
        return s;
    }

public:

    TEST_CLASS_INITIALIZE(ClassSetup)
    {
        WSADATA w;
        (void)WSAStartup(MAKEWORD(2, 2), &w);
        srand(42);
    }

    TEST_CLASS_CLEANUP(ClassTeardown)
    {
        (void)WSACleanup();
    }

    // ----------------------------------------------------------
    // Test 1: Full handshake with correct shared secret succeeds
    //         on both the server side and the client side.
    // ----------------------------------------------------------
    TEST_METHOD(Test1_CorrectSecret_HandshakeSucceeds)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 1: Listening socket creation must succeed");

        Networking::Server server;
        server.sharedSecret = TEST_SECRET;

        std::atomic<bool> serverResult{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn != INVALID_SOCKET)
                {
                    serverResult = server.PerformHandshake(conn, "InFlightClient");
                    (void)closesocket(conn);
                }
            });

        WaitForThread();

        InFlightClient::InFlightClient ifClient;
        ifClient.sharedSecret = TEST_SECRET;

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 1: Client socket must connect to the server");

        bool clientResult = ifClient.PerformHandshake(clientSock, "InFlightClient");

        serverThread.join();

        (void)closesocket(clientSock);
        (void)closesocket(listenSock);

        Assert::IsTrue(clientResult,
            L"Test 1: InFlightClient::PerformHandshake must return true with correct secret");
        Assert::IsTrue(serverResult,
            L"Test 1: Server::PerformHandshake must return true with correct secret");
    }

    // ----------------------------------------------------------
    // Test 2: Handshake fails when the client uses the wrong
    //         shared secret. Client socket is closed BEFORE
    //         joining the server thread to avoid the deadlock
    //         where server blocks on recv() in Step 4.
    // ----------------------------------------------------------
    TEST_METHOD(Test2_WrongClientSecret_HandshakeFails)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 2: Listening socket creation must succeed");

        Networking::Server server;
        server.sharedSecret = TEST_SECRET;

        std::atomic<bool> serverResult{ true };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn != INVALID_SOCKET)
                {
                    serverResult = server.PerformHandshake(conn, "InFlightClient");
                    (void)closesocket(conn);
                }
            });

        WaitForThread();

        InFlightClient::InFlightClient ifClient;
        ifClient.sharedSecret = "COMPLETELY_WRONG_SECRET";

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 2: Client socket must connect");

        bool clientResult = ifClient.PerformHandshake(clientSock, "InFlightClient");

        // Close BEFORE join() — unblocks server's recv() in Step 4.
        (void)closesocket(clientSock);
        clientSock = INVALID_SOCKET;

        serverThread.join();

        (void)closesocket(listenSock);

        bool atLeastOneFailed = (!clientResult || !serverResult);
        Assert::IsTrue(atLeastOneFailed,
            L"Test 2: At least one side must reject a wrong shared secret");
    }

    // ----------------------------------------------------------
    // Test 3: A tampered CRC in the client challenge packet is
    //         detected by Server::PerformHandshake in Step 1.
    // ----------------------------------------------------------
    TEST_METHOD(Test3_TamperedChallengeCRC_ServerRejectsHandshake)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 3: Listening socket must be created");

        Networking::Server server;
        server.sharedSecret = TEST_SECRET;

        std::atomic<bool> serverAccepted{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn != INVALID_SOCKET)
                {
                    serverAccepted = server.PerformHandshake(conn, "InFlightClient");
                    (void)closesocket(conn);
                }
            });

        WaitForThread();

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 3: Client must connect");

        // Send a challenge packet with a deliberately invalid CRC.
        ServerHandshake::ChallengePacket ch{};
        ch.Type = static_cast<uint32_t>(ServerHandshake::VerificationPacketType::CHALLENGE);
        ch.Random = 0xDEADBEEF;
        ch.CRC32 = 0x00000000;   // wrong — server must reject this

        (void)send(clientSock,
            reinterpret_cast<const char*>(&ch), sizeof(ch), 0);

        // Close before join — server exits after detecting the bad CRC
        // in Step 1, so no deadlock risk here, but consistent practice.
        (void)closesocket(clientSock);
        clientSock = INVALID_SOCKET;

        serverThread.join();

        (void)closesocket(listenSock);

        Assert::IsFalse(serverAccepted,
            L"Test 3: Server::PerformHandshake must return false for a tampered CRC");
    }

    // ----------------------------------------------------------
    // Test 4: Empty shared secret causes handshake failure.
    //         Client socket closed before join() to prevent
    //         deadlock on server's Step 4 recv().
    // ----------------------------------------------------------
    TEST_METHOD(Test4_EmptyClientSecret_HandshakeFails)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 4: Listening socket must be created");

        Networking::Server server;
        server.sharedSecret = TEST_SECRET;

        std::atomic<bool> serverResult{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn != INVALID_SOCKET)
                {
                    serverResult = server.PerformHandshake(conn, "InFlightClient");
                    (void)closesocket(conn);
                }
            });

        WaitForThread();

        InFlightClient::InFlightClient ifClient;
        ifClient.sharedSecret = "";   // empty — signatures will not match

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 4: Client must connect");

        bool clientResult = ifClient.PerformHandshake(clientSock, "InFlightClient");

        // Close BEFORE join() — unblocks server's recv() in Step 4.
        (void)closesocket(clientSock);
        clientSock = INVALID_SOCKET;

        serverThread.join();

        (void)closesocket(listenSock);

        bool atLeastOneFailed = (!clientResult || !serverResult);
        Assert::IsTrue(atLeastOneFailed,
            L"Test 4: An empty shared secret must cause failure on at least one side");
    }

    // ----------------------------------------------------------
    // Test 5: GroundControlClient handshake with the server
    //         succeeds when the correct shared secret is used.
    // ----------------------------------------------------------
    TEST_METHOD(Test5_GroundControlClient_HandshakeSucceeds)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 5: Listening socket must be created");

        Networking::Server server;
        server.sharedSecret = TEST_SECRET;

        std::atomic<bool> serverResult{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn != INVALID_SOCKET)
                {
                    serverResult = server.PerformHandshake(conn, "GroundControl");
                    (void)closesocket(conn);
                }
            });

        WaitForThread();

        SOCKET gcSock = MakeClientSocket();
        Assert::IsTrue(gcSock != INVALID_SOCKET,
            L"Test 5: GC socket must connect");

        bool gcResult = GroundControlMutualVerification::Handshake::Execute(gcSock, TEST_SECRET);

        serverThread.join();

        (void)closesocket(gcSock);
        (void)closesocket(listenSock);

        Assert::IsTrue(gcResult,
            L"Test 5: Handshake::Execute must succeed for GC client with correct secret");
        Assert::IsTrue(serverResult,
            L"Test 5: Server::PerformHandshake must succeed for GC client");
    }
};


//// ============================================================
////  TEST CLASS 2 — Packet Relay Integration
////
////  Uses Communication::Packet (real class) to build, send,
////  receive, and validate packets. Server::ValidatePacket()
////  and InFlightClient::ValidatePacket() are called directly.
//// ============================================================
//TEST_CLASS(Test_PacketRelay_Integration)
//{
//    static SOCKET MakeListenSocket(unsigned short port = PORT_BIDIRECTIONAL)
//    {
//        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//        if (s == INVALID_SOCKET) return INVALID_SOCKET;
//
//        int opt = 1;
//        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
//            reinterpret_cast<const char*>(&opt), sizeof(opt));
//
//        sockaddr_in addr{};
//        addr.sin_family = AF_INET;
//        addr.sin_addr.s_addr = INADDR_ANY;
//        addr.sin_port = htons(port);
//
//        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
//        {
//            (void)closesocket(s);
//            return INVALID_SOCKET;
//        }
//
//        (void)listen(s, 2);
//        return s;
//    }
//
//    static SOCKET MakeClientSocket(unsigned short port = PORT_BIDIRECTIONAL)
//    {
//        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//        if (s == INVALID_SOCKET) return INVALID_SOCKET;
//
//        sockaddr_in addr{};
//        addr.sin_family = AF_INET;
//        addr.sin_port = htons(port);
//        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
//
//        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
//        {
//            (void)closesocket(s);
//            return INVALID_SOCKET;
//        }
//        return s;
//    }
//
//    static std::vector<char> BuildPacket(unsigned int       flightID,
//        unsigned int       msgType,
//        const std::string& body)
//    {
//        InFlightCommunication::Packet pkt;
//        pkt.SetFlightID(flightID);
//        pkt.SetMessageType(msgType);
//        pkt.SetData(body.c_str(), static_cast<unsigned int>(body.size()));
//        unsigned int sz = 0;
//        char* raw = pkt.SerializeData(sz);
//        return std::vector<char>(raw, raw + sz);
//    }
//
//    static std::vector<char> RecvFullPacket(SOCKET sock)
//    {
//        char headerBuf[sizeof(InFlightCommunication::PacketHeader)];
//        if (recv(sock, headerBuf, sizeof(headerBuf), MSG_WAITALL)
//            != sizeof(InFlightCommunication::PacketHeader))
//            return {};
//
//        InFlightCommunication::PacketHeader hdr{};
//        (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));
//
//        unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
//        std::vector<char> buf(total);
//        (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));
//
//        recv(sock, buf.data() + sizeof(hdr),
//            static_cast<int>(hdr.Length + sizeof(uint32_t)), MSG_WAITALL);
//
//        return buf;
//    }
//
//public:
//
//    TEST_CLASS_INITIALIZE(ClassSetup)
//    {
//        WSADATA w;
//        (void)WSAStartup(MAKEWORD(2, 2), &w);
//    }
//
//    TEST_CLASS_CLEANUP(ClassTeardown)
//    {
//        (void)WSACleanup();
//    }
//
//    // ----------------------------------------------------------
//    // Test 6: Packet sent by InFlight side arrives intact at GC.
//    //         Server::ValidatePacket() confirms structural and
//    //         CRC integrity after the packet crosses the wire.
//    // ----------------------------------------------------------
//    TEST_METHOD(Test6_InFlightToGC_PacketArrivesIntact)
//    {
//        SOCKET listenSock = MakeListenSocket();
//        Assert::IsTrue(listenSock != INVALID_SOCKET,
//            L"Test 6: Listening socket must be created");
//
//        const unsigned int FLIGHT_ID = 101;
//        const unsigned int MSG_TYPE = 0;
//        const std::string  BODY = "Hello Ground Control";
//
//        Networking::Server server;
//        std::vector<char>  receivedBuf;
//        std::atomic<bool>  packetValid{ false };
//
//        std::thread receiverThread([&]()
//            {
//                SOCKET conn = accept(listenSock, nullptr, nullptr);
//                if (conn == INVALID_SOCKET) return;
//
//                receivedBuf = RecvFullPacket(conn);
//
//                if (!receivedBuf.empty())
//                {
//                    packetValid = server.ValidatePacket(
//                        receivedBuf.data(),
//                        static_cast<unsigned int>(receivedBuf.size()));
//                }
//
//                (void)closesocket(conn);
//            });
//
//        WaitForThread();
//
//        SOCKET senderSock = MakeClientSocket();
//        Assert::IsTrue(senderSock != INVALID_SOCKET,
//            L"Test 6: Sender socket must connect");
//
//        auto pktBytes = BuildPacket(FLIGHT_ID, MSG_TYPE, BODY);
//        int sent = send(senderSock,
//            pktBytes.data(), static_cast<int>(pktBytes.size()), 0);
//
//        receiverThread.join();
//
//        (void)closesocket(senderSock);
//        (void)closesocket(listenSock);
//
//        Assert::AreEqual(static_cast<int>(pktBytes.size()), sent,
//            L"Test 6: All bytes must be sent");
//        Assert::IsTrue(packetValid,
//            L"Test 6: Server::ValidatePacket must confirm packet integrity");
//        Assert::IsFalse(receivedBuf.empty(),
//            L"Test 6: Receiver buffer must not be empty");
//
//        GroundControlCommunication::Packet rxPkt(receivedBuf.data());
//        Assert::AreEqual(FLIGHT_ID, rxPkt.GetFlightID(),
//            L"Test 6: FlightID must match after transmission");
//        Assert::AreEqual(static_cast<unsigned int>(BODY.size()),
//            rxPkt.GetBodyLength(),
//            L"Test 6: Body length must match after transmission");
//
//        std::string rxBody(rxPkt.GetData(), rxPkt.GetBodyLength());
//        Assert::AreEqual(BODY, rxBody,
//            L"Test 6: Body content must be identical after transmission");
//    }
//
//    // ----------------------------------------------------------
//    // Test 7: GC reply packet is correctly received by InFlight.
//    //         InFlightClient::ValidatePacket() verifies integrity.
//    // ----------------------------------------------------------
//    TEST_METHOD(Test7_GCReply_ReceivedAndValidatedByInFlight)
//    {
//        SOCKET listenSock = MakeListenSocket();
//        Assert::IsTrue(listenSock != INVALID_SOCKET,
//            L"Test 7: Listening socket must be created");
//
//        const unsigned int FLIGHT_ID = 202;
//        const std::string  REPLY = "Acknowledged, cleared to land";
//
//        InFlightClient::InFlightClient ifClient;
//        std::vector<char>              receivedBuf;
//        std::atomic<bool>              packetValid{ false };
//
//        std::thread inFlightThread([&]()
//            {
//                SOCKET conn = accept(listenSock, nullptr, nullptr);
//                if (conn == INVALID_SOCKET) return;
//
//                receivedBuf = RecvFullPacket(conn);
//
//                if (!receivedBuf.empty())
//                {
//                    packetValid = ifClient.ValidatePacket(
//                        receivedBuf.data(),
//                        static_cast<unsigned int>(receivedBuf.size()));
//                }
//
//                (void)closesocket(conn);
//            });
//
//        WaitForThread();
//
//        SOCKET gcSock = MakeClientSocket();
//        Assert::IsTrue(gcSock != INVALID_SOCKET,
//            L"Test 7: GC socket must connect");
//
//        auto pktBytes = BuildPacket(FLIGHT_ID, 0, REPLY);
//        (void)send(gcSock, pktBytes.data(),
//            static_cast<int>(pktBytes.size()), 0);
//
//        inFlightThread.join();
//
//        (void)closesocket(gcSock);
//        (void)closesocket(listenSock);
//
//        Assert::IsTrue(packetValid,
//            L"Test 7: InFlightClient::ValidatePacket must confirm GC reply integrity");
//
//        GroundControlCommunication::Packet rxPkt(receivedBuf.data());
//        std::string body(rxPkt.GetData(), rxPkt.GetBodyLength());
//        Assert::AreEqual(REPLY, body,
//            L"Test 7: Reply body must arrive word-for-word");
//        Assert::AreEqual(FLIGHT_ID, rxPkt.GetFlightID(),
//            L"Test 7: FlightID must be preserved in the GC reply");
//    }
//
//    // ----------------------------------------------------------
//    // Test 8: A deliberately corrupted packet body is rejected
//    //         by Server::ValidatePacket (CRC mismatch detected).
//    // ----------------------------------------------------------
//    TEST_METHOD(Test8_CorruptedPacketBody_RejectedByServerValidation)
//    {
//        SOCKET listenSock = MakeListenSocket();
//        Assert::IsTrue(listenSock != INVALID_SOCKET,
//            L"Test 8: Listening socket must be created");
//
//        Networking::Server server;
//        std::atomic<bool>  packetAccepted{ true };
//
//        std::thread serverThread([&]()
//            {
//                SOCKET conn = accept(listenSock, nullptr, nullptr);
//                if (conn == INVALID_SOCKET) return;
//
//                std::vector<char> buf = RecvFullPacket(conn);
//                if (!buf.empty())
//                {
//                    packetAccepted = server.ValidatePacket(
//                        buf.data(),
//                        static_cast<unsigned int>(buf.size()));
//                }
//                (void)closesocket(conn);
//            });
//
//        WaitForThread();
//
//        SOCKET clientSock = MakeClientSocket();
//        Assert::IsTrue(clientSock != INVALID_SOCKET,
//            L"Test 8: Client must connect");
//
//        auto pktBytes = BuildPacket(404, 0, "Uncorrupted body text here");
//        pktBytes[sizeof(InFlightCommunication::PacketHeader) + 2] ^= 0xFF;
//
//        (void)send(clientSock, pktBytes.data(),
//            static_cast<int>(pktBytes.size()), 0);
//
//        serverThread.join();
//
//        (void)closesocket(clientSock);
//        (void)closesocket(listenSock);
//
//        Assert::IsFalse(packetAccepted,
//            L"Test 8: Server::ValidatePacket must return false for a corrupted body");
//    }
//
//    // ----------------------------------------------------------
//    // Test 9: A corrupted packet is also rejected by
//    //         InFlightClient::ValidatePacket (CRC mismatch).
//    // ----------------------------------------------------------
//    TEST_METHOD(Test9_CorruptedPacket_RejectedByInFlightValidation)
//    {
//        SOCKET listenSock = MakeListenSocket();
//        Assert::IsTrue(listenSock != INVALID_SOCKET,
//            L"Test 9: Listening socket must be created");
//
//        InFlightClient::InFlightClient ifClient;
//        std::atomic<bool>              packetAccepted{ true };
//
//        std::thread receiverThread([&]()
//            {
//                SOCKET conn = accept(listenSock, nullptr, nullptr);
//                if (conn == INVALID_SOCKET) return;
//
//                std::vector<char> buf = RecvFullPacket(conn);
//                if (!buf.empty())
//                {
//                    packetAccepted = ifClient.ValidatePacket(
//                        buf.data(),
//                        static_cast<unsigned int>(buf.size()));
//                }
//                (void)closesocket(conn);
//            });
//
//        WaitForThread();
//
//        SOCKET clientSock = MakeClientSocket();
//        Assert::IsTrue(clientSock != INVALID_SOCKET,
//            L"Test 9: Client must connect");
//
//        auto pktBytes = BuildPacket(505, 0, "Body to be corrupted");
//        pktBytes[sizeof(InFlightCommunication::PacketHeader) + 3] ^= 0xAB;
//
//        (void)send(clientSock, pktBytes.data(),
//            static_cast<int>(pktBytes.size()), 0);
//
//        receiverThread.join();
//
//        (void)closesocket(clientSock);
//        (void)closesocket(listenSock);
//
//        Assert::IsFalse(packetAccepted,
//            L"Test 9: InFlightClient::ValidatePacket must return false for corrupted data");
//    }
//};


// ============================================================
//  TEST CLASS 3 — Bidirectional Message Exchange
//
//  Tests a full request-reply cycle through a relay thread
//  that calls Server::ValidatePacket before forwarding.
// ============================================================
TEST_CLASS(Test_BidirectionalExchange_Integration)
{
    static SOCKET MakeListenSocket(unsigned short port)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        int opt = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }

        (void)listen(s, 2);
        return s;
    }

    static SOCKET MakeClientSocket(unsigned short port)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }
        return s;
    }

    static std::vector<char> BuildPacket(unsigned int       flightID,
        unsigned int       msgType,
        const std::string& body)
    {
        InFlightCommunication::Packet pkt;
        pkt.SetFlightID(flightID);
        pkt.SetMessageType(msgType);
        pkt.SetData(body.c_str(), static_cast<unsigned int>(body.size()));
        unsigned int sz = 0;
        char* raw = pkt.SerializeData(sz);
        return std::vector<char>(raw, raw + sz);
    }

    static std::vector<char> RecvFullPacket(SOCKET sock)
    {
        char headerBuf[sizeof(InFlightCommunication::PacketHeader)];
        if (recv(sock, headerBuf, sizeof(headerBuf), MSG_WAITALL)
            != sizeof(InFlightCommunication::PacketHeader))
            return {};

        InFlightCommunication::PacketHeader hdr{};
        (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));

        unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
        std::vector<char> buf(total);
        (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));

        recv(sock, buf.data() + sizeof(hdr),
            static_cast<int>(hdr.Length + sizeof(uint32_t)), MSG_WAITALL);

        return buf;
    }

public:

    TEST_CLASS_INITIALIZE(ClassSetup)
    {
        WSADATA w;
        (void)WSAStartup(MAKEWORD(2, 2), &w);
    }

    TEST_CLASS_CLEANUP(ClassTeardown)
    {
        (void)WSACleanup();
    }

    // ----------------------------------------------------------
    // Test 10: Full request-reply cycle through a relay that
    //          calls Server::ValidatePacket before forwarding.
    // ----------------------------------------------------------
    TEST_METHOD(Test10_RequestReply_ThroughValidatingRelay)
    {
        // Two separate ports — one for InFlight, one for GC.
        SOCKET listenA = MakeListenSocket(PORT_BIDIRECTIONAL_A);
        SOCKET listenB = MakeListenSocket(PORT_BIDIRECTIONAL_B);

        Assert::IsTrue(listenA != INVALID_SOCKET && listenB != INVALID_SOCKET,
            L"Test 10: Both listening sockets must be created");

        const std::string INFLIGHT_MSG = "Position: 35000ft heading 090";
        const std::string GC_REPLY = "Roger that, maintain altitude";

        Networking::Server server;
        std::string        gcReceived;
        std::string        ifReceived;
        std::atomic<bool>  relayDone{ false };

        std::thread relayThread([&]()
            {
                SOCKET sockA = accept(listenA, nullptr, nullptr);
                SOCKET sockB = accept(listenB, nullptr, nullptr);
                if (sockA == INVALID_SOCKET || sockB == INVALID_SOCKET) return;

                // A -> B (InFlight -> GC)
                {
                    auto buf = RecvFullPacket(sockA);
                    if (!buf.empty() &&
                        server.ValidatePacket(buf.data(),
                            static_cast<unsigned int>(buf.size())))
                    {
                        send(sockB, buf.data(), static_cast<int>(buf.size()), 0);
                    }
                }

                // B -> A (GC -> InFlight)
                {
                    auto buf = RecvFullPacket(sockB);
                    if (!buf.empty() &&
                        server.ValidatePacket(buf.data(),
                            static_cast<unsigned int>(buf.size())))
                    {
                        send(sockA, buf.data(), static_cast<int>(buf.size()), 0);
                    }
                }

                relayDone = true;
                (void)closesocket(sockA);
                (void)closesocket(sockB);
            });

        WaitForThread();

        std::thread gcThread([&]()
            {
                SOCKET gcSock = MakeClientSocket(PORT_BIDIRECTIONAL_B);
                if (gcSock == INVALID_SOCKET) return;

                auto buf = RecvFullPacket(gcSock);
                if (!buf.empty())
                {
                    GroundControlCommunication::Packet rxPkt(buf.data());
                    gcReceived = std::string(rxPkt.GetData(), rxPkt.GetBodyLength());

                    auto replyBytes = BuildPacket(rxPkt.GetFlightID(), 0, GC_REPLY);
                    send(gcSock, replyBytes.data(),
                        static_cast<int>(replyBytes.size()), 0);
                }
                (void)closesocket(gcSock);
            });

        SOCKET ifSock = MakeClientSocket(PORT_BIDIRECTIONAL_A);
        Assert::IsTrue(ifSock != INVALID_SOCKET,
            L"Test 10: InFlight socket must connect");

        auto msgBytes = BuildPacket(505, 0, INFLIGHT_MSG);
        (void)send(ifSock, msgBytes.data(),
            static_cast<int>(msgBytes.size()), 0);

        auto replyBuf = RecvFullPacket(ifSock);
        if (!replyBuf.empty())
        {
            GroundControlCommunication::Packet replyPkt(replyBuf.data());
            ifReceived = std::string(replyPkt.GetData(), replyPkt.GetBodyLength());
        }

        gcThread.join();
        relayThread.join();

        (void)closesocket(ifSock);
        (void)closesocket(listenA);
        (void)closesocket(listenB);

        Assert::AreEqual(INFLIGHT_MSG, gcReceived,
            L"Test 10: GC must receive the exact InFlight message");
        Assert::AreEqual(GC_REPLY, ifReceived,
            L"Test 10: InFlight must receive the exact GC reply");
        Assert::IsTrue(relayDone,
            L"Test 10: Relay must complete both validated forwarding operations");
    }

    // ----------------------------------------------------------
    // Test 11: Three sequential messages arrive in the correct
    //          order, each passing Server::ValidatePacket.
    // ----------------------------------------------------------
    TEST_METHOD(Test11_MultipleMessages_OrderAndContentPreserved)
    {
        SOCKET listenSock = MakeListenSocket(PORT_BIDIRECTIONAL);
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 11: Listening socket must be created");

        const std::vector<std::string> MESSAGES = {
            "MSG_ONE: Departure clearance requested",
            "MSG_TWO: En-route update - turbulence ahead",
            "MSG_THREE: Final approach checklist complete"
        };

        Networking::Server       server;
        std::vector<std::string> received;
        std::atomic<bool>        allReceived{ false };

        std::thread receiverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn == INVALID_SOCKET) return;

                for (int i = 0; i < 3; ++i)
                {
                    auto buf = RecvFullPacket(conn);
                    if (buf.empty()) break;

                    if (!server.ValidatePacket(buf.data(),
                        static_cast<unsigned int>(buf.size()))) break;

                    GroundControlCommunication::Packet pkt(buf.data());
                    received.push_back(
                        std::string(pkt.GetData(), pkt.GetBodyLength()));
                }

                allReceived = (received.size() == MESSAGES.size());
                (void)closesocket(conn);
            });

        WaitForThread();

        SOCKET senderSock = MakeClientSocket(PORT_BIDIRECTIONAL);
        Assert::IsTrue(senderSock != INVALID_SOCKET,
            L"Test 11: Sender must connect");

        for (const auto& msg : MESSAGES)
        {
            auto pktBytes = BuildPacket(606, 0, msg);
            (void)send(senderSock, pktBytes.data(),
                static_cast<int>(pktBytes.size()), 0);
        }

        receiverThread.join();

        (void)closesocket(senderSock);
        (void)closesocket(listenSock);

        Assert::IsTrue(allReceived,
            L"Test 11: All three messages must pass server validation and be received");

        for (size_t i = 0; i < MESSAGES.size(); ++i)
        {
            Assert::AreEqual(MESSAGES[i], received[i],
                L"Test 11: Each message must arrive in the correct order");
        }
    }
};


//// ============================================================
////  TEST CLASS 4 — Telemetry Path Integration
//// ============================================================
//TEST_CLASS(Test_TelemetryPath_Integration)
//{
//    static SOCKET MakeListenSocket(unsigned short port = PORT_DISCONNECTION)
//    {
//        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//        if (s == INVALID_SOCKET) return INVALID_SOCKET;
//
//        int opt = 1;
//        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
//            reinterpret_cast<const char*>(&opt), sizeof(opt));
//
//        sockaddr_in addr{};
//        addr.sin_family = AF_INET;
//        addr.sin_addr.s_addr = INADDR_ANY;
//        addr.sin_port = htons(port);
//
//        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
//        {
//            (void)closesocket(s);
//            return INVALID_SOCKET;
//        }
//
//        (void)listen(s, 2);
//        return s;
//    }
//
//    static SOCKET MakeClientSocket(unsigned short port = PORT_DISCONNECTION)
//    {
//        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//        if (s == INVALID_SOCKET) return INVALID_SOCKET;
//
//        sockaddr_in addr{};
//        addr.sin_family = AF_INET;
//        addr.sin_port = htons(port);
//        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
//
//        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
//        {
//            (void)closesocket(s);
//            return INVALID_SOCKET;
//        }
//        return s;
//    }
//
//    static std::vector<char> RecvFullPacket(SOCKET sock)
//    {
//        char headerBuf[sizeof(GroundControlCommunication::PacketHeader)];
//        if (recv(sock, headerBuf, sizeof(headerBuf), MSG_WAITALL)
//            != sizeof(GroundControlCommunication::PacketHeader))
//            return {};
//
//        GroundControlCommunication::PacketHeader hdr{};
//        (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));
//
//        unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
//        std::vector<char> buf(total);
//        (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));
//
//        recv(sock, buf.data() + sizeof(hdr),
//            static_cast<int>(hdr.Length + sizeof(uint32_t)), MSG_WAITALL);
//
//        return buf;
//    }
//
//public:
//
//    TEST_CLASS_INITIALIZE(ClassSetup)
//    {
//        WSADATA w;
//        (void)WSAStartup(MAKEWORD(2, 2), &w);
//    }
//
//    TEST_CLASS_CLEANUP(ClassTeardown)
//    {
//        (void)WSACleanup();
//    }
//
//    // ----------------------------------------------------------
//    // Test 12: Telemetry packet (MessageType=1) is transmitted,
//    //          passes Server::ValidatePacket, and MessageType
//    //          is correctly preserved on the receiving end.
//    // ----------------------------------------------------------
//    TEST_METHOD(Test12_TelemetryPacket_ValidatedAndIdentified)
//    {
//        SOCKET listenSock = MakeListenSocket();
//        Assert::IsTrue(listenSock != INVALID_SOCKET,
//            L"Test 12: Listening socket must be created");
//
//        const unsigned int TELEMETRY_TYPE = 1;
//        const std::string  TELEMETRY_BODY =
//            "TELEMETRY|ALT=35000,SPD=450,HDG=090,FUEL=72%";
//
//        Networking::Server        server;
//        std::atomic<bool>         received{ false };
//        std::atomic<unsigned int> receivedMsgType{ 0 };
//        std::string               receivedBody;
//
//        std::thread gcThread([&]()
//            {
//                SOCKET conn = accept(listenSock, nullptr, nullptr);
//                if (conn == INVALID_SOCKET) return;
//
//                auto buf = RecvFullPacket(conn);
//                if (!buf.empty() &&
//                    server.ValidatePacket(buf.data(),
//                        static_cast<unsigned int>(buf.size())))
//                {
//                    GroundControlCommunication::Packet pkt(buf.data());
//                    receivedMsgType = pkt.GetHeader().MessageType;
//                    receivedBody = std::string(pkt.GetData(), pkt.GetBodyLength());
//                    received = true;
//                }
//
//                (void)closesocket(conn);
//            });
//
//        WaitForThread();
//
//        SOCKET ifSock = MakeClientSocket();
//        Assert::IsTrue(ifSock != INVALID_SOCKET,
//            L"Test 12: InFlight socket must connect");
//
//        GroundControlCommunication::Packet txPkt;
//        txPkt.SetFlightID(707);
//        txPkt.SetMessageType(TELEMETRY_TYPE);
//        txPkt.SetData(TELEMETRY_BODY.c_str(),
//            static_cast<unsigned int>(TELEMETRY_BODY.size()));
//        unsigned int sz = 0;
//        char* raw = txPkt.SerializeData(sz);
//        (void)send(ifSock, raw, static_cast<int>(sz), 0);
//
//        gcThread.join();
//
//        (void)closesocket(ifSock);
//        (void)closesocket(listenSock);
//
//        Assert::IsTrue(received,
//            L"Test 12: GC must receive and validate the telemetry packet");
//        Assert::AreEqual(TELEMETRY_TYPE, receivedMsgType.load(),
//            L"Test 12: MessageType must be 1 for telemetry");
//        Assert::AreEqual(TELEMETRY_BODY, receivedBody,
//            L"Test 12: Telemetry body must arrive unchanged");
//    }
//
//    // ----------------------------------------------------------
//    // Test 13: Large telemetry payload (~8 KB) is transmitted
//    //          intact and passes Server::ValidatePacket.
//    // ----------------------------------------------------------
//    TEST_METHOD(Test13_LargeTelemetryPayload_TransmittedAndValidated)
//    {
//        SOCKET listenSock = MakeListenSocket();
//        Assert::IsTrue(listenSock != INVALID_SOCKET,
//            L"Test 13: Listening socket must be created");
//
//        std::string largeTelemetry;
//        largeTelemetry.reserve(8192);
//        for (int i = 0; i < 256; ++i)
//        {
//            std::ostringstream oss;
//            oss << "TELEMETRY|ROW=" << i
//                << ",ALT=35000,SPD=450,HDG=090,FUEL=72%;";
//            largeTelemetry += oss.str();
//        }
//
//        Networking::Server server;
//        std::string        receivedBody;
//        std::atomic<bool>  validatedOk{ false };
//
//        std::thread gcThread([&]()
//            {
//                SOCKET conn = accept(listenSock, nullptr, nullptr);
//                if (conn == INVALID_SOCKET) return;
//
//                char headerBuf[sizeof(GroundControlCommunication::PacketHeader)];
//                if (recv(conn, headerBuf, sizeof(headerBuf), MSG_WAITALL)
//                    != sizeof(GroundControlCommunication::PacketHeader))
//                {
//                    (void)closesocket(conn); return;
//                }
//
//                GroundControlCommunication::PacketHeader hdr{};
//                (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));
//
//                unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
//                std::vector<char> buf(total);
//                (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));
//
//                // Stream-receive for large payloads — recv() may return
//                // partial data for buffers above the TCP segment size.
//                unsigned int rem = hdr.Length + sizeof(uint32_t);
//                unsigned int off = sizeof(hdr);
//                while (rem > 0)
//                {
//                    int got = recv(conn, buf.data() + off,
//                        static_cast<int>(rem), 0);
//                    if (got <= 0) break;
//                    rem -= static_cast<unsigned int>(got);
//                    off += static_cast<unsigned int>(got);
//                }
//
//                if (server.ValidatePacket(buf.data(), total))
//                {
//                    GroundControlCommunication::Packet pkt(buf.data());
//                    receivedBody = std::string(pkt.GetData(), pkt.GetBodyLength());
//                    validatedOk = true;
//                }
//
//                (void)closesocket(conn);
//            });
//
//        WaitForThread();
//
//        SOCKET ifSock = MakeClientSocket();
//        Assert::IsTrue(ifSock != INVALID_SOCKET,
//            L"Test 13: InFlight socket must connect");
//
//        GroundControlCommunication::Packet txPkt;
//        txPkt.SetFlightID(808);
//        txPkt.SetMessageType(1);
//        txPkt.SetData(largeTelemetry.c_str(),
//            static_cast<unsigned int>(largeTelemetry.size()));
//        unsigned int sz = 0;
//        char* raw = txPkt.SerializeData(sz);
//        (void)send(ifSock, raw, static_cast<int>(sz), 0);
//
//        gcThread.join();
//
//        (void)closesocket(ifSock);
//        (void)closesocket(listenSock);
//
//        Assert::IsTrue(validatedOk,
//            L"Test 13: Server::ValidatePacket must pass for the large telemetry packet");
//        Assert::AreEqual(largeTelemetry, receivedBody,
//            L"Test 13: Large telemetry body must arrive byte-for-byte identical");
//    }
//};


// ============================================================
//  TEST CLASS 5 — Disconnection Integration
// ============================================================
TEST_CLASS(Test_Disconnection_Integration)
{
    static SOCKET MakeListenSocket(unsigned short port = PORT_DISCONNECTION)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        int opt = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }

        (void)listen(s, 2);
        return s;
    }

    static SOCKET MakeClientSocket(unsigned short port = PORT_DISCONNECTION)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }
        return s;
    }

    static std::vector<char> RecvFullPacket(SOCKET sock)
    {
        char headerBuf[sizeof(GroundControlCommunication::PacketHeader)];
        if (recv(sock, headerBuf, sizeof(headerBuf), MSG_WAITALL)
            != sizeof(GroundControlCommunication::PacketHeader))
            return {};

        GroundControlCommunication::PacketHeader hdr{};
        (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));

        unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
        std::vector<char> buf(total);
        (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));

        recv(sock, buf.data() + sizeof(hdr),
            static_cast<int>(hdr.Length + sizeof(uint32_t)), MSG_WAITALL);

        return buf;
    }

public:

    TEST_CLASS_INITIALIZE(ClassSetup)
    {
        WSADATA w;
        (void)WSAStartup(MAKEWORD(2, 2), &w);
    }

    TEST_CLASS_CLEANUP(ClassTeardown)
    {
        (void)WSACleanup();
    }

    // ----------------------------------------------------------
    // Test 14: Server-side recv() returns 0 (graceful close)
    //          when the client closes its socket cleanly.
    // ----------------------------------------------------------
    TEST_METHOD(Test14_GracefulClientDisconnect_DetectedByServer)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 14: Listening socket must be created");

        std::atomic<bool> disconnectDetected{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn == INVALID_SOCKET) return;

                char buf[64];
                int bytes = recv(conn, buf, sizeof(buf), 0);
                disconnectDetected = (bytes == 0);

                (void)closesocket(conn);
            });

        WaitForThread();

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 14: Client must connect");

        (void)closesocket(clientSock);

        serverThread.join();
        (void)closesocket(listenSock);

        Assert::IsTrue(disconnectDetected,
            L"Test 14: recv() must return 0 upon graceful client disconnect");
    }

    // ----------------------------------------------------------
    // Test 15: After a client disconnects, a new client can
    //          reconnect on the same port and exchange data.
    // ----------------------------------------------------------
    TEST_METHOD(Test15_ClientReconnect_SecondSessionSucceeds)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 15: Listening socket must be created");

        const std::string FIRST_MSG = "Session 1 message";
        const std::string SECOND_MSG = "Session 2 message";

        Networking::Server       server;
        std::vector<std::string> serverReceived;
        std::atomic<int>         sessionCount{ 0 };

        std::thread serverThread([&]()
            {
                for (int s = 0; s < 2; ++s)
                {
                    SOCKET conn = accept(listenSock, nullptr, nullptr);
                    if (conn == INVALID_SOCKET) break;

                    auto buf = RecvFullPacket(conn);
                    if (!buf.empty() &&
                        server.ValidatePacket(buf.data(),
                            static_cast<unsigned int>(buf.size())))
                    {
                        GroundControlCommunication::Packet pkt(buf.data());
                        serverReceived.push_back(
                            std::string(pkt.GetData(), pkt.GetBodyLength()));
                        ++sessionCount;
                    }

                    (void)closesocket(conn);
                }
            });

        WaitForThread();

        // First client
        {
            SOCKET c1 = MakeClientSocket();
            Assert::IsTrue(c1 != INVALID_SOCKET,
                L"Test 15: First client must connect");

            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(1);
            pkt.SetMessageType(0);
            pkt.SetData(FIRST_MSG.c_str(),
                static_cast<unsigned int>(FIRST_MSG.size()));
            unsigned int sz = 0;
            char* raw = pkt.SerializeData(sz);
            (void)send(c1, raw, static_cast<int>(sz), 0);

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            (void)closesocket(c1);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Second client
        {
            SOCKET c2 = MakeClientSocket();
            Assert::IsTrue(c2 != INVALID_SOCKET,
                L"Test 15: Second client must reconnect on the same port");

            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(2);
            pkt.SetMessageType(0);
            pkt.SetData(SECOND_MSG.c_str(),
                static_cast<unsigned int>(SECOND_MSG.size()));
            unsigned int sz = 0;
            char* raw = pkt.SerializeData(sz);
            (void)send(c2, raw, static_cast<int>(sz), 0);

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            (void)closesocket(c2);
        }

        serverThread.join();
        (void)closesocket(listenSock);

        Assert::AreEqual(2, sessionCount.load(),
            L"Test 15: Server must serve two sequential client sessions");
        Assert::AreEqual(static_cast<size_t>(2), serverReceived.size(),
            L"Test 15: Two messages must be received and validated");
        Assert::AreEqual(FIRST_MSG, serverReceived[0],
            L"Test 15: First session message must be correct");
        Assert::AreEqual(SECOND_MSG, serverReceived[1],
            L"Test 15: Second session message must be correct");
    }
};


// ============================================================
//  TEST CLASS 6 — FlightID Tracking Integration
// ============================================================
TEST_CLASS(Test_FlightID_Integration)
{
    static SOCKET MakeListenSocket(unsigned short port = PORT_FLIGHTID)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        int opt = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }

        (void)listen(s, 2);
        return s;
    }

    static SOCKET MakeClientSocket(unsigned short port = PORT_FLIGHTID)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }
        return s;
    }

    static std::vector<char> RecvFullPacket(SOCKET sock)
    {
        char headerBuf[sizeof(GroundControlCommunication::PacketHeader)];
        if (recv(sock, headerBuf, sizeof(headerBuf), MSG_WAITALL)
            != sizeof(GroundControlCommunication::PacketHeader))
            return {};

        GroundControlCommunication::PacketHeader hdr{};
        (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));

        unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
        std::vector<char> buf(total);
        (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));

        recv(sock, buf.data() + sizeof(hdr),
            static_cast<int>(hdr.Length + sizeof(uint32_t)), MSG_WAITALL);

        return buf;
    }

public:

    TEST_CLASS_INITIALIZE(ClassSetup)
    {
        WSADATA w;
        (void)WSAStartup(MAKEWORD(2, 2), &w);
    }

    TEST_CLASS_CLEANUP(ClassTeardown)
    {
        (void)WSACleanup();
    }

    // ----------------------------------------------------------
    // Test 16: FlightID is preserved through the full
    //          serialise -> send -> recv -> deserialise cycle.
    // ----------------------------------------------------------
    TEST_METHOD(Test16_FlightID_PreservedEndToEnd)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 16: Listening socket must be created");

        const unsigned int EXPECTED_ID = 12345;

        Networking::Server        server;
        std::atomic<unsigned int> receivedID{ 0 };
        std::atomic<bool>         validated{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn == INVALID_SOCKET) return;

                auto buf = RecvFullPacket(conn);
                if (!buf.empty() &&
                    server.ValidatePacket(buf.data(),
                        static_cast<unsigned int>(buf.size())))
                {
                    GroundControlCommunication::Packet pkt(buf.data());
                    receivedID = pkt.GetFlightID();
                    validated = true;
                }
                (void)closesocket(conn);
            });

        WaitForThread();

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 16: Client must connect");

        GroundControlCommunication::Packet txPkt;
        txPkt.SetFlightID(EXPECTED_ID);
        txPkt.SetMessageType(0);
        txPkt.SetData("ID check", 8);
        unsigned int sz = 0;
        char* raw = txPkt.SerializeData(sz);
        (void)send(clientSock, raw, static_cast<int>(sz), 0);

        serverThread.join();

        (void)closesocket(clientSock);
        (void)closesocket(listenSock);

        Assert::IsTrue(validated,
            L"Test 16: Server::ValidatePacket must pass");
        Assert::AreEqual(EXPECTED_ID, receivedID.load(),
            L"Test 16: FlightID must survive the full send-receive cycle unchanged");
    }

    // ----------------------------------------------------------
    // Test 17: Three packets from distinct FlightIDs are each
    //          correctly received, validated, and distinguished.
    // ----------------------------------------------------------
    TEST_METHOD(Test17_MultipleFlightIDs_CorrectlyDistinguished)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 17: Listening socket must be created");

        struct FlightRecord { unsigned int id; std::string body; };
        const std::vector<FlightRecord> FLIGHTS = {
            { 111, "Flight 111 reporting" },
            { 222, "Flight 222 reporting" },
            { 333, "Flight 333 reporting" }
        };

        Networking::Server        server;
        std::vector<FlightRecord> received;
        std::atomic<bool>         allIn{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn == INVALID_SOCKET) return;

                for (int i = 0; i < 3; ++i)
                {
                    auto buf = RecvFullPacket(conn);
                    if (buf.empty()) break;
                    if (!server.ValidatePacket(buf.data(),
                        static_cast<unsigned int>(buf.size()))) break;

                    GroundControlCommunication::Packet pkt(buf.data());
                    FlightRecord r;
                    r.id = pkt.GetFlightID();
                    r.body = std::string(pkt.GetData(), pkt.GetBodyLength());
                    received.push_back(r);
                }

                allIn = (received.size() == 3);
                (void)closesocket(conn);
            });

        WaitForThread();

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 17: Client must connect");

        for (const auto& f : FLIGHTS)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(f.id);
            pkt.SetMessageType(0);
            pkt.SetData(f.body.c_str(),
                static_cast<unsigned int>(f.body.size()));
            unsigned int sz = 0;
            char* raw = pkt.SerializeData(sz);
            (void)send(clientSock, raw, static_cast<int>(sz), 0);
        }

        serverThread.join();

        (void)closesocket(clientSock);
        (void)closesocket(listenSock);

        Assert::IsTrue(allIn,
            L"Test 17: All three flight packets must be received and validated");

        for (size_t i = 0; i < FLIGHTS.size(); ++i)
        {
            Assert::AreEqual(FLIGHTS[i].id, received[i].id,
                L"Test 17: FlightID must match the corresponding sent value");
            Assert::AreEqual(FLIGHTS[i].body, received[i].body,
                L"Test 17: Body must match the corresponding sent value");
        }
    }
};


// ============================================================
//  TEST CLASS 7 — Handshake + Data Session (Combined Flow)
// ============================================================
TEST_CLASS(Test_HandshakeThenData_Integration)
{
    static SOCKET MakeListenSocket(unsigned short port = PORT_SESSION)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        int opt = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }

        (void)listen(s, 2);
        return s;
    }

    static SOCKET MakeClientSocket(unsigned short port = PORT_SESSION)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            (void)closesocket(s);
            return INVALID_SOCKET;
        }
        return s;
    }

    static std::vector<char> RecvFullPacket(SOCKET sock)
    {
        char headerBuf[sizeof(GroundControlCommunication::PacketHeader)];
        if (recv(sock, headerBuf, sizeof(headerBuf), MSG_WAITALL)
            != sizeof(GroundControlCommunication::PacketHeader))
            return {};

        GroundControlCommunication::PacketHeader hdr{};
        (void)std::memcpy(&hdr, headerBuf, sizeof(hdr));

        unsigned int total = sizeof(hdr) + hdr.Length + sizeof(uint32_t);
        std::vector<char> buf(total);
        (void)std::memcpy(buf.data(), headerBuf, sizeof(hdr));

        recv(sock, buf.data() + sizeof(hdr),
            static_cast<int>(hdr.Length + sizeof(uint32_t)), MSG_WAITALL);

        return buf;
    }

public:

    TEST_CLASS_INITIALIZE(ClassSetup)
    {
        WSADATA w;
        (void)WSAStartup(MAKEWORD(2, 2), &w);
        srand(static_cast<unsigned int>(time(nullptr)));
    }

    TEST_CLASS_CLEANUP(ClassTeardown)
    {
        (void)WSACleanup();
    }

    // ----------------------------------------------------------
    // Test 18: Post-handshake data packet is exchanged correctly.
    //          Realistic full session: handshake then data.
    // ----------------------------------------------------------
    TEST_METHOD(Test18_HandshakeThenDataPacket_FullSessionSucceeds)
    {
        SOCKET listenSock = MakeListenSocket();
        Assert::IsTrue(listenSock != INVALID_SOCKET,
            L"Test 18: Listening socket must be created");

        const std::string DATA_MSG = "Post-handshake: Ready for flight";

        Networking::Server server;
        server.sharedSecret = TEST_SECRET;

        std::string       serverReceived;
        std::atomic<bool> sessionOk{ false };

        std::thread serverThread([&]()
            {
                SOCKET conn = accept(listenSock, nullptr, nullptr);
                if (conn == INVALID_SOCKET) return;

                if (!server.PerformHandshake(conn, "InFlightClient"))
                {
                    (void)closesocket(conn); return;
                }

                auto buf = RecvFullPacket(conn);
                if (!buf.empty() &&
                    server.ValidatePacket(buf.data(),
                        static_cast<unsigned int>(buf.size())))
                {
                    GroundControlCommunication::Packet pkt(buf.data());
                    serverReceived = std::string(pkt.GetData(), pkt.GetBodyLength());
                    sessionOk = true;
                }

                (void)closesocket(conn);
            });

        WaitForThread();

        InFlightClient::InFlightClient ifClient;
        ifClient.sharedSecret = TEST_SECRET;

        SOCKET clientSock = MakeClientSocket();
        Assert::IsTrue(clientSock != INVALID_SOCKET,
            L"Test 18: Client must connect");

        bool hsOk = ifClient.PerformHandshake(clientSock, "InFlightClient");
        Assert::IsTrue(hsOk,
            L"Test 18: PerformHandshake must succeed before data is sent");

        InFlightCommunication::Packet txPkt;
        txPkt.SetFlightID(9001);
        txPkt.SetMessageType(0);
        txPkt.SetData(DATA_MSG.c_str(),
            static_cast<unsigned int>(DATA_MSG.size()));
        unsigned int sz = 0;
        char* raw = txPkt.SerializeData(sz);
        (void)send(clientSock, raw, static_cast<int>(sz), 0);

        serverThread.join();

        (void)closesocket(clientSock);
        (void)closesocket(listenSock);

        Assert::IsTrue(sessionOk,
            L"Test 18: Full session (handshake + data + validation) must complete");
        Assert::AreEqual(DATA_MSG, serverReceived,
            L"Test 18: Data message sent after handshake must arrive intact");
    }
};