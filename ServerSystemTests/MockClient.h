#pragma once

// MockClient.h
// A lightweight Winsock TCP client used exclusively by system tests.
// It performs the real 4-packet handshake and can send/receive real
// serialized Packet buffers — no UI, no loops, just bare mechanics.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <cstdint>
#include <cstring>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

// Must match Server's VerificationPacket.h
#include "../Server/VerificationPacket.h"
#include "../Server/CRC32.h"
#include "../InFlightClient/Packet.h"

// Port used exclusively by system tests — avoids conflicts with
// a real server running on the default port (54000).
static const int SYSTEM_TEST_PORT = 54564;

class MockClient
{
public:
    explicit MockClient(const std::string& sharedSecret)
        : m_socket(INVALID_SOCKET)
        , m_sharedSecret(sharedSecret)
        , m_connected(false)
    {
    }

    ~MockClient()
    {
        Disconnect();
    }

    // Connects to the test server on localhost:SYSTEM_TEST_PORT.
    // Returns true on success.
    bool Connect()
    {
        m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_socket == INVALID_SOCKET) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<u_short>(SYSTEM_TEST_PORT));

        static const char ipAddress[] = "127.0.0.1";
        (void)inet_pton(AF_INET, &ipAddress[0], &addr.sin_addr);

        if (connect(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
            return false;
        }

        m_connected = true;
        return true;
    }

    // Performs the 4-packet mutual verification handshake with the server.
    // Returns true if all 4 steps succeed.
    bool PerformHandshake()
    {
        // ---- Step 1: Send CHALLENGE ----
        Handshake::ChallengePacket clientChallenge{};
        clientChallenge.Type = static_cast<uint32_t>(Handshake::VerificationPacketType::CHALLENGE);
        clientChallenge.Random = 0xABCD1234U; // Fixed value for deterministic tests
        clientChallenge.CRC32 = Checksum::CRC32::Calculate(
            reinterpret_cast<const char*>(&clientChallenge),
            sizeof(uint32_t) + sizeof(uint32_t));

        if (send(m_socket, reinterpret_cast<const char*>(&clientChallenge),
            sizeof(Handshake::ChallengePacket), 0) != sizeof(Handshake::ChallengePacket))
            return false;

        // ---- Step 2: Receive server RESPONSE, validate ----
        Handshake::ResponsePacket serverResponse{};
        if (recv(m_socket, reinterpret_cast<char*>(&serverResponse),
            sizeof(Handshake::ResponsePacket), MSG_WAITALL) != sizeof(Handshake::ResponsePacket))
            return false;

        if (static_cast<Handshake::VerificationPacketType>(serverResponse.Type) != Handshake::VerificationPacketType::RESPONSE)
            return false;

        uint32_t expectedSig = ComputeSignature(clientChallenge.Random);
        if (serverResponse.Signature != expectedSig) return false;

        // ---- Step 3: Receive server CHALLENGE ----
        Handshake::ChallengePacket serverChallenge{};
        if (recv(m_socket, reinterpret_cast<char*>(&serverChallenge),
            sizeof(Handshake::ChallengePacket), MSG_WAITALL) != sizeof(Handshake::ChallengePacket))
            return false;

        if (static_cast<Handshake::VerificationPacketType>(serverChallenge.Type) != Handshake::VerificationPacketType::CHALLENGE)
            return false;

        // ---- Step 4: Send RESPONSE ----
        Handshake::ResponsePacket clientResponse{};
        clientResponse.Type = static_cast<uint32_t>(Handshake::VerificationPacketType::RESPONSE);
        clientResponse.Signature = ComputeSignature(serverChallenge.Random);
        clientResponse.CRC32 = Checksum::CRC32::Calculate(
            reinterpret_cast<const char*>(&clientResponse),
            sizeof(uint32_t) + sizeof(uint32_t));
        
        if (send(m_socket, reinterpret_cast<const char*>(&clientResponse),
            sizeof(Handshake::ResponsePacket), 0) != sizeof(Handshake::ResponsePacket))
            return false;

        return true;
    }

    // Sends a serialized Packet with the given body over the socket.
    // Returns true if all bytes were sent.
    bool SendPacket(unsigned int flightID,
        unsigned int messageType,
        const char* body,
        unsigned int bodyLen)
    {
        Communication::Packet pkt;
        pkt.SetFlightID(flightID);
        pkt.SetMessageType(messageType);
        pkt.SetTimeStamp(1U);
        pkt.SetData(body, bodyLen);

        unsigned int totalSize = 0U;
        char* buf = pkt.SerializeData(totalSize);

        return send(m_socket, buf, static_cast<int>(totalSize), 0)
            == static_cast<int>(totalSize);
    }

    // Sends a raw pre-built buffer — used to inject malformed packets.
    bool SendRaw(const char* buf, unsigned int size)
    {
        return send(m_socket, buf, static_cast<int>(size), 0)
            == static_cast<int>(size);
    }

    // Receives one full packet using two-phase recv (header then body).
    // Stores the body in outBody. Returns true on success.
    bool ReceivePacket(std::string& outBody, unsigned int timeoutMs = 2000U)
    {
        // Apply receive timeout so tests don't hang forever.
        DWORD timeout = static_cast<DWORD>(timeoutMs);
        setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        // Phase 1: header
        char headerBuf[sizeof(Communication::PacketHeader)];
        std::memset(headerBuf, 0, sizeof(Communication::PacketHeader));

        int r = recv(m_socket, headerBuf, sizeof(headerBuf), MSG_WAITALL);
        if (r <= 0) return false;

        Communication::PacketHeader hdr{};
        std::memcpy(&hdr, headerBuf, sizeof(Communication::PacketHeader));

        // Phase 2: body + CRC tail
        unsigned int remaining = hdr.Length + sizeof(uint32_t);
        char* bodyBuf = new char[remaining];
        std::memset(bodyBuf, 0, remaining);

        r = recv(m_socket, bodyBuf, static_cast<int>(remaining), MSG_WAITALL);
        if (r <= 0)
        {
            delete[] bodyBuf;
            return false;
        }

        outBody = std::string(bodyBuf, hdr.Length);
        delete[] bodyBuf;
        return true;
    }

    void Disconnect()
    {
        if (m_socket != INVALID_SOCKET)
        {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
        m_connected = false;
    }

    bool IsConnected() const { return m_connected; }

private:
    SOCKET      m_socket;
    std::string m_sharedSecret;
    bool        m_connected;

    uint32_t ComputeSignature(uint32_t randomNumber) const
    {
        std::string payload = m_sharedSecret;
        payload.append(reinterpret_cast<const char*>(&randomNumber), sizeof(uint32_t));
        return Checksum::CRC32::Calculate(payload.c_str(),
            static_cast<unsigned int>(payload.size()));
    }
};