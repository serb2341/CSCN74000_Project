#include "pch.h"
#include "CppUnitTest.h"

#include "../Server/PacketHeader.h"
#include "../Server/CRC32.h"
#include "../Server/Server.h"
#include "../Server/VerificationPacket.h"

#include <cstring>
#include <cstdint>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ServerTests
{
    // Helper — builds a valid serialized packet buffer and returns it.
    // Caller is responsible for delete[].
    void BuildValidPacket(char** buf, const char* body, unsigned int bodyLen, unsigned int& outTotalSize) {
        outTotalSize = sizeof(PacketHeader) + bodyLen + sizeof(uint32_t);

        *buf = new char[outTotalSize];

        (void)std::memset(*buf, 0, outTotalSize);

        // Fill header
        PacketHeader hdr{};
        hdr.FlightID = 42U;
        hdr.MessageType = 1U;
        hdr.Length = bodyLen;
        hdr.TimeStamp = 7U;

        (void)std::memcpy(*buf, &hdr, sizeof(PacketHeader));

        // Fill body
        if (body != nullptr && bodyLen > 0U) {
            std::memcpy(*buf + sizeof(PacketHeader), body, bodyLen);
        };

        // Compute CRC-32 over header + body, append as tail
        uint32_t crc = Checksum::CRC32::Calculate(*buf, sizeof(PacketHeader) + bodyLen);
        std::memcpy(*buf + sizeof(PacketHeader) + bodyLen, &crc, sizeof(uint32_t));
    };

    TEST_CLASS(ValidatePacketTests) {
    public:

        // --------------------------------------------------------
        // Valid packets
        // --------------------------------------------------------

        TEST_METHOD(ValidPacket_WithBody_ReturnsTrue) {
            Server server;

            const char body[] = "Hello GC";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, static_cast<unsigned int>(strlen(body)), totalSize);

            Assert::IsNotNull(buf);

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsTrue(result, L"A correctly formed packet with valid CRC-32 must pass validation.");
        };

        TEST_METHOD(ValidPacket_EmptyBody_ReturnsTrue) {
            Server server;

            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, nullptr, 0U, totalSize);

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsTrue(result, L"A packet with zero-length body and valid CRC-32 must pass validation.");
        };

        TEST_METHOD(ValidPacket_LargeBody_ReturnsTrue) {
            Server server;

            const unsigned int bodyLen = 1024U;

            char* body = new char[bodyLen];

            for (unsigned int i = 0U; i < bodyLen; ++i) {
                body[i] = static_cast<char>(i % 128);
            };

            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, bodyLen, totalSize);

            delete[] body;
            body = nullptr;

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsTrue(result, L"A large packet with valid CRC-32 must pass validation.");
        };

        // --------------------------------------------------------
        // Structural failures
        // --------------------------------------------------------

        TEST_METHOD(TooSmall_BelowMinimumSize_ReturnsFalse) {
            Server server;

            // Anything smaller than sizeof(PacketHeader) + sizeof(CRC) is invalid.
            char buf[4] = { 0x01, 0x02, 0x03, 0x04 };

            bool result = server.ValidatePacket(buf, 4U);

            Assert::IsFalse(result, L"A buffer smaller than the minimum packet size must fail validation.");
        };

        TEST_METHOD(StructuralMismatch_LengthFieldTooLarge_ReturnsFalse) {
            Server server;

            // Build a packet where hdr.Length claims more bytes than we actually have.
            const char body[] = "short";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, sizeof(body), totalSize);

            // Inflate the Length field inside the buffer to lie about body size.
            PacketHeader hdr{};
            (void)std::memcpy(&hdr, buf, sizeof(PacketHeader));

            hdr.Length = 9999U;   // way more than we have
            (void)std::memcpy(buf, &hdr, sizeof(PacketHeader));

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsFalse(result, L"A packet where declared Length exceeds actual buffer size must fail validation.");
        };

        TEST_METHOD(StructuralMismatch_TotalSizeTooSmall_ReturnsFalse) {
            Server server;

            const char body[] = "test body";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, sizeof(body), totalSize);

            // Pass a totalSize that is 1 byte short of what hdr.Length declares.
            bool result = server.ValidatePacket(buf, totalSize - 1U);

            delete[] buf;
            buf = nullptr;

            Assert::IsFalse(result, L"Passing a totalSize smaller than the packet declares must fail validation.");
        };

         /*--------------------------------------------------------
         CRC-32 integrity failures
         --------------------------------------------------------*/

        TEST_METHOD(CorruptedBody_ReturnsFalse) {
            Server server;

            const char body[] = "Original data";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, sizeof(body), totalSize);

            // Flip a byte in the body — CRC should no longer match.
            buf[sizeof(PacketHeader) + 4] ^= 0xFF;

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsFalse(result, L"A packet with a corrupted body byte must fail CRC-32 validation.");
        };

        TEST_METHOD(CorruptedHeader_ReturnsFalse) {
            Server server;

            const char body[] = "Test";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, sizeof(body), totalSize);

            // Corrupt the FlightID in the header.
            buf[0] ^= 0x01;

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsFalse(result, L"A packet with a corrupted header byte must fail CRC-32 validation.");
        };

        TEST_METHOD(CorruptedCRCTail_ReturnsFalse) {
            Server server;

            const char body[] = "Integrity";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, sizeof(body), totalSize);

            // Corrupt the CRC tail directly.
            unsigned int crcOffset = sizeof(PacketHeader) + sizeof(body);
            buf[crcOffset] ^= 0xFF;

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsFalse(result, L"A packet with a corrupted CRC tail must fail validation.");
        };

        TEST_METHOD(ZeroCRC_WhenNonZeroExpected_ReturnsFalse) {
            Server server;

            const char body[] = "NonZeroCRC";
            unsigned int totalSize = 0U;

            char* buf = nullptr;

            (void)BuildValidPacket(&buf, body, sizeof(body), totalSize);

            // Overwrite CRC tail with all zeros.
            unsigned int crcOffset = sizeof(PacketHeader) + 10U;
            (void)std::memset(buf + crcOffset, 0, sizeof(uint32_t));

            bool result = server.ValidatePacket(buf, totalSize);

            delete[] buf;
            buf = nullptr;

            Assert::IsFalse(result, L"A packet with a zeroed-out CRC tail must fail validation.");
        };
    };
};