#include "pch.h"
#include "CppUnitTest.h"

#include "../Server/PacketHeader.h"
#include "../Server/VerificationPacket.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ServerTests {
    TEST_CLASS(StructureTests) {
    public:

        // --------------------------------------------------------
        // PacketHeader layout
        //
        // #pragma pack(push, 1) must be in effect on Packet.h.
        // Without it the compiler inserts 3 padding bytes after
        // TimeStamp (1 byte) to align Length (4 bytes), making
        // sizeof(PacketHeader) = 16 instead of 13.
        // The server reads exactly sizeof(PacketHeader) bytes off
        // the wire — if this is wrong, every packet is misread.
        // --------------------------------------------------------

        TEST_METHOD(PacketHeader_SizeIs16Bytes) {
            Assert::AreEqual(static_cast<size_t>(16U), sizeof(PacketHeader),
                L"PacketHeader must be exactly 16 bytes with #pragma pack(1). "
                L"If this fails, compiler padding is breaking the wire format.");
        };

        TEST_METHOD(PacketHeader_FlightID_Offset0) {
            // FlightID must start at byte 0 of the struct.
            PacketHeader h{};

            size_t offset = reinterpret_cast<size_t>(&h.FlightID) - reinterpret_cast<size_t>(&h);

            Assert::AreEqual(static_cast<size_t>(0U), offset, L"FlightID must be at offset 0 in PacketHeader.");
        };

        TEST_METHOD(PacketHeader_MessageType_Offset4) {
            PacketHeader h{};

            size_t offset = reinterpret_cast<size_t>(&h.MessageType) - reinterpret_cast<size_t>(&h);

            Assert::AreEqual(static_cast<size_t>(4U), offset, L"MessageType must be at offset 4 in PacketHeader.");
        };

        TEST_METHOD(PacketHeader_TimeStamp_Offset12) {
            PacketHeader h{};

            size_t offset = reinterpret_cast<size_t>(&h.TimeStamp) - reinterpret_cast<size_t>(&h);

            Assert::AreEqual(static_cast<size_t>(12U), offset, L"TimeStamp must be at offset 8 in PacketHeader.");
        };

        TEST_METHOD(PacketHeader_Length_Offset8) {
            PacketHeader h{};

            size_t offset = reinterpret_cast<size_t>(&h.Length) - reinterpret_cast<size_t>(&h);

            Assert::AreEqual(static_cast<size_t>(8U), offset, L"Length must be at offset 9 in PacketHeader (no padding after TimeStamp).");
        };

        // --------------------------------------------------------
        // VerificationPacket sizes
        //
        // Both ChallengePacket and ResponsePacket must be exactly
        // 12 bytes: Type (4) + payload (4) + CRC32 (4).
        // The handshake recv() calls use sizeof() — if these are
        // wrong, the handshake reads garbage bytes.
        // --------------------------------------------------------

        TEST_METHOD(ChallengePacket_SizeIs12Bytes) {
            Assert::AreEqual(static_cast<size_t>(12U), sizeof(ChallengePacket), L"ChallengePacket must be exactly 12 bytes.");
        };

        TEST_METHOD(ResponsePacket_SizeIs12Bytes) {
            Assert::AreEqual(static_cast<size_t>(12U), sizeof(ResponsePacket), L"ResponsePacket must be exactly 12 bytes.");
        };

        TEST_METHOD(ChallengePacket_Type_Offset0) {
            ChallengePacket p{};

            size_t offset = reinterpret_cast<size_t>(&p.Type) - reinterpret_cast<size_t>(&p);

            Assert::AreEqual(static_cast<size_t>(0U), offset, L"ChallengePacket.Type must be at offset 0.");
        };

        TEST_METHOD(ChallengePacket_CRC32_Offset8) {
            ChallengePacket p{};

            size_t offset = reinterpret_cast<size_t>(&p.CRC32) - reinterpret_cast<size_t>(&p);

            Assert::AreEqual(static_cast<size_t>(8U), offset, L"ChallengePacket.CRC32 must be at offset 8 (last 4 bytes).");
        };

        TEST_METHOD(ResponsePacket_CRC32_Offset8) {
            ResponsePacket p{};

            size_t offset = reinterpret_cast<size_t>(&p.CRC32) - reinterpret_cast<size_t>(&p);

            Assert::AreEqual(static_cast<size_t>(8U), offset, L"ResponsePacket.CRC32 must be at offset 8 (last 4 bytes).");
        };
    };
};