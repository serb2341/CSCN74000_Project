#include "pch.h"
#include "CppUnitTest.h"

#include "../GroundControlClient/VerificationPacket.h"
#include "../GroundControlClient/CRC32.h"
#include "../GroundControlClient/Packet.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace GroundControl_Tests {
    TEST_CLASS(PacketTests) {
public:

    // ChallengePacket must be exactly 12 bytes (3 × uint32_t packed)
    TEST_METHOD(GC_VerifyPkt_TEST_01_ChallengePacket_IsTwelveBytes)
    {
        Assert::AreEqual(static_cast<size_t>(12u), sizeof(VerificationPacket::ChallengePacket));
    }

    // ResponsePacket must be exactly 12 bytes (3 × uint32_t packed)
    TEST_METHOD(GC_VerifyPkt_TEST_02_ResponsePacket_IsTwelveBytes)
    {
        Assert::AreEqual(static_cast<size_t>(12u), sizeof(VerificationPacket::ResponsePacket));
    }

    // CHALLENGE enum value
    TEST_METHOD(GC_VerifyPkt_TEST_03_ChallengePacketType_CorrectValue)
    {
        Assert::AreEqual(static_cast<uint32_t>(1u),
            static_cast<uint32_t>(VerificationPacket::VerificationPacketType::CHALLENGE));
    }

    // RESPONSE enum value
    TEST_METHOD(GC_VerifyPkt_TEST_04_ResponsePacketType_CorrectValue)
    {
        Assert::AreEqual(static_cast<uint32_t>(2u),
            static_cast<uint32_t>(VerificationPacket::VerificationPacketType::RESPONSE));
    }

    // ChallengePacket fields are at expected offsets (Type at 0, Random at 4, CRC32 at 8)
    TEST_METHOD(GC_VerifyPkt_TEST_05_ChallengePacket_FieldOffsets_AreCorrect)
    {
        VerificationPacket::ChallengePacket pkt{};
        pkt.Type = 0xAABBCCDDU;
        pkt.Random = 0x11223344U;
        pkt.CRC32 = 0xDEADBEEFU;

        const char* raw = reinterpret_cast<const char*>(&pkt);

        uint32_t typeVal, randomVal, crcVal;
        std::memcpy(&typeVal, raw + 0, 4);
        std::memcpy(&randomVal, raw + 4, 4);
        std::memcpy(&crcVal, raw + 8, 4);

        Assert::AreEqual(0xAABBCCDDU, typeVal);
        Assert::AreEqual(0x11223344U, randomVal);
        Assert::AreEqual(0xDEADBEEFU, crcVal);
    }

    // ResponsePacket fields are at expected offsets
    TEST_METHOD(GC_VerifyPkt_TEST_06_ResponsePacket_FieldOffsets_AreCorrect)
    {
        VerificationPacket::ResponsePacket pkt{};
        pkt.Type = 0x00000002U;
        pkt.Signature = 0xCAFEBABEU;
        pkt.CRC32 = 0x12345678U;

        const char* raw = reinterpret_cast<const char*>(&pkt);

        uint32_t typeVal, sigVal, crcVal;
        std::memcpy(&typeVal, raw + 0, 4);
        std::memcpy(&sigVal, raw + 4, 4);
        std::memcpy(&crcVal, raw + 8, 4);

        Assert::AreEqual(0x00000002U, typeVal);
        Assert::AreEqual(0xCAFEBABEU, sigVal);
        Assert::AreEqual(0x12345678U, crcVal);
    }
    };

    // CRC-32 over a challenge packet (Type + Random) must be stable
    TEST_CLASS(ChallengePacketCRCConsistencyTests)
    {
    public:
        TEST_METHOD(GC_VerifyPkt_TEST_07_ChallengeCRC_ComputedTwice_Matches)
        {
            VerificationPacket::ChallengePacket pkt{};
            pkt.Type = static_cast<uint32_t>(VerificationPacket::VerificationPacketType::CHALLENGE);
            pkt.Random = 0xABCD1234U;

            uint32_t crc1 = Checksum::CRC32::Calculate(
                reinterpret_cast<const char*>(&pkt),
                sizeof(uint32_t) + sizeof(uint32_t));

            uint32_t crc2 = Checksum::CRC32::Calculate(
                reinterpret_cast<const char*>(&pkt),
                sizeof(uint32_t) + sizeof(uint32_t));

            Assert::AreEqual(crc1, crc2);
        }

        TEST_METHOD(GC_VerifyPkt_TEST_08_ResponseCRC_ChangesWhenSignatureChanges)
        {
            VerificationPacket::ResponsePacket pkt1{};
            pkt1.Type = static_cast<uint32_t>(VerificationPacket::VerificationPacketType::RESPONSE);
            pkt1.Signature = 0x11111111U;

            VerificationPacket::ResponsePacket pkt2{};
            pkt2.Type = static_cast<uint32_t>(VerificationPacket::VerificationPacketType::RESPONSE);
            pkt2.Signature = 0x22222222U;

            uint32_t crc1 = Checksum::CRC32::Calculate(
                reinterpret_cast<const char*>(&pkt1), 8u);
            uint32_t crc2 = Checksum::CRC32::Calculate(
                reinterpret_cast<const char*>(&pkt2), 8u);

            Assert::AreNotEqual(crc1, crc2);
        }
    };

};





