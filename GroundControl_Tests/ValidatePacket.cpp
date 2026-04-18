#include "pch.h"
#include "CppUnitTest.h"

#include "../GroundControlClient/VerificationPacket.h"
#include "../GroundControlClient/Packet.h"
#include "../GroundControlClient/CRC32.h"


#include <cstring>
#include <fstream>
#include <string>
#include <filesystem>
#include <vector>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

//  **** Defining helper functions for testing  ****

/* Building a valid raw packet buffer identical to what
  Packet::SerializeData() produces, so ValidatePacket() tests
  can be self-contained without going through GroundControlClient.*/

static std::vector<char> BuildRawPacket(unsigned int flightID, unsigned int msgType, const std::string& body)
{
    GroundControlCommunication::Packet pkt;
    pkt.SetFlightID(flightID);
    pkt.SetMessageType(msgType);
    pkt.SetTimeStamp(0u);
    pkt.SetData(body.c_str(), static_cast<unsigned int>(body.size()));

    unsigned int totalSize = 0u;
    char* raw = pkt.SerializeData(totalSize);

    // Copy into a vector so the caller owns the memory
    std::vector<char> buf(raw, raw + totalSize);
    return buf;
}


// Since the real method is private, we replicate the logic here for testing purposes (the main logic will be tested through integration testing)
static bool ValidateRawPacket(const char* buffer)
{
    GroundControlCommunication::PacketHeader head{};
    std::memcpy(&head, buffer, sizeof(GroundControlCommunication::PacketHeader));

    unsigned int payloadSize = sizeof(GroundControlCommunication::PacketHeader) + head.Length;
    uint32_t computed = GroundControlChecksum::CRC32::Calculate(buffer, payloadSize);

    uint32_t received = 0u;
    std::memcpy(&received, buffer + payloadSize, sizeof(uint32_t));

    return (computed == received);
}


namespace GroundControl_Tests
{
    TEST_CLASS(ValidatePacket)
    {
    public:

        // A freshly serialized packet must pass validation
        TEST_METHOD(ValidPacket_PassesValidation)
        {
            auto buf = BuildRawPacket(1u, 0u, "HelloValidation");
            Assert::IsTrue(ValidateRawPacket(buf.data()));
        }

        // Flipping any byte in the body must cause validation to fail
        TEST_METHOD(CorruptedBody_FailsValidation)
        {
            auto buf = BuildRawPacket(2u, 0u, "GoodData");
            // Corrupt a byte inside the body (after the header)
            buf[sizeof(GroundControlCommunication::PacketHeader) + 2] ^= 0xFF;
            Assert::IsFalse(ValidateRawPacket(buf.data()));
        }

        // Flipping a header byte must cause validation to fail
        TEST_METHOD(CorruptedHeader_FailsValidation)
        {
            auto buf = BuildRawPacket(3u, 0u, "GoodHeader");
            buf[1] ^= 0x01; // flip a bit in the header
            Assert::IsFalse(ValidateRawPacket(buf.data()));
        }

        // Corrupting the appended CRC itself must cause validation to fail
        TEST_METHOD(CorruptedCRC_FailsValidation)
        {
            auto buf = BuildRawPacket(4u, 0u, "CRCData");
            // The CRC is the last 4 bytes
            buf[buf.size() - 1] ^= 0xFF;
            Assert::IsFalse(ValidateRawPacket(buf.data()));
        }

        // Single-byte body must still validate correctly
        TEST_METHOD(SingleByteBody_ValidatesCorrectly)
        {
            auto buf = BuildRawPacket(5u, 0u, "X");
            Assert::IsTrue(ValidateRawPacket(buf.data()));
        }

        // Empty body edge case
        // Note: SetData ignores size=0, so we verify the behaviour is consistent
        TEST_METHOD(MultipleValidPackets_AllPass)
        {
            for (unsigned int i = 0u; i < 10u; i++) {
                auto buf = BuildRawPacket(i, 1u, "Packet_" + std::to_string(i));
                Assert::IsTrue(ValidateRawPacket(buf.data()));
            }

        };
    };
}