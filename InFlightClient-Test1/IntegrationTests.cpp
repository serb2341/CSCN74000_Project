#include "pch.h"
#include "gtest/gtest.h"
#include "..\InFlightClient\InFlightClient.h"
#include "..\InFlightClient\Packet.h"
#include <fstream>
#include <cstdio>


namespace InFlightClientTests
{
    // ------------------------------------------------------
    // Integration Test Class
    // ------------------------------------------------------
    class IntegrationTests : public ::testing::Test {
    protected:
        Client::InFlightClient client;

        void TearDown() override {
            std::remove("test_logger.txt");
            std::remove("integration_log.txt");
            std::remove("integration_config.txt");
            std::remove("pipeline_log.txt");
        }
    };

    // Test Packet Serialize to Deserialize
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_001_Packet_RoundTrip_Serialize_Validate_Deserialize)
    {
        // Arrange
        Client::InFlightClient client;
        Communication::Packet original;

        original.SetFlightID(42);
        original.SetMessageType(1);
        original.SetTimeStamp(999999);
        original.SetData("INTEGRATION_TEST", 16);

        unsigned int size = 0;

        // Act
        char* buffer = original.SerializeData(size);
        bool valid = client.ValidatePacket(buffer, size);
        Communication::Packet reconstructed(buffer);

        // Assert
        EXPECT_TRUE(valid);
        EXPECT_EQ(reconstructed.GetBodyLength(), original.GetBodyLength());
        EXPECT_EQ(
            std::memcmp(reconstructed.GetData(), original.GetData(), original.GetBodyLength()),
            0
        );
    }

    // Test CRC Integrity Through Serialization
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_002_Packet_CRC_Integrity_IsPreserved_Across_Serialize)
    {
        // Arrange
        Communication::Packet pkt;
        pkt.SetFlightID(7);
        pkt.SetMessageType(2);
        pkt.SetTimeStamp(111111);
        pkt.SetData("CRC_TEST", 8);

        unsigned int size = 0;

        // Act
        char* buffer = pkt.SerializeData(size);

        uint32_t extractedCRC = 0;
        std::memcpy(&extractedCRC,
            buffer + sizeof(Communication::PacketHeader) + pkt.GetBodyLength(),
            sizeof(uint32_t));

        Communication::Packet temp(buffer);
        uint32_t computedCRC = temp.CalculateCRC();

        // Assert
        EXPECT_EQ(extractedCRC, computedCRC);
    }

    // Test ValidatePacket with Valid Packet
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_003_ValidatePacket_ValidPacket_ReturnsTrue)
    {
        // Arrange
        Communication::Packet pkt;
        pkt.SetFlightID(101);
        pkt.SetMessageType(1);
        pkt.SetTimeStamp(123456);
        pkt.SetData("HELLO", 5);

        unsigned int size = 0;
        char* buffer = pkt.SerializeData(size);

        // Act
        bool result = client.ValidatePacket(buffer, size);

        // Assert
        EXPECT_TRUE(result);
    }

    // Test ValidatePacket with Incorrect Length
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_004_ValidatePacket_BadLength_ReturnsFalse)
    {
        // Arrange
        Communication::Packet pkt;
        pkt.SetFlightID(101);
        pkt.SetMessageType(1);
        pkt.SetTimeStamp(123456);
        pkt.SetData("HELLO", 5);

        unsigned int size = 0;
        char* buffer = pkt.SerializeData(size);

        // Act
        bool result = client.ValidatePacket(buffer, size - 1);

        // Assert
        EXPECT_FALSE(result);
    }

    // Test ValidatePacket with Bad CRC
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_005_ValidatePacket_BadCRC_ReturnsFalse)
    {
        // Arrange
        Communication::Packet pkt;
        pkt.SetFlightID(101);
        pkt.SetMessageType(1);
        pkt.SetTimeStamp(123456);
        pkt.SetData("HELLO", 5);

        unsigned int size = 0;
        char* buffer = pkt.SerializeData(size);
        buffer[5] ^= 0xFF;

        // Act
        bool result = client.ValidatePacket(buffer, size);

        // Assert
        EXPECT_FALSE(result);
    }

    // Test Packet Sent Message Is Logged Correctly
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_006_Packet_SentMessage_IsLoggedCorrectly)
    {
        // Arrange
        const std::string filename = "integration_log.txt";
        std::remove(filename.c_str());

        Logging::Logger logger(filename);
        Communication::Packet pkt;
        pkt.SetData("LOG_THIS_MESSAGE", 16);

        unsigned int size = 0;
        char* buffer = pkt.SerializeData(size);

        // Act
        logger.Log(pkt.GetData(), pkt.GetBodyLength());

        std::ifstream file(filename);
        ASSERT_TRUE(file.is_open());

        std::string content;
        std::getline(file, content);

        // Assert
        EXPECT_NE(content.find("LOG_THIS_MESSAGE"), std::string::npos);
        EXPECT_NE(content.find('['), std::string::npos);

        file.close();
    }

    // Test LoadConfig and ComputeSignature Together
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_007_Client_LoadConfig_And_ComputeSignature_WorkTogether)
    {
        // Arrange
        Client::InFlightClient client;

        std::ofstream file("integration_config.txt");
        file << "SECRET=integrationkey";
        file.close();

        uint32_t random = 55555;

        // Act
        ASSERT_TRUE(client.LoadConfig("integration_config.txt"));
        uint32_t sig1 = client.ComputeSignature(random);
        uint32_t sig2 = client.ComputeSignature(random);

        // Assert
        EXPECT_EQ(sig1, sig2);
    }

    // Test Full Pipeline Validate and Log
    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_008_FullPipeline_Packet_IsValidated_And_Logged)
    {
        // Arrange
        Client::InFlightClient client;
        const std::string logFile = "pipeline_log.txt";

        Logging::Logger logger(logFile);
        Communication::Packet pkt;
        pkt.SetData("PIPELINE_TEST", 13);

        unsigned int size = 0;
        char* buffer = pkt.SerializeData(size);

        // Act
        bool valid = client.ValidatePacket(buffer, size);
        logger.Log(pkt.GetData(), pkt.GetBodyLength());

        std::ifstream file(logFile);
        std::string line;
        std::getline(file, line);

        // Assert
        ASSERT_TRUE(valid);
        EXPECT_NE(line.find("PIPELINE_TEST"), std::string::npos);
    }

    // ======================================================
    // Packet Tests
    // ======================================================

    TEST_F(IntegrationTests, FLIGHT_CLT_INT_TEST_009_SerializeData_ReturnsValidBuffer)
    {
        // Arrange
        Communication::Packet pkt;
        const char input[] = "TESTDATA";
        unsigned int size = sizeof(input) - 1;

        pkt.SetData(input, size);

        unsigned int totalSize = 0;

        // Act
        char* buffer = pkt.SerializeData(totalSize);

        Communication::PacketHeader header{};
        std::memcpy(&header, buffer, sizeof(Communication::PacketHeader));

        // Assert
        ASSERT_NE(buffer, nullptr);
        EXPECT_GT(totalSize, sizeof(Communication::PacketHeader));
        EXPECT_EQ(header.Length, size);
    }
}