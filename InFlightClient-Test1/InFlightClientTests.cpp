#include "pch.h"

#include "gtest/gtest.h"
#include "..\InFlightClient\InFlightClient.h"
#include "..\InFlightClient\CRC32.h"

#include <fstream>
#include <cstdio>

namespace InFlightClientTests
{
    // ------------------------------------------------------
    // InFlightClient Test Class
    // ------------------------------------------------------
    class InFlightClientTest : public ::testing::Test {
    protected:
        Client::InFlightClient client;

        // Removes all of the created files at end of testing
        void TearDown() override {
            std::remove("config_test.txt");
            std::remove("config_bad.txt");
        }
    };

    // ======================================================
    // Tests for ComputeSignature
    // ======================================================

    //Test ComputeSignature with empty secret
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_001_EmptySecretHandlesGracefully)
    {
        // Arrange
        Client::InFlightClient client;
        uint32_t value = 12345;

        // Act / Assert
        EXPECT_NO_THROW(client.ComputeSignature(value));
    }

    //Tests ComputeSignature function with Same CRCs
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_002_ComputeSignature_ReturnsExpectedCRC_ReturnsEQ)
    {
        // Arrange
        std::ofstream file("config_test.txt");
        file << "SECRET=testkey123";
        file.close();

        client.LoadConfig("config_test.txt");

        uint32_t randomValue = 12345;

        std::string payload = "testkey123";
        payload.append(reinterpret_cast<const char*>(&randomValue), sizeof(uint32_t));

        uint32_t expected = Checksum::CRC32::Calculate(
            payload.c_str(),
            static_cast<unsigned int>(payload.size())
        );

        // Act
        uint32_t result = client.ComputeSignature(randomValue);

        // Assert
        EXPECT_EQ(result, expected);
    }

    //Tests ComputeSignature function with Different CRCs
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_003_ComputeSignature_DifferentInputsProduceDifferentResults_ReturnsNE)
    {
        // Arrange
        std::ofstream file("config_test.txt");
        file << "SECRET=testkey123";
        file.close();

        client.LoadConfig("config_test.txt");

        // Act
        uint32_t sig1 = client.ComputeSignature(1);
        uint32_t sig2 = client.ComputeSignature(2);

        // Assert
        EXPECT_NE(sig1, sig2);
    }

    // ======================================================
    // Tests for ValidatePacket
    // ======================================================

    //Test ValidatePacket with Small Buffer
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_004_ValidatePacket_BufferSmall_ReturnsFalse)
    {
        // Arrange
        char smallBuffer[2] = { 0 };

        // Act
        bool result = client.ValidatePacket(smallBuffer, 2);

        // Assert
        EXPECT_FALSE(result);
    }

    //Test ValidatePacket on null buffer
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_005_NullBuffer_ReturnsFalse)
    {
        // Arrange
        Client::InFlightClient client;

        // Act
        bool result = client.ValidatePacket(nullptr, 10);

        // Assert
        EXPECT_FALSE(result);
    }

    // ======================================================
    // CloseSocket Tests
    // ======================================================

    //Test CloseSocket on Invalid Socket
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_006_CloseSocket_InvalidSocket_DoesNothing_ReturnsEQ)
    {
        // Arrange
        SOCKET sock = INVALID_SOCKET;

        // Act
        client.CloseSocket(&sock);

        // Assert
        EXPECT_EQ(sock, INVALID_SOCKET);
    }

    // =====================================================
    // Test InitializeWinsock
    // =====================================================

    //Test InitializeWinsock successful
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_007_InitializeWinsock_Success)
    {
        // Arrange
        Client::InFlightClient client;

        // Act
        bool result = client.InitializeWinsock();

        // Assert
        EXPECT_TRUE(result);
    }

    // =====================================================
    // Test CreateSocket
    // =====================================================

    //Test CreateSocket does not throw error
    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_008_CreateSocket_ReturnsBool)
    {
        // Arrange
        Client::InFlightClient client;

        // Act / Assert
        EXPECT_NO_THROW(client.CreateSocket());
    }

    // ======================================================
    // LoadConfig Tests
    // ======================================================

    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_009_LoadConfig_ValidFile_ReturnsTrue)
    {
        // Arrange
        std::ofstream file("config_test.txt");
        file << "SECRET=testsecretkey";
        file.close();

        // Act
        bool result = client.LoadConfig("config_test.txt");

        // Assert
        EXPECT_TRUE(result);
    }

    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_010_LoadConfig_FileDoesNotExist_ReturnsFalse)
    {
        // Act
        bool result = client.LoadConfig("missing_test.txt");

        // Assert
        EXPECT_FALSE(result);
    }

    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_011_LoadConfig_SecretMissing_ReturnsFalse)
    {
        // Arrange
        std::ofstream file("config_bad.txt");
        file << "PORT=54000";
        file.close();

        // Act
        bool result = client.LoadConfig("config_bad.txt");

        // Assert
        EXPECT_FALSE(result);
    }

    TEST_F(InFlightClientTest, FLIGHT_CLT_TEST_012_LoadConfig_IgnoresCommentsAndBlankLines_ReturnsTrue)
    {
        // Arrange
        std::ofstream file("config_test.txt");
        file << "# Comment line\n";
        file << "\n";
        file << "SECRET=testabc123\n";
        file.close();

        // Act
        bool result = client.LoadConfig("config_test.txt");

        // Assert
        EXPECT_TRUE(result);
    }
}