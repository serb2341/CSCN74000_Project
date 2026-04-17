#include "pch.h"

#include "gtest/gtest.h"
#include "..\InFlightClient\InFlightClient.h"
#include "..\InFlightClient\Packet.h"
#include "..\InFlightClient\CRC32.h"

#include <fstream>
#include <cstdio>

// ------------------------------------------------------
// Test Class
// ------------------------------------------------------
class InFlightClientTest : public ::testing::Test {
protected:
    InFlightClient client;

    // Removes all of the created files at end of testing
    void TearDown() override {
        std::remove("config_test.txt");
        std::remove("config_bad.txt");
        std::remove("test_logger.txt");
    }
};

// ======================================================
// Tests for ComputeSignature
// ======================================================

//Test ComputeSignature with empty secret
TEST(ComputeSignatureTests, EmptySecretHandlesGracefully)
{
    // Arrange
    InFlightClient client;
    uint32_t value = 12345;

    // Act / Assert
    EXPECT_NO_THROW(client.ComputeSignature(value));
}

//Tests ComputeSignature function with Same CRCs
TEST_F(InFlightClientTest, ComputeSignature_ReturnsExpectedCRC_ReturnsEQ)
{
    // Arrange
    std::ofstream file("config_test.txt");
    file << "SECRET=testkey123";
    file.close();

    client.LoadConfig("config_test.txt");

    uint32_t randomValue = 12345;

    std::string payload = "testkey123";
    payload.append(reinterpret_cast<const char*>(&randomValue), sizeof(uint32_t));

    uint32_t expected = CRC32::Calculate(
        payload.c_str(),
        static_cast<unsigned int>(payload.size())
    );

    // Act
    uint32_t result = client.ComputeSignature(randomValue);

    // Assert
    EXPECT_EQ(result, expected);
}

//Tests ComputeSignature function with Different CRCs
TEST_F(InFlightClientTest, ComputeSignature_DifferentInputsProduceDifferentResults_ReturnsNE)
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
TEST_F(InFlightClientTest, ValidatePacket_BufferSmall_ReturnsFalse)
{
    // Arrange
    char smallBuffer[2] = { 0 };

    // Act
    bool result = client.ValidatePacket(smallBuffer, 2);

    // Assert
    EXPECT_FALSE(result);
}

//Test ValidatePacket on null buffer
TEST(ValidatePacketTests, NullBuffer_ReturnsFalse)
{
    // Arrange
    InFlightClient client;

    // Act
    bool result = client.ValidatePacket(nullptr, 10);

    // Assert
    EXPECT_FALSE(result);
}

// ======================================================
// CloseSocket Tests
// ======================================================

//Test CloseSocket on Invalid Socket
TEST_F(InFlightClientTest, CloseSocket_InvalidSocket_DoesNothing_ReturnsEQ)
{
    // Arrange
    SOCKET sock = INVALID_SOCKET;

    // Act
    client.CloseSocket(&sock);

    // Assert
    EXPECT_EQ(sock, INVALID_SOCKET);
}

// =====================================================
// Test SetData
// =====================================================

//Test Set Data on Correct Length
TEST(PacketTests, SetData_StoresCorrectLength)
{
    // Arrange
    Packet pkt;

    const char input[] = "HELLO";
    unsigned int size = sizeof(input) - 1;

    // Act
    pkt.SetData(input, size);

    // Assert
    EXPECT_EQ(pkt.GetBodyLength(), size);
    EXPECT_EQ(std::memcmp(pkt.GetData(), input, size), 0);
}

//Test Set Data on Null Input
TEST(PacketTests, SetData_StoresNullInput)
{
    // Arrange
    Packet pkt;

    const char input[] = "";
    unsigned int size = sizeof(input);

    // Act
    pkt.SetData(input, size);

    // Assert
    EXPECT_EQ(pkt.GetBodyLength(), size);
    EXPECT_EQ(std::memcmp(pkt.GetData(), input, size), 0);
}

// =====================================================
// Test Copy Constructor
// =====================================================

//Test Copy Constructor on Valid Data
TEST(PacketTests, CopyConstructor_CreatesDeepCopy)
{
    // Arrange
    Packet pkt;

    const char data[] = "COPY_TEST";
    unsigned int size = sizeof(data) - 1;

    pkt.SetData(data, size);

    // Act
    Packet copy(pkt);

    // Assert
    EXPECT_EQ(copy.GetBodyLength(), pkt.GetBodyLength());
    EXPECT_EQ(std::memcmp(copy.GetData(), pkt.GetData(), size), 0);
    EXPECT_NE(copy.GetData(), pkt.GetData());
}

// =====================================================
// Test Copy Assignment Operator
// =====================================================

//Test Copy Assignment Operator on Valid Data
TEST(PacketTests, AssignmentOperator_DeepCopiesData)
{
    // Arrange
    Packet a;
    Packet b;

    const char data[] = "ASSIGN_TEST";
    unsigned int size = sizeof(data) - 1;

    a.SetData(data, size);

    // Act
    b = a;

    // Assert
    EXPECT_EQ(b.GetBodyLength(), a.GetBodyLength());
    EXPECT_EQ(std::memcmp(b.GetData(), a.GetData(), size), 0);
    EXPECT_NE(b.GetData(), a.GetData());
}

// =====================================================
// Test Calculate
// =====================================================

//Test Calculate function on same CRCs
TEST(CRC32Tests, SameInputProducesSameCRC)
{
    // Arrange
    const char data[] = "HELLO_WORLD";

    // Act
    uint32_t crc1 = CRC32::Calculate(data, strlen(data));
    uint32_t crc2 = CRC32::Calculate(data, strlen(data));

    // Assert
    EXPECT_EQ(crc1, crc2);
}

//Test Calculate on different CRCs
TEST(CRC32Tests, DifferentInputProducesDifferentCRC)
{
    // Arrange
    const char a[] = "HELLO";
    const char b[] = "HELLO!";

    // Act
    uint32_t crcA = CRC32::Calculate(a, strlen(a));
    uint32_t crcB = CRC32::Calculate(b, strlen(b));

    // Assert
    EXPECT_NE(crcA, crcB);
}

//Test Calculate on Empty buffer
TEST(CRC32Tests, EmptyBufferReturnsValidCRC)
{
    // Arrange / Act
    uint32_t crc = CRC32::Calculate(nullptr, 0);

    // Assert
    EXPECT_EQ(crc, 0);
}

// =====================================================
// Test InitializeWinsock
// =====================================================

//Test InitializeWinsock successful
TEST(InFlightClientTests, InitializeWinsock_Success)
{
    // Arrange
    InFlightClient client;

    // Act
    bool result = client.InitializeWinsock();

    // Assert
    EXPECT_TRUE(result);
}

// =====================================================
// Test CreateSocket
// =====================================================

//Test CreateSocket does not throw error
TEST(InFlightClientTests, CreateSocket_ReturnsBool)
{
    // Arrange
    InFlightClient client;

    // Act / Assert
    EXPECT_NO_THROW(client.CreateSocket());
}

// ======================================================
// LoadConfig Tests
// ======================================================

TEST_F(InFlightClientTest, LoadConfig_ValidFile_ReturnsTrue)
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

TEST_F(InFlightClientTest, LoadConfig_FileDoesNotExist_ReturnsFalse)
{
    // Act
    bool result = client.LoadConfig("missing_test.txt");

    // Assert
    EXPECT_FALSE(result);
}

TEST_F(InFlightClientTest, LoadConfig_SecretMissing_ReturnsFalse)
{
    // Arrange
    std::ofstream file("config_bad.txt");
    file << "PORT=54564";
    file.close();

    // Act
    bool result = client.LoadConfig("config_bad.txt");

    // Assert
    EXPECT_FALSE(result);
}

TEST_F(InFlightClientTest, LoadConfig_IgnoresCommentsAndBlankLines_ReturnsTrue)
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
