#include "pch.h"

//TEST(TestCaseName, TestName) {
//  EXPECT_EQ(1, 1);
//  EXPECT_TRUE(true);
//}

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
        std::remove("test_config.txt");
        std::remove("config_test.txt");
        std::remove("config_bad.txt");
        std::remove("test_logger.txt");
    }
};


// ======================================================
// Tests for LoadConfig
// ======================================================

//Tests LoadConfig function with valid file
TEST_F(InFlightClientTest, LoadConfig_ValidFile_ReturnsTrue)
{
    std::ofstream file("config_test.txt");
    file << "SECRET=testsecretkey";
    file.close();

    EXPECT_TRUE(client.LoadConfig("config_test.txt"));
}

//Tests LoadConfig function with missing file
TEST_F(InFlightClientTest, LoadConfig_FileDoesNotExist_ReturnsFalse)
{
    EXPECT_FALSE(client.LoadConfig("missing_test.txt"));
}

//Test LoadConfig function with no SECRET key
TEST_F(InFlightClientTest, LoadConfig_SecretMissing_ReturnsFalse)
{
    std::ofstream file("config_bad.txt");
    file << "PORT=54000";
    file.close();

    EXPECT_FALSE(client.LoadConfig("config_bad.txt"));
}

//Test LoadConfig function with multiple lines above SECRET key
TEST_F(InFlightClientTest, LoadConfig_IgnoresCommentsAndBlankLines_ReturnsTrue)
{
    std::ofstream file("config_test.txt");
    file << "# Comment line\n";
    file << "\n";
    file << "SECRET=testabc123\n";
    file.close();

    EXPECT_TRUE(client.LoadConfig("config_test.txt"));
}


// ======================================================
// Tests for ComputeSignature
// ======================================================

//Tests ComputeSignature function with Same CRCs
TEST_F(InFlightClientTest, ComputeSignature_ReturnsExpectedCRC_ReturnsEQ)
{
    std::ofstream file("config_test.txt");
    file << "SECRET=testkey123";
    file.close();

    client.LoadConfig("config_test.txt");

    uint32_t randomValue = 12345;

    std::string payload = "testkey123";
    payload.append(reinterpret_cast<const char*>(&randomValue), sizeof(uint32_t));

    uint32_t expected = CRC32::Calculate(payload.c_str(),
        static_cast<unsigned int>(payload.size()));

    EXPECT_EQ(client.ComputeSignature(randomValue), expected);
}

//Tests ComputeSignature function with Different CRCs
TEST_F(InFlightClientTest, ComputeSignature_DifferentInputsProduceDifferentResults_ReturnsNE)
{
    std::ofstream file("config_test.txt");
    file << "SECRET=testkey123";
    file.close();

    client.LoadConfig("config_test.txt");

    EXPECT_NE(client.ComputeSignature(1), client.ComputeSignature(2));
}

//Test ComputeSignature with empty secret
TEST(ComputeSignatureTests, EmptySecretHandlesGracefully)
{
    InFlightClient client;

    uint32_t value = 12345;

    EXPECT_NO_THROW(client.ComputeSignature(value));
}

// ======================================================
// Tests for ValidatePacket
// ======================================================

//Test ValidatePacket with Valid Packet
TEST_F(InFlightClientTest, ValidatePacket_ValidPacket_ReturnsTrue)
{
    Packet pkt;
    pkt.SetFlightID(101);
    pkt.SetMessageType(1);
    pkt.SetTimeStamp(123456);
    pkt.SetData("HELLO", 5);

    unsigned int size = 0;
    char* buffer = pkt.SerializeData(size);

    EXPECT_TRUE(client.ValidatePacket(buffer, size));
}

//Test ValidatePacket with Small Buffer
TEST_F(InFlightClientTest, ValidatePacket_BufferSmall_ReturnsFalse)
{
    char smallBuffer[2] = { 0 };

    EXPECT_FALSE(client.ValidatePacket(smallBuffer, 2));
}

//Test ValidatePacket with Incorrect Length
TEST_F(InFlightClientTest, ValidatePacket_BadLength_ReturnsFalse)
{
    Packet pkt;
    pkt.SetFlightID(101);
    pkt.SetMessageType(1);
    pkt.SetTimeStamp(123456);
    pkt.SetData("HELLO", 5);

    unsigned int size = 0;
    char* buffer = pkt.SerializeData(size);

    EXPECT_FALSE(client.ValidatePacket(buffer, size - 1));       // Compare to wrong size
}

//Test ValidatePacket with Bad CRC
TEST_F(InFlightClientTest, ValidatePacket_BadCRC_ReturnsFalse)
{
    Packet pkt;
    pkt.SetFlightID(101);
    pkt.SetMessageType(1);
    pkt.SetTimeStamp(123456);
    pkt.SetData("HELLO", 5);

    unsigned int size = 0;
    char* buffer = pkt.SerializeData(size);

    buffer[5] ^= 0xFF;    // Change CRC by one byte

    EXPECT_FALSE(client.ValidatePacket(buffer, size));
}

//Test ValidatePacket on null buffer
TEST(ValidatePacketTests, NullBuffer_ReturnsFalse)
{
    InFlightClient client;

    EXPECT_FALSE(client.ValidatePacket(nullptr, 10));
}

// ======================================================
// CloseSocket Tests
// ======================================================

//Test CloseSocket on Invalid Socket
TEST_F(InFlightClientTest, CloseSocket_InvalidSocket_DoesNothing_ReturnsEQ)
{
    SOCKET sock = INVALID_SOCKET;

    client.CloseSocket(&sock);

    EXPECT_EQ(sock, INVALID_SOCKET);
}


// =====================================================
// Test SetData
// =====================================================

//Test Set Data on Corrupt Length
TEST(PacketTests, SetData_StoresCorrectLength)
{
    Packet pkt;

    const char input[] = "HELLO";
    unsigned int size = sizeof(input) - 1;

    pkt.SetData(input, size);

    EXPECT_EQ(pkt.GetBodyLength(), size);
    EXPECT_EQ(std::memcmp(pkt.GetData(), input, size), 0);
}

//Test Set Data on Null Input
TEST(PacketTests, SetData_StoresNullInput)
{
    Packet pkt;

    const char input[] = "";
    unsigned int size = sizeof(input);

    pkt.SetData(input, size);

    EXPECT_EQ(pkt.GetBodyLength(), size);
    EXPECT_EQ(std::memcmp(pkt.GetData(), input, size), 0);
}

// =====================================================
// Test SerializeData
// =====================================================

//Test SerializeData on Valid Buffer
TEST(PacketTests, SerializeData_ReturnsValidBuffer)
{
    Packet pkt;

    const char input[] = "TESTDATA";
    unsigned int size = sizeof(input) - 1;

    pkt.SetData(input, size);

    unsigned int totalSize = 0;
    char* buffer = pkt.SerializeData(totalSize);

    ASSERT_NE(buffer, nullptr);
    EXPECT_GT(totalSize, sizeof(PacketHeader));

    // Check header exists at start (basic structural validation)
    PacketHeader header{};
    std::memcpy(&header, buffer, sizeof(PacketHeader));

    EXPECT_EQ(header.Length, size);
}

// =====================================================
// Test Copy Constructor
// =====================================================

//Test Copy Constructor on Valid Data
TEST(PacketTests, CopyConstructor_CreatesDeepCopy)
{
    Packet pkt;

    const char data[] = "COPY_TEST";
    unsigned int size = sizeof(data) - 1;

    pkt.SetData(data, size);

    Packet copy(pkt);

    EXPECT_EQ(copy.GetBodyLength(), pkt.GetBodyLength());
    EXPECT_EQ(std::memcmp(copy.GetData(), pkt.GetData(), size), 0);

    EXPECT_NE(copy.GetData(), pkt.GetData()); // Check deep copy occured
}

// =====================================================
// Test Copy Assignment Operator
// =====================================================

//Test Copy Assignment Operator on Valid Data
TEST(PacketTests, AssignmentOperator_DeepCopiesData)
{
    Packet a;
    Packet b;

    const char data[] = "ASSIGN_TEST";
    unsigned int size = sizeof(data) - 1;

    a.SetData(data, size);

    b = a;

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
    const char data[] = "HELLO_WORLD";

    uint32_t crc1 = CRC32::Calculate(data, strlen(data));
    uint32_t crc2 = CRC32::Calculate(data, strlen(data));

    EXPECT_EQ(crc1, crc2);
}

//Test Calculate on different CRCs
TEST(CRC32Tests, DifferentInputProducesDifferentCRC)
{
    const char a[] = "HELLO";
    const char b[] = "HELLO!";

    uint32_t crcA = CRC32::Calculate(a, strlen(a));
    uint32_t crcB = CRC32::Calculate(b, strlen(b));

    EXPECT_NE(crcA, crcB);
}

//Test Calculate on Empty buffer
TEST(CRC32Tests, EmptyBufferReturnsValidCRC)
{
    uint32_t crc = CRC32::Calculate(nullptr, 0);

    EXPECT_EQ(crc, 0);
}

// =====================================================
// Test Logger 
// =====================================================

//Test Log function writing to file
TEST(LoggerTests, Log_WritesToFile)
{
    const std::string filename = "test_logger.txt";

    std::remove(filename.c_str());

    Logger logger(filename);

    const char msg[] = "LOG_TEST_MESSAGE";

    logger.Log(msg, sizeof(msg) - 1);

    std::ifstream file(filename);
    ASSERT_TRUE(file.is_open());

    std::string line;
    std::getline(file, line);

    // Check message exists
    EXPECT_NE(line.find("LOG_TEST_MESSAGE"), std::string::npos);

    // Check timestamp exists (basic heuristic: '[' and ']')
    EXPECT_NE(line.find('['), std::string::npos);
    EXPECT_NE(line.find(']'), std::string::npos);

    file.close();
    std::remove(filename.c_str());
}

//Test Log function writing to file on empty message
TEST(LoggerTests, Log_WritesToFile_EmptyMessage)
{
    const std::string filename = "test_logger.txt";

    std::remove(filename.c_str());

    Logger logger(filename);

    const char msg[] = "";

    logger.Log(msg, sizeof(msg) - 1);

    std::ifstream file(filename);
    ASSERT_TRUE(file.is_open());

    std::string line;
    std::getline(file, line);

    // Check message exists
    EXPECT_NE(line.find(""), std::string::npos);

    // Check timestamp exists (basic heuristic: '[' and ']')
    EXPECT_NE(line.find('['), std::string::npos);
    EXPECT_NE(line.find(']'), std::string::npos);

    file.close();
    std::remove(filename.c_str());
}

// =====================================================
// Test InitializeWinsock
// =====================================================

//Test InitializeWinsock successful
TEST(InFlightClientTests, InitializeWinsock_Success)
{
    InFlightClient client;

    EXPECT_TRUE(client.InitializeWinsock());
}

// =====================================================
// Test CreateSocket 
// =====================================================


//Test CreateSocket does not throw error
TEST(InFlightClientTests, CreateSocket_ReturnsBool)
{
    InFlightClient client;

    EXPECT_NO_THROW(client.CreateSocket());
}


