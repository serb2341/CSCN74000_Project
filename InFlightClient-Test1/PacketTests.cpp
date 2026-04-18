#include "pch.h"

#include "gtest/gtest.h"
#include "..\InFlightClient\Packet.h"

#include <fstream>
#include <cstdio>


namespace InFlightClientTests
{
    // ------------------------------------------------------
    // Packet Test Class
    // ------------------------------------------------------
    class PacketTests : public ::testing::Test {
    protected:

    };

    // =====================================================
    // Test SetData
    // =====================================================

    //Test Set Data on Correct Length
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_001_SetData_StoresCorrectLength)
    {
        // Arrange
        InFlightCommunication::Packet pkt;

        const char input[] = "HELLO";
        unsigned int size = sizeof(input) - 1;

        // Act
        pkt.SetData(input, size);

        // Assert
        EXPECT_EQ(pkt.GetBodyLength(), size);
        EXPECT_EQ(std::memcmp(pkt.GetData(), input, size), 0);
    }

    //Test Set Data on Null Input
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_002_SetData_StoresNullInput)
    {
        // Arrange
        InFlightCommunication::Packet pkt;

        const char input[] = "";
        unsigned int size = sizeof(input);

        // Act
        pkt.SetData(input, size);

        // Assert
        EXPECT_EQ(pkt.GetBodyLength(), size);
        EXPECT_EQ(std::memcmp(pkt.GetData(), input, size), 0);
    }

    // =====================================================
    // Test PacketHeader
    // =====================================================

    //Test Empty Header
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_003_PacketHeader_EmptyHeaderBytes)
    {
        // Arrange
        size_t expectedSize = 16U;

        // Act
        size_t actualSize = sizeof(InFlightCommunication::PacketHeader);

        // Assert
        EXPECT_EQ(expectedSize, actualSize);
    }

    //Test Header Offset 0 Bytes for FlightID
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_004_PacketHeader_HeaderOffset0Bytes_FlightID)
    {
        // Arrange
        InFlightCommunication::PacketHeader header{};
        size_t expectedSize = 0U;

        // Act
        size_t offset = (size_t)&header.FlightID - (size_t)& header;

        // Assert
        EXPECT_EQ(expectedSize, offset);
    }

    //Test Header Offset 4 Bytes for Message Type
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_005_PacketHeader_HeaderOffset4Bytes_MessageType)
    {
        // Arrange
        InFlightCommunication::PacketHeader header{};
        size_t expectedSize = 4U;

        // Act
        size_t offset = (size_t)&header.MessageType - (size_t)&header;

        // Assert
        EXPECT_EQ(expectedSize, offset);
    }

    //Test Header Offset 8 Bytes for Length
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_006_PacketHeader_HeaderOffset12Bytes_Length)
    {
        // Arrange
        InFlightCommunication::PacketHeader header{};
        size_t expectedSize = 8U;

        // Act
        size_t offset = (size_t)&header.Length - (size_t)&header;

        // Assert
        EXPECT_EQ(expectedSize, offset);
    }

    //Test Header Offset 12 Bytes for TimeStamp
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_007_PacketHeader_HeaderOffset12Bytes_TimeStamp)
    {
        // Arrange
        InFlightCommunication::PacketHeader header{};
        size_t expectedSize = 12U;

        // Act
        size_t offset = (size_t)&header.TimeStamp - (size_t)&header;

        // Assert
        EXPECT_EQ(expectedSize, offset);
    }

    // =====================================================
    // Test Copy Constructor
    // =====================================================

    //Test Copy Constructor on Valid Data
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_008_CopyConstructor_CreatesDeepCopy)
    {
        // Arrange
        InFlightCommunication::Packet pkt;

        const char data[] = "COPY_TEST";
        unsigned int size = sizeof(data) - 1;

        pkt.SetData(data, size);

        // Act
        InFlightCommunication::Packet copy(pkt);

        // Assert
        EXPECT_EQ(copy.GetBodyLength(), pkt.GetBodyLength());
        EXPECT_EQ(std::memcmp(copy.GetData(), pkt.GetData(), size), 0);
        EXPECT_NE(copy.GetData(), pkt.GetData());
    }

    // =====================================================
    // Test Copy Assignment Operator
    // =====================================================

    //Test Copy Assignment Operator on Valid Data
    TEST(PacketTests, FLIGHT_CLT_PKT_TEST_009_AssignmentOperator_DeepCopiesData)
    {
        // Arrange
        InFlightCommunication::Packet a;
        InFlightCommunication::Packet b;

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

}