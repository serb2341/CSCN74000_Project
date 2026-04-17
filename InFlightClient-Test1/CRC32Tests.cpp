#include "pch.h"

#include "gtest/gtest.h"
#include "..\InFlightClient\CRC32.h"

#include <fstream>
#include <cstdio>

// ------------------------------------------------------
// Test Class
// ------------------------------------------------------

namespace InFlightClientTests 
{
    // =====================================================
    // CRC32 Test Calculate
    // =====================================================

    class CRC32Tests : public ::testing::Test {
    protected:

    };

    //Test Calculate function on expected CRCs
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_001_ExpectedCRCResults)
    {
        // Arrange
        const char data[] = { 'A', 'B', 'C' };
        uint32_t expected = 0xA3830348U;

        // Act
        uint32_t actual = Checksum::CRC32::Calculate(data, 3U);

        // Assert
        EXPECT_EQ(actual, expected);
    }
    
    //Test Calculate function on same CRCs
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_002_SameInputProducesSameCRC)
    {
        // Arrange
        const char data[] = "HELLO_WORLD";

        // Act
        uint32_t crc1 = Checksum::CRC32::Calculate(data, strlen(data));
        uint32_t crc2 = Checksum::CRC32::Calculate(data, strlen(data));

        // Assert
        EXPECT_EQ(crc1, crc2);
    }

    //Test Calculate on different CRCs
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_003_DifferentInputProducesDifferentCRC)
    {
        // Arrange
        const char a[] = "HELLO";
        const char b[] = "HELLO!";

        // Act
        uint32_t crcA = Checksum::CRC32::Calculate(a, strlen(a));
        uint32_t crcB = Checksum::CRC32::Calculate(b, strlen(b));

        // Assert
        EXPECT_NE(crcA, crcB);
    }

    //Test Calculate on Empty buffer
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_004_EmptyBufferReturnsValidCRC)
    {
        // Arrange / Act
        uint32_t crc = Checksum::CRC32::Calculate(nullptr, 0);

        // Assert
        EXPECT_EQ(crc, 0);
    }

    //Test Calculate on Single Byte buffer
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_005_SingleByteBufferReturnsValidCRC)
    {
        // Arrange 
        const char data[] = { 0x42 };

        // Act
        uint32_t crc = Checksum::CRC32::Calculate(data, 1U);

        // Assert
        EXPECT_NE(crc, 0U);
    }

    //Test Calculate on All Zero buffer
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_006_AllZeroBufferReturnsValidCRC)
    {
        // Arrange 
        const char data[8] = {};

        // Act
        uint32_t crc = Checksum::CRC32::Calculate(data, 8U);

        // Assert
        EXPECT_NE(crc, 0U);
    }

    //Test Calculate on Corrupt buffer
    TEST(CRC32Tests, FLIGHT_CLT_CRC_TEST_007_CorruptBufferReturnsValidCRC)
    {
        // Arrange 
        char data[] = "HelloWorld";

        // Act
        uint32_t crc1 = Checksum::CRC32::Calculate(data, strlen(data));
        
        data[5] ^= 0x01;

        uint32_t crc2 = Checksum::CRC32::Calculate(data, strlen(data));

        // Assert
        EXPECT_NE(crc1, crc2);
    }
}