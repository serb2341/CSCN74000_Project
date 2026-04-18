#include "pch.h"
#include "CppUnitTest.h"

#include "../GroundControlClient/CRC32.h"


#include <cstring>
#include <fstream>
#include <string>
#include <filesystem>
#include <vector>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;



namespace GroundControl_Tests
{
    TEST_CLASS(CRC32Tests)
    {
    public:

        // Empty buffer → well-known CRC-32 value for zero bytes (0x00000000 with final XOR)
        TEST_METHOD(GC_CRC_TEST01_EmptyBuffer_ReturnsZero)
        {
            uint32_t result = Checksum::CRC32::Calculate("", 0u);
            // CRC-32 of empty input is 0x00000000
            Assert::AreEqual(static_cast<uint32_t>(0x00000000U), result);
        }

        // Single known byte: CRC-32("A") = 0xD3D99E8B
        TEST_METHOD(GC_CRC_TEST02_SingleByte_KnownValue)
        {
            uint32_t result = Checksum::CRC32::Calculate("A", 1u);
            Assert::AreEqual(static_cast<uint32_t>(0xD3D99E8BU), result);
        }

        // Classic test vector: CRC-32("123456789") = 0xCBF43926
        TEST_METHOD(GC_CRC_TEST03_KnownString_StandardTestVector)
        {
            const char* data = "123456789";
            uint32_t result = Checksum::CRC32::Calculate(data, 9u);
            Assert::AreEqual(static_cast<uint32_t>(0xCBF43926U), result);
        }

        // Two calls with identical input must return identical results (determinism)
        TEST_METHOD(GC_CRC_TEST04_SameInput_AlwaysReturnsSameResult)
        {
            const char* data = "hello world";
            uint32_t r1 = Checksum::CRC32::Calculate(data, 11u);
            uint32_t r2 = Checksum::CRC32::Calculate(data, 11u);
            Assert::AreEqual(r1, r2);
        }

        // Different input must (almost certainly) produce different CRC
        TEST_METHOD(GC_CRC_TEST05_DifferentInputs_ProduceDifferentResults)
        {
            uint32_t r1 = Checksum::CRC32::Calculate("abc", 3u);
            uint32_t r2 = Checksum::CRC32::Calculate("abd", 3u);
            Assert::AreNotEqual(r1, r2);
        }

        // Length 1 vs length 2 of same buffer must differ
        TEST_METHOD(GC_CRC_TEST06_DifferentLengths_ProduceDifferentResults)
        {
            uint32_t r1 = Checksum::CRC32::Calculate("AB", 1u);
            uint32_t r2 = Checksum::CRC32::Calculate("AB", 2u);
            Assert::AreNotEqual(r1, r2);
        }

        // Changing a single byte must change the CRC
        TEST_METHOD(GC_CRC_TEST07_SingleBitFlip_ChangesCRC)
        {
            char buf1[4] = { 0x01, 0x02, 0x03, 0x04 };
            char buf2[4] = { 0x01, 0x02, 0x03, 0x05 }; // last byte flipped
            uint32_t r1 = Checksum::CRC32::Calculate(buf1, 4u);
            uint32_t r2 = Checksum::CRC32::Calculate(buf2, 4u);
            Assert::AreNotEqual(r1, r2);
        }

        // All-zeros buffer of length 4 should not equal all-ones
        TEST_METHOD(GC_CRC_TEST08_AllZeroVsAllFF_AreDistinct)
        {
            char zeros[4] = { 0x00, 0x00, 0x00, 0x00 };
            char ones[4] = { static_cast<char>(0xFF), static_cast<char>(0xFF),
                              static_cast<char>(0xFF), static_cast<char>(0xFF) };
            uint32_t r1 = Checksum::CRC32::Calculate(zeros, 4u);
            uint32_t r2 = Checksum::CRC32::Calculate(ones, 4u);
            Assert::AreNotEqual(r1, r2);
        }

        // Large buffer — just confirm it does not crash and returns non-zero
        TEST_METHOD(GC_CRC_TEST09_LargeBuffer_DoesNotCrash)
        {
            std::vector<char> big(4096, 0x42);
            uint32_t result = Checksum::CRC32::Calculate(big.data(), static_cast<unsigned int>(big.size()));
            Assert::AreNotEqual(static_cast<uint32_t>(0u), result);
        }
    };
}
