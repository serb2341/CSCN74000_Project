#include "pch.h"
#include "CppUnitTest.h"

#include "../Server/CRC32.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ServerTests {
	TEST_CLASS(CRC32Tests) {
	public:
		// --------------------------------------------------------
		// Known-value tests — verified against standard CRC-32 tables.
		// These pin the algorithm so any future change is caught.
		// --------------------------------------------------------

		TEST_METHOD(SVR_CRC_TEST_001_KnownValue_ABC) {
			// CRC-32 of "ABC" is a well-known reference value.
			const char input[] = { 'A', 'B', 'C' };

			uint32_t result = ServerChecksum::CRC32::Calculate(input, 3U);

			Assert::AreEqual(static_cast<uint32_t>(0xA3830348U), result, L"CRC32 of 'ABC' must match the known reference value.");
		};

		TEST_METHOD(SVR_CRC_TEST_002_KnownValue_123456789) {
			// CRC-32 of "123456789" is the canonical self-test value (0xCBF43926).
			const char input[] = { '1','2','3','4','5','6','7','8','9' };

			uint32_t result = ServerChecksum::CRC32::Calculate(input, 9U);

			Assert::AreEqual(static_cast<uint32_t>(0xCBF43926U), result, L"CRC32 of '123456789' must equal the canonical 0xCBF43926.");
		};


		// --------------------------------------------------------
		// Consistency tests
		// --------------------------------------------------------

		TEST_METHOD(SVR_CRC_TEST_003_SameInput_SameOutput) {
			// Deterministic — two calls with identical input must produce identical output.
			const char input[] = "Hello Server";

			unsigned int len = static_cast<unsigned int>(sizeof(input) - 1U);

			uint32_t first = ServerChecksum::CRC32::Calculate(input, len);
			uint32_t second = ServerChecksum::CRC32::Calculate(input, len);

			Assert::AreEqual(first, second, L"Checksum::CRC32::Calculate must be deterministic for the same input.");
		};

		TEST_METHOD(SVR_CRC_TEST_004_DifferentInput_DifferentOutput) {
			// Even a 1-byte difference must produce a different CRC.
			const char inputA[] = "PacketA";
			const char inputB[] = "PacketB";

			uint32_t CRC_A = ServerChecksum::CRC32::Calculate(inputA, 7U);
			uint32_t CRC_B = ServerChecksum::CRC32::Calculate(inputB, 7U);

			Assert::AreNotEqual(CRC_A, CRC_B, L"Different inputs must not produce the same CRC-32.");
		};


		// --------------------------------------------------------
		// Edge cases
		// --------------------------------------------------------

		TEST_METHOD(SVR_CRC_TEST_005_SingleByte) {
			// Single byte input must not crash and must return a non-zero value.
			const char input[] = { 0x42 };

			uint32_t result = ServerChecksum::CRC32::Calculate(input, 1U);

			// Just verify it doesn't return 0 for a non-zero byte.
			// a CRC of 0 on non-empty input would indicate a broken implementation.
			Assert::AreNotEqual(static_cast<uint32_t>(0U), result, L"CRC-32 of a single non-zero byte must not be 0.");
		};

		TEST_METHOD(SVR_CRC_TEST_006_AllZeroBytes_NonZeroCRC) {
			// A buffer of zeroes should still produce a meaningful CRC (not 0).
			char input[8] = {};

			uint32_t result = ServerChecksum::CRC32::Calculate(input, 8U);

			Assert::AreNotEqual(static_cast<uint32_t>(0U), result, L"CRC-32 of an all-zero buffer must not be 0.");
		};

		TEST_METHOD(SVR_CRC_TEST_007_LargeInput_DoesNotCrash) {
			// Stress test — large buffer should complete without crashing.
			const unsigned int size = 10000U;

			char* input = new char[size];

			for (unsigned int i = 0U; i < size; ++i) {
				input[i] = static_cast<char>(i % 256);
			};

			uint32_t result = ServerChecksum::CRC32::Calculate(input, size);

			delete[] input;
			input = nullptr;

			// As long as it doesn't crash and returns something, this passes.
			(void)result;

			Assert::IsTrue(true, L"CRC32::Calculate must handle large inputs without crashing.");
		};

		TEST_METHOD(SVR_CRC_TEST_008_CRC_ChangesWhenByteFlipped) {
			// Simulates a single-bit corruption, CRC must detect it.
			char input[16] = "ServerPacket";

			unsigned int len = 12U;

			uint32_t original = ServerChecksum::CRC32::Calculate(input, len);

			input[5] ^= 0x01;   // Flip one bit

			uint32_t corrupted = ServerChecksum::CRC32::Calculate(input, len);

			Assert::AreNotEqual(original, corrupted, L"CRC-32 must change when any byte in the input is modified.");
		};
	};
};