#include "pch.h"
#include "CppUnitTest.h"
#include "../InFlightClient/CRC32.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace InFlightClientTests
{
	TEST_CLASS(InFlightClientTests)
	{
	public:
		
		TEST_METHOD(FLIGHT_CLI_CRC_TEST_001_KnownValue_ABC) {
			// CRC-32 of "ABC" is a well-known reference value.
			const char input[] = { 'A', 'B', 'C' };

			uint32_t result = Checksum::CRC32::Calculate(input, 3U);

			Assert::AreEqual(static_cast<uint32_t>(0xA3830348U), result, L"CRC32 of 'ABC' must match the known reference value.");
		};
		
	};
}
