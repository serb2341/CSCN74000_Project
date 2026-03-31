#pragma once

#include <cstdint>

class CRC32 {
private:
	// This is a precomputed lookup table (256 entries) for fast CRC calculation.
	static const uint32_t s_table[256];

public:
	// Here we compute the CRC-32 over the given byte buffer.
	// buffer is the pointer to the data to checksum.
	// lenght is the number of bytes to process.
	// The method returns the 32-bit CRC value.
	static uint32_t Calculate(const char* buffer, unsigned int length);
};