#pragma once

#ifndef PACKET_HEADER

#include <cstdint>

struct PacketHeader {
	unsigned int FlightID;
	unsigned int MessageType;
	unsigned int Length;
	uint32_t TimeStamp;
};

#endif // PACKET_HEADER