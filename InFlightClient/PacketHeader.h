#pragma once

#ifndef PACKET_HEADER

struct PacketHeader {
	unsigned int FlightID;
	unsigned int MessageType;
	unsigned int Length;
	unsigned char TimeStamp;
};

#endif // PACKET_HEADER