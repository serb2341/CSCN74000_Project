#pragma once

#ifndef PACKET_HEADER

struct PacketHeader {
	unsigned int FlightID;
	unsigned int MessageType;
	unsigned char TimeStamp;
	unsigned int Length;
};

#endif // PACKET_HEADER