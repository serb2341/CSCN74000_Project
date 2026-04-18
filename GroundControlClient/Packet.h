#pragma once

#include <iostream>
#include <fstream>
#include <cstdint>

namespace GroundControlCommunication {
	#pragma pack(push, 1)
	struct PacketHeader {
		unsigned int FlightID;		// Source ID.
		unsigned int MessageType;	// Message Type Identifier.
		unsigned int Length;		// Number of bytes in the data body.
		uint32_t TimeStamp;
	};
	#pragma pack(pop)

	class Packet {
	private:
		PacketHeader pktHead;

		char* data;

		uint32_t CRC;


		char* txBuffer;

		uint32_t CalculateCRC() const;

	public:
		Packet();

		Packet(const char* src);

		~Packet();

		Packet(const Packet& pkt);

		Packet& operator=(const Packet& pkt);

		void SetFlightID(unsigned int value);
		void SetMessageType(unsigned int value);
		void SetTimeStamp(uint32_t value);
		void SetData(const char* srcData, unsigned int size);

		char* SerializeData(unsigned int& totalSize);
		void DeserializeData(const char* rxBuffer);

		void DisplayInFlightSide(std::ostream& os);
		void DisplayGroundControlSide(std::ostream& os);

		const char* GetData();
		unsigned int GetBodyLength();
		unsigned int GetFlightID();

		// Returns a constant reference to the internal header structure
		const PacketHeader& GetHeader() const;
	};
};