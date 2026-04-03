#pragma once

#include <iostream>
#include <fstream>
#include <cstdint>

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
};







//#include <memory>
//#include <iostream>
//#include <fstream>

//class Packet
//{
//private:
//	static const unsigned int CRCvalue = 0xFF00FF00U;
//	static const unsigned int MAX_DATA_SIZE = 256;
//	struct Header
//	{
//		unsigned int FlightID;				//Source ID
//		unsigned int MessageType;			//Line number of the input file being transmitted
//		unsigned char TimeStamp;					//Number of characters in the line
//		unsigned int Length;
//	} Head;
//	char Data[MAX_DATA_SIZE];							//The data bytes
//	unsigned int CRC;					//Cyclic Redundancy Check
//
//	char TxBuffer[sizeof(Head) + MAX_DATA_SIZE + sizeof(unsigned int)];
//
//public:
//	Packet() {
//		(void)memset(&Head, 0, sizeof(Head));
//		for (unsigned int i = 0U; i < MAX_DATA_SIZE; ++i) // prevent misra error "'Data' array should not decay to a pointer."
//		{
//			Data[i] = '\0';
//		}
//		for (unsigned int i = 0U; i < sizeof(TxBuffer); ++i) // prevent misra error "'TxBuffer' array should not decay to a pointer."
//		{
//			TxBuffer[i] = '\0';
//		}
//	} //Default Constructor - Safe State
//
//	void SetFlightID(unsigned int value) { Head.FlightID = value; };		//Sets the flight ID in the packet header to the value passed in as a parameter
//	// get the value of the flight ID from the packet header
//	unsigned int GetFlightID() const { return Head.FlightID; };
//	void SetMessageType(unsigned int value) { Head.MessageType = value; };
//	void SetTimeStamp(unsigned char value) { Head.TimeStamp = value; };
//
//	void DisplayInFlightSide(std::ostream& os)
//	{
//		os << std::dec;
//		os << "Ground Control | " << Data << std::endl;
//	}
//
//	void DisplayGroundControlSide(std::ostream& os)
//	{
//		os << std::dec;
//		os << Head.FlightID << " | " << Data << std::endl;
//	}
//
//	Packet(const char* src) //Overloaded constructor that takes character pointer src and uses it to populate the packet
//	{
//		if (src != nullptr)
//		{
//			(void)memset(&Head, 0, sizeof(Head));
//			for (unsigned int i = 0U; i < MAX_DATA_SIZE; ++i) // prevent misra error "'Data' array should not decay to a pointer."
//			{
//				Data[i] = '\0';
//			}
//
//			(void)memcpy(&Head, src, sizeof(Head)); //copies the first two bytes of the src character array to the Head of the packet
//
//			if (Head.Length > MAX_DATA_SIZE)
//			{
//				Head.Length = MAX_DATA_SIZE;
//			}
//
//			for (unsigned int i = 0U; i < Head.Length; ++i) // copies data 
//			{
//				Data[i] = src[sizeof(Head) + i];
//			}
//
//			Data[Head.Length] = '\0'; //adds termination character to end of the Data array
//
//			unsigned int offset = sizeof(Head) + Head.Length; // prevents "Array indexing should be the only form of pointer arithmetic and it should be applied only to objects defined as an array type."
//
//			unsigned char* crcBytes = reinterpret_cast<unsigned char*>(&CRC); //misra safe casting
//
//			for (unsigned int i = 0U; i < sizeof(unsigned int); ++i) //copies crc
//			{
//				crcBytes[i] = src[offset + i];
//			}
//		}
//	}
//
//	void SetData(const char srcData[], unsigned int Size) //parameters are a char array and a length of the char array
//	{
//		if (srcData != nullptr) //checks if data is empty
//		{
//			if (Size > MAX_DATA_SIZE) //ensures data is not too long
//			{
//				Size = MAX_DATA_SIZE;
//			}
//
//			for (unsigned int i = 0U; i < Size; ++i) // copies data
//			{
//				Data[i] = srcData[i];
//			}
//			Data[Size] = '\0'; //adds termination character to end of the Data array
//
//			Head.Length = Size; //sets the Head.Length to the correct size
//
//			CRC = CalculateCRC(); //calculates the CRC for the data
//		}
//	};
//
//	char* SerializeData(unsigned int& TotalSize) //Puts all of the data in one spot sequenitally
//	{
//		TotalSize = sizeof(Header) + Head.Length + sizeof(unsigned int); //calcualtes the amount of space needed to store all of the info in the Packet
//		(void)memcpy(TxBuffer, &Head, sizeof(Head)); //copies the memory of the Head into the start of the TxBuffer
//		for (unsigned int i = 0U; i < Head.Length; ++i) //copies the memory of the Data into the TxBuffer after the Head
//		{
//			TxBuffer[sizeof(Head) + i] = Data[i];
//		}
//		unsigned int offset = sizeof(Head) + Head.Length; // prevents misra array and decay rules
//		unsigned char* crcBytes = reinterpret_cast<unsigned char*>(&CRC);
//		for (unsigned int i = 0U; i < sizeof(unsigned int); ++i) //copies the memory of the CRC to the TxBuffer after the Data
//		{
//			TxBuffer[offset + i] = crcBytes[i];
//		}
//
//		return TxBuffer; //returns the character array buffer to be sent to the Server
//	};
//
//	void DeserializeData(const char* rxBuffer) //Extracts data
//	{
//		if (rxBuffer != nullptr) //checks if data is empty
//		{
//			(void)memcpy(&Head, rxBuffer, sizeof(Head));
//
//			if (Head.Length > MAX_DATA_SIZE) //ensures data is not too long
//			{
//				Head.Length = MAX_DATA_SIZE;
//			}
//
//			(void)memcpy(Data, rxBuffer + sizeof(Head), Head.Length);
//			Data[Head.Length] = '\0';
//
//			(void)memcpy(&CRC, rxBuffer + sizeof(Head) + Head.Length, sizeof(unsigned int));
//		}
//	};
//
//	unsigned int CalculateCRC() //cyclic redundancy check should be calculated after the data is placed in the packet
//	{
//		return CRCvalue; //uses constant value 
//	}
//};
