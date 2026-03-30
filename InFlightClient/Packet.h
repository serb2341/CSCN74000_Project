#pragma once
#include <memory>
#include <iostream>
#include <fstream>

const unsigned int CRCvalue = 0xFF00FF00;
const unsigned int MAX_DATA_SIZE = 256;

class Packet
{
	struct Header
	{
		unsigned int FlightID;				//Source ID
		unsigned int MessageType;			//Line number of the input file being transmitted
		unsigned char TimeStamp;					//Number of characters in the line
		unsigned int Length;
	} Head;
	char Data[MAX_DATA_SIZE];							//The data bytes
	unsigned int CRC;					//Cyclic Redundancy Check

	char TxBuffer[sizeof(Head) + MAX_DATA_SIZE + sizeof(unsigned int)];

public:
	Packet() { 
		memset(&Head, 0, sizeof(Head));
		memset(Data, 0, sizeof(Data));
		memset(TxBuffer, 0, sizeof(TxBuffer));
	} //Default Constructor - Safe State
	
	void SetFlightID(unsigned int value) { Head.FlightID = value; };		//Sets the line number within the object
	void SetMessageType(unsigned int value) { Head.MessageType = value; };
	void SetTimeStamp(unsigned char value) { Head.TimeStamp = value; };

	void DisplayInFlightSide(std::ostream& os)
	{
		os << std::dec;
		os << "Ground Control | " << Data << std::endl;
	}

	void DisplayGroundControlSide(std::ostream& os)
	{
		os << std::dec;
		os << Head.FlightID << " | " << Data  << std::endl;
	}

	Packet(const char* src) //Overloaded constructor that takes character pointer src and uses it to populate the packet
	{
		memset(&Head, 0, sizeof(Head));
		memset(Data, 0, sizeof(Data));
		
		if (src == nullptr)
		{
			return;
		}
		
		memcpy(&Head, src, sizeof(Head)); //copies the first two bytes of the src character array to the Head of the packet

		if (Head.Length > MAX_DATA_SIZE)
		{
			Head.Length = MAX_DATA_SIZE; 
		}

		memcpy(Data, src + sizeof(Head), Head.Length); //copies memory from the src o the Data variable
		Data[Head.Length] = '\0'; //adds termination character to end of the Data array

		memcpy(&CRC, src + sizeof(Head) + Head.Length, sizeof(unsigned int));  //copies memory from the src to the CRC variable
	}

	void SetData(const char* srcData, unsigned int Size) //parameters are a char array and a length of the char array
	{
		if (srcData == nullptr) //checks if data is empty
		{
			return;
		}

		if (Size > MAX_DATA_SIZE) //ensures data is not too long
		{
			Size = MAX_DATA_SIZE;
		}
		
		memcpy(Data, srcData, Size);
		Data[Head.Length] = '\0'; //adds termination character to end of the Data array

		Head.Length = Size; //sets the Head.Length to the correct size

		CRC = CalculateCRC(); //calculates the CRC for the data
	};

	char* SerializeData(unsigned int& TotalSize) //Puts all of the data in one spot sequenitally
	{
		TotalSize = sizeof(Header) + Head.Length + sizeof(unsigned int); //calcualtes the amount of space needed to store all of the info in the Packet
		memcpy(TxBuffer, &Head, sizeof(Head)); //copies the memory of the Head into the start of the TxBuffer
		memcpy(TxBuffer + sizeof(Head), Data, Head.Length); //copies the memory of the Data into the TxBuffer after the Head
		memcpy(TxBuffer + sizeof(Head) + Head.Length, &CRC, sizeof(unsigned int)); //copies the memory of the CRC to the TxBuffer after the Data

		return TxBuffer; //returns the character array buffer to be sent to the Server
	};

	char* DeserializeData(const char* rxBuffer) //Extracts data
	{
		if (rxBuffer == nullptr) //checks if data is empty
		{
			return;
		}

		memcpy(&Head, rxBuffer, sizeof(Head));

		if (Head.Length > MAX_DATA_SIZE) //ensures data is not too long
		{
			Head.Length = MAX_DATA_SIZE;
		}

		memcpy(Data, rxBuffer + sizeof(Head), Head.Length);
		Data[Head.Length] = '\0';

		memcpy(&CRC, rxBuffer + sizeof(Head) + Head.Length, sizeof(unsigned int));
	};

	unsigned int CalculateCRC() //cyclic redundancy check should be calculated after the data is placed in the packet
	{
		return CRCvalue; //uses constant value 
	}
};
