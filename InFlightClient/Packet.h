#pragma once
#include <memory>
#include <iostream>
#include <fstream>

const unsigned int CRCvalue = 0xFF00FF00;


class Packet
{
	struct Header
	{
		unsigned int FlightID;				//Source ID
		unsigned int MessageType;			//Line number of the input file being transmitted
		unsigned char TimeStamp;					//Number of characters in the line
		unsigned int Length;
	} Head;
	char* Data;							//The data bytes
	unsigned int CRC;					//Cyclic Redundancy Check

	char* TxBuffer;

public:
	Packet() : Data(nullptr), TxBuffer(nullptr) { memset(&Head, 0, sizeof(Head));};		//Default Constructor - Safe State
	void SetFlightID(unsigned int value) { Head.FlightID = value; };		//Sets the line number within the object
	void SetMessageType(int value) { Head.MessageType = value; };
	void SetTimeStamp(char value) { Head.TimeStamp = value; };

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

	Packet(char* src) //Overloaded constructor that takes character pointer src and uses it to populate the packet
	{
		if (src == nullptr)
		{
			Data = nullptr;
			TxBuffer = nullptr;
			return;
		}
		
		memcpy(&Head, src, sizeof(Head)); //copies the first two bytes of the src character array to the Head of the packet

		Data = new char[Head.Length + sizeof(char)]; //assignes new space in memory to hold a char array that is the dataSize+sizeof(char) ->for the termination character

		memcpy(Data, src + sizeof(Head), Head.Length); //copies memory from the src o the Data variable
		Data[Head.Length] = '\0'; //adds termination character to end of the Data array

		memcpy(&CRC, src + sizeof(Head) + Head.Length, sizeof(unsigned int));  //copies memory from the src to the CRC variable

		TxBuffer = nullptr; //Initializes the TxBuffer
	}

	void SetData(char* srcData, int Size) //parameters are a char array and a length of the char array
	{
		if (Data != nullptr) //checks if data is already filled
		{
			delete[] Data; //deletes what is stored in data
		}

		Data = new char[Size]; //reserves enough space in memory for the Data
		memcpy(Data, srcData, Size); //copies the data in the secData char array into the Data variable 

		Head.Length = Size; //sets the Head.Length to the correct size

		CRC = CalculateCRC(); //calculates the CRC for the data
	};

	char* SerializeData(int& TotalSize) //Puts all of the data in one spot sequenitally
	{
		if (TxBuffer != nullptr) //checks if TxBuffer is already filled
		{
			delete[] TxBuffer; //deletes what is stored in TxBuffer
		}

		TotalSize = sizeof(Header) + Head.Length + sizeof(unsigned int); //calcualtes the amount of space needed to store all of the info in the Packet
		TxBuffer = new char[TotalSize]; //reserves enough space in memory for TxBuffer

		memcpy(TxBuffer, &Head, sizeof(Head)); //copies the memory of the Head into the start of the TxBuffer
		memcpy(TxBuffer + sizeof(Head), Data, Head.Length); //copies the memory of the Data into the TxBuffer after the Head
		memcpy(TxBuffer + sizeof(Head) + Head.Length, &CRC, sizeof(unsigned int)); //copies the memory of the CRC to the TxBuffer after the Data

		return TxBuffer; //returns the character array buffer to be sent to the Server
	};

	char* DeserializeData(char* rxBuffer) //Extracts data
	{
		if (Data != nullptr)
		{
			delete[] Data;
			Data = nullptr;
		}

		memcpy(&Head, rxBuffer, sizeof(Head));

		if (Head.Length > 0U)
		{
			Data = new char[Head.Length + 1U];

			memcpy(Data, rxBuffer + sizeof(Head), Head.Length);
			Data[Head.Length] = '\0';
		}

		memcpy(&CRC, rxBuffer + sizeof(Head) + Head.Length, sizeof(unsigned int));
	};

	unsigned int CalculateCRC() //cyclic redundancy check should be calculated after the data is placed in the packet
	{
		return CRCvalue; //uses constant value 
	}

	~Packet()
	{
		delete[] Data;
		delete[] TxBuffer;
	}
};
