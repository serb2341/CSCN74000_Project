#include "Packet.h"
#include "CRC32.h"

// Constructor.
Packet::Packet() {
	this->data = nullptr;

	this->txBuffer = nullptr;

	this->CRC = 0U;

	std::memset(&(this->pktHead), 0, sizeof(PacketHeader));
};

Packet::Packet(const char* src) {
	this->data = nullptr;

	this->txBuffer = nullptr;

	this->CRC = 0U;

	std::memset(&(this->pktHead), 0, sizeof(PacketHeader));

	if (src != nullptr) {
		std::memcpy(&(this->pktHead), src, sizeof(PacketHeader));

		this->data = new char[this->pktHead.Length];

		std::memset(this->data, 0, this->pktHead.Length);

		std::memcpy(this->data, src + sizeof(PacketHeader), this->pktHead.Length);

		std::memcpy(&(this->CRC), src + sizeof(PacketHeader) + this->pktHead.Length, sizeof(this->CRC));
	};
};

// Destructor.
Packet::~Packet() {
	delete[] this->data;
	this->data = nullptr;

	delete[] this->txBuffer;
	this->txBuffer = nullptr;
};

// Copy Constructor - Deep Copy.
Packet::Packet(const Packet& pkt) {
	this->pktHead = pkt.pktHead;
	this->CRC = pkt.CRC;
	this->data = nullptr;
	this->txBuffer = nullptr;

	if ((pkt.data != nullptr) && (this->pktHead.Length > 0U)) {
		this->data = new char[this->pktHead.Length];

		std::memcpy(this->data, pkt.data, this->pktHead.Length);
	};
};


// Copy Assignment.
Packet& Packet::operator=(const Packet& pkt) {
	if (this != &pkt) {
		delete[] this->data;
		this->data = nullptr;

		delete[] this->txBuffer;
		this->txBuffer = nullptr;

		this->pktHead = pkt.pktHead;
		this->CRC = pkt.CRC;

		if ((pkt.data != nullptr) && (this->pktHead.Length > 0U)) {
			this->data = new char[this->pktHead.Length];

			std::memcpy(this->data, pkt.data, this->pktHead.Length);
		};
	};

	return *this;
};

void Packet::SetData(const char* srcData, unsigned int size) {
	if ((srcData != nullptr) && (size > 0U)) {
		delete[] this->data;
		this->data = nullptr;

		this->data = new char[size];

		std::memcpy(this->data, srcData, size);

		this->pktHead.Length = size;

		this->CRC = CalculateCRC();
	};
};

char* Packet::SerializeData(unsigned int& totalSize) {
	totalSize = sizeof(PacketHeader) + this->pktHead.Length + sizeof(this->CRC);

	delete[] this->txBuffer;
	this->txBuffer = nullptr;

	this->txBuffer = new char[totalSize];

	if (this->txBuffer != nullptr) {
		std::memset(this->txBuffer, 0, totalSize);

		std::memcpy(this->txBuffer, &(this->pktHead), sizeof(PacketHeader));

		std::memcpy(this->txBuffer + sizeof(PacketHeader), this->data, this->pktHead.Length);

		std::memcpy(this->txBuffer + sizeof(PacketHeader) + this->pktHead.Length, &(this->CRC), sizeof(this->CRC));
	};

	return this->txBuffer;
};

void Packet::DeserializeData(const char* rxBuffer) {
	if (rxBuffer != nullptr) {
		delete[] this->data;
		this->data = nullptr;

		std::memcpy(&(this->pktHead), rxBuffer, sizeof(PacketHeader));

		
		this->data = new char[this->pktHead.Length];

		std::memset(this->data, 0, this->pktHead.Length);

		std::memcpy(this->data, rxBuffer + sizeof(PacketHeader), this->pktHead.Length);

		std::memcpy(&(this->CRC), rxBuffer + sizeof(PacketHeader) + this->pktHead.Length, sizeof(this->CRC));
	};
};

void Packet::SetFlightID(unsigned int value) {
	this->pktHead.FlightID = value;
};

void Packet::SetMessageType(unsigned int value) {
	this->pktHead.MessageType = value;
};

void Packet::SetTimeStamp(uint32_t value) {
	this->pktHead.TimeStamp = value;
};

void Packet::DisplayInFlightSide(std::ostream& os) {
	os << std::dec;

	os << "Ground Control | ";

	os.write(this->data, this->pktHead.Length);

	os << std::endl;
};

void Packet::DisplayGroundControlSide(std::ostream& os) {
	os << std::dec;

	os << this->pktHead.FlightID << " | "; 
	
	os.write(this->data, this->pktHead.Length);

	os << std::endl;
};

uint32_t Packet::CalculateCRC() const {
	// Contiguous buffer of Header + Body.
	char* tempBuffer = new char[sizeof(PacketHeader) + this->pktHead.Length];

	std::memset(tempBuffer, 0, sizeof(PacketHeader) + this->pktHead.Length);

	std::memcpy(tempBuffer, &(this->pktHead), sizeof(PacketHeader));

	std::memcpy(tempBuffer + sizeof(PacketHeader), this->data, this->pktHead.Length);

	uint32_t crc = CRC32::Calculate(tempBuffer, (sizeof(PacketHeader) + this->pktHead.Length));

	delete[] tempBuffer;
	tempBuffer = nullptr;

	return crc;
};

const char* Packet::GetData() {
	return this->data;
};

unsigned int Packet::GetBodyLength() {
	return this->pktHead.Length;
};