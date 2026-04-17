#include "Packet.h"
#include "CRC32.h"

// Constructor.
Communication::Packet::Packet() {
	this->data = nullptr;

	this->txBuffer = nullptr;

	this->CRC = 0U;

	(void)std::memset(&(this->pktHead), 0, sizeof(PacketHeader));
};

Communication::Packet::Packet(const char* src) {
	this->data = nullptr;

	this->txBuffer = nullptr;

	this->CRC = 0U;

	(void)std::memset(&(this->pktHead), 0, sizeof(PacketHeader));

	if (src != nullptr) {
		(void)std::memcpy(&(this->pktHead), src, sizeof(PacketHeader));

		this->data = new char[this->pktHead.Length];

		(void)std::memset(this->data, 0, this->pktHead.Length);

		(void)std::memcpy(this->data, src + sizeof(PacketHeader), this->pktHead.Length);	//-V2563

		(void)std::memcpy(&(this->CRC), src + sizeof(PacketHeader) + this->pktHead.Length, sizeof(this->CRC));	//-V2563
	};
};

// Destructor.
Communication::Packet::~Packet() {
	delete[] this->data;
	this->data = nullptr;

	delete[] this->txBuffer;
	this->txBuffer = nullptr;
};

// Copy Constructor - Deep Copy.
Communication::Packet::Packet(const Packet& pkt) {
	this->pktHead = pkt.pktHead;
	this->CRC = pkt.CRC;
	this->data = nullptr;
	this->txBuffer = nullptr;

	if ((pkt.data != nullptr) && (this->pktHead.Length > 0U)) {
		this->data = new char[this->pktHead.Length];

		(void)std::memcpy(this->data, pkt.data, this->pktHead.Length);
	};
};


// Copy Assignment.
Communication::Packet& Communication::Packet::operator=(const Packet& pkt) {
	if (this != &pkt) {
		delete[] this->data;
		this->data = nullptr;

		delete[] this->txBuffer;
		this->txBuffer = nullptr;

		this->pktHead = pkt.pktHead;
		this->CRC = pkt.CRC;

		if ((pkt.data != nullptr) && (this->pktHead.Length > 0U)) {
			this->data = new char[this->pktHead.Length];

			(void)std::memcpy(this->data, pkt.data, this->pktHead.Length);
		};
	};

	return *this;
};

void Communication::Packet::SetData(const char* srcData, unsigned int size) {
	if ((srcData != nullptr) && (size > 0U)) {
		delete[] this->data;
		this->data = nullptr;

		this->data = new char[size];

		(void)std::memcpy(this->data, srcData, size);

		this->pktHead.Length = size;

		this->CRC = CalculateCRC();
	};
};

char* Communication::Packet::SerializeData(unsigned int& totalSize) {
	totalSize = sizeof(PacketHeader) + this->pktHead.Length + sizeof(this->CRC);

	delete[] this->txBuffer;
	this->txBuffer = nullptr;

	this->txBuffer = new char[totalSize];

	if (this->txBuffer != nullptr) {
		(void)std::memset(this->txBuffer, 0, totalSize);

		(void)std::memcpy(this->txBuffer, &(this->pktHead), sizeof(PacketHeader));

		(void)std::memcpy(this->txBuffer + sizeof(PacketHeader), this->data, this->pktHead.Length);	//-V2563

		(void)std::memcpy(this->txBuffer + sizeof(PacketHeader) + this->pktHead.Length, &(this->CRC), sizeof(this->CRC));	//-V2563
	};

	return this->txBuffer;
};

void Communication::Packet::DeserializeData(const char* rxBuffer) {
	if (rxBuffer != nullptr) {
		delete[] this->data;
		this->data = nullptr;

		(void)std::memcpy(&(this->pktHead), rxBuffer, sizeof(PacketHeader));

		
		this->data = new char[this->pktHead.Length];

		(void)std::memset(this->data, 0, this->pktHead.Length);

		(void)std::memcpy(this->data, rxBuffer + sizeof(PacketHeader), this->pktHead.Length);	//-V2563

		(void)std::memcpy(&(this->CRC), rxBuffer + sizeof(PacketHeader) + this->pktHead.Length, sizeof(this->CRC));	//-V2563
	};
};

void Communication::Packet::SetFlightID(unsigned int value) {
	this->pktHead.FlightID = value;
};

void Communication::Packet::SetMessageType(unsigned int value) {
	this->pktHead.MessageType = value;
};

void Communication::Packet::SetTimeStamp(uint32_t value) {
	this->pktHead.TimeStamp = value;
};

void Communication::Packet::DisplayInFlightSide(std::ostream& os) {
	os << std::dec;

	os << "Ground Control | ";

	(void)os.write(this->data, this->pktHead.Length);

	os << std::endl;
};

void Communication::Packet::DisplayGroundControlSide(std::ostream& os) {
	os << std::dec;

	os << this->pktHead.FlightID << " | "; 
	
	(void)os.write(this->data, this->pktHead.Length);

	os << std::endl;
};

uint32_t Communication::Packet::CalculateCRC() const {
	// Contiguous buffer of Header + Body.
	char* tempBuffer = new char[sizeof(PacketHeader) + this->pktHead.Length];

	(void)std::memset(tempBuffer, 0, sizeof(PacketHeader) + this->pktHead.Length);

	(void)std::memcpy(tempBuffer, &(this->pktHead), sizeof(PacketHeader));

	(void)std::memcpy(tempBuffer + sizeof(PacketHeader), this->data, this->pktHead.Length); //-V2563

	uint32_t crc = Checksum::CRC32::Calculate(tempBuffer, (sizeof(PacketHeader) + this->pktHead.Length));

	delete[] tempBuffer;
	tempBuffer = nullptr;

	return crc;
};

const char* Communication::Packet::GetData() {
	return this->data;
};

unsigned int Communication::Packet::GetBodyLength() {
	return this->pktHead.Length;
};