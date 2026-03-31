#include "InFlightClient.h"
#include "PacketHeader.h"
#include "VerificationPacket.h"
#include "Packet.h"
#include "CRC32.h"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>

InFlightClient::InFlightClient() {
	this->clientSocket = INVALID_SOCKET;

	this->isRunning = false;
};

InFlightClient::~InFlightClient() {
	this->Shutdown();
};

bool InFlightClient::LoadConfig(const std::string& configPath) {
	std::ifstream configFile(configPath);

	if (!configFile.is_open()) {
		std::cerr << "[InFlightClient] Could not open config file: " << configPath << std::endl;

		return false;
	};

	std::string line;

	while (std::getline(configFile, line)) {
		// Skip empty lines and comments (lines starting with #)
		if (line.empty() || line[0] == '#')
		{
			continue;
		};

		size_t delimPos = line.find('=');

		if (delimPos == std::string::npos) {
			continue;		// Its not a valid key=value line.
		};

		std::string key = line.substr(0, delimPos);
		std::string value = line.substr(delimPos + 1);


		if (key == "SECRET") {
			this->sharedSecret = value;

			std::cout << "[InFlightClient] Shared secret loaded from config." << std::endl;

			return true;
		};
	};

	std::cerr << "[InFlightClient] SECRET key not found in config file." << std::endl;

	return false;
};

bool InFlightClient::InitializeWinsock() {
	WSADATA wsaData;

	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) {
		std::cerr << "WSAStartup Failed. Error: " << result << std::endl;

		return false;
	};

	return true;
};

bool InFlightClient::CreateSocket() {
	// Creating a TCP Socket.
	this->clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (this->clientSocket == INVALID_SOCKET) {
		std::cerr << "Socket() failed. Error: " << WSAGetLastError() << std::endl;

		return false;
	};

	// Bind to all interfaces on SERVER_PORT.
    sockaddr_in SvrAddr;
    SvrAddr.sin_family = AF_INET;						//Address family type itnernet
    SvrAddr.sin_port = htons(54000);					//port (host to network conversion)
    SvrAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //IP address
	
	int result = connect(this->clientSocket, reinterpret_cast<sockaddr*>(&SvrAddr), sizeof(SvrAddr));

	if (result == SOCKET_ERROR) {
		std::cerr << "connect() failed. Error: " << WSAGetLastError() << std::endl;

		this->CloseSocket(&(this->clientSocket));

		return false;
	};
	return true;
};


// ============================================================
//  Handshake
// ============================================================

uint32_t InFlightClient::ComputeSignature(uint32_t randomNumber) const {
	std::string payload = this->sharedSecret;

	payload.append((const char*)(&randomNumber), sizeof(uint32_t));

	return CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
};

bool InFlightClient::PerformHandshake(SOCKET clientSocket, const std::string& clientName) {
	// ----------------------------------------------------------------
		// STEP 1: Send the client's CHALLENGE packet.
		// ----------------------------------------------------------------
	ChallengePacket clientChallenge{};
	clientChallenge.Type = static_cast<uint32_t>(VerificationPacketType::CHALLENGE);
	clientChallenge.Random = static_cast<uint32_t>(rand());
	// CRC-32 covers Type + Random (8 bytes)
	clientChallenge.CRC32 = CRC32::Calculate(reinterpret_cast<const char*>(&clientChallenge), sizeof(uint32_t) + sizeof(uint32_t));

	int bytesSent = send(clientSocket, reinterpret_cast<const char*>(&clientChallenge), sizeof(ChallengePacket), 0);
	if (bytesSent != sizeof(ChallengePacket)) {
		std::cerr << "[Handshake] Step 1: Failed to send challenge. Error: " << WSAGetLastError() << std::endl;
		return false;
	}
	std::cout << "[Handshake] Step 1: Challenge sent." << std::endl;


	// ----------------------------------------------------------------
	// STEP 2: Receive the Server's RESPONSE and validate signature.
	// ----------------------------------------------------------------
	ResponsePacket serverResponse{};
	int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&serverResponse), sizeof(ResponsePacket), MSG_WAITALL);

	if (bytesReceived != sizeof(ResponsePacket)) {
		std::cerr << "[Handshake] Step 2: Failed to receive response. Error: " << WSAGetLastError() << std::endl;
		return false;
	}

	// Validate Type
	if (static_cast<VerificationPacketType>(serverResponse.Type) != VerificationPacketType::RESPONSE) {
		std::cerr << "[Handshake] Step 2: Unexpected packet type." << std::endl;
		return false;
	}

	// Validate CRC-32 (Type + Signature)
	uint32_t expectedSvrResponseCRC = CRC32::Calculate(reinterpret_cast<const char*>(&serverResponse), sizeof(uint32_t) + sizeof(uint32_t));
	if (serverResponse.CRC32 != expectedSvrResponseCRC) {
		std::cerr << "[Handshake] Step 2: CRC-32 validation failed." << std::endl;
		return false;
	}

	// Validate Signature
	uint32_t expectedSvrSignature = ComputeSignature(clientChallenge.Random);
	if (serverResponse.Signature != expectedSvrSignature) {
		std::cerr << "[Handshake] Step 2: Signature mismatch. Server failed authentication." << std::endl;
		return false;
	}
	std::cout << "[Handshake] Step 2: Server response validated." << std::endl;


	// ----------------------------------------------------------------
	// STEP 3: Receive the Server's CHALLENGE.
	// ----------------------------------------------------------------
	ChallengePacket serverChallenge{};
	bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&serverChallenge), sizeof(ChallengePacket), MSG_WAITALL);

	if (bytesReceived != sizeof(ChallengePacket)) {
		std::cerr << "[Handshake] Step 3: Failed to receive server challenge. Error: " << WSAGetLastError() << std::endl;
		return false;
	}

	// Validate Type
	if (static_cast<VerificationPacketType>(serverChallenge.Type) != VerificationPacketType::CHALLENGE) {
		std::cerr << "[Handshake] Step 3: Unexpected packet type." << std::endl;
		return false;
	}

	// Validate CRC-32
	uint32_t expectedSvrChallengeCRC = CRC32::Calculate(reinterpret_cast<const char*>(&serverChallenge), sizeof(uint32_t) + sizeof(uint32_t));
	if (serverChallenge.CRC32 != expectedSvrChallengeCRC) {
		std::cerr << "[Handshake] Step 3: CRC-32 validation failed." << std::endl;
		return false;
	}
	std::cout << "[Handshake] Step 3: Server challenge received and validated." << std::endl;


	// ----------------------------------------------------------------
	// STEP 4: Send the client's RESPONSE.
	// ----------------------------------------------------------------
	ResponsePacket clientResponse{};
	clientResponse.Type = static_cast<uint32_t>(VerificationPacketType::RESPONSE);
	clientResponse.Signature = ComputeSignature(serverChallenge.Random);
	clientResponse.CRC32 = CRC32::Calculate(reinterpret_cast<const char*>(&clientResponse), sizeof(uint32_t) + sizeof(uint32_t));

	bytesSent = send(clientSocket, reinterpret_cast<const char*>(&clientResponse), sizeof(ResponsePacket), 0);
	if (bytesSent != sizeof(ResponsePacket)) {
		std::cerr << "[Handshake] Step 4: Failed to send response. Error: " << WSAGetLastError() << std::endl;
		return false;
	}
	std::cout << "[Handshake] Step 4: Response sent. Handshake complete." << std::endl;

	return true;
}



// ============================================================
//  Packet Validation
// ============================================================

bool InFlightClient::ValidatePacket(const char* buffer, unsigned int totalSize) const
{
	// ---- Structural check ----
	// totalSize must be at least Header + CRC tail (body can be zero length).
	if (totalSize < (sizeof(PacketHeader) + sizeof(uint32_t))) {
		std::cerr << "[Validation] Packet too small to be valid." << std::endl;

		return false;
	}

	// Extracting the header to read Length.
	PacketHeader pktHeader{};
	std::memcpy(&pktHeader, buffer, sizeof(PacketHeader));

	// Verify the declared length matches the actual received size
	unsigned int expectedSize = sizeof(PacketHeader) + pktHeader.Length + sizeof(uint32_t);

	if (totalSize != expectedSize) {
		std::cerr << "[Validation] Structural mismatch: expected " << expectedSize << " bytes, got " << totalSize << " bytes." << std::endl;

		return false;
	}

	// ---- CRC-32 integrity check ----
	// CRC-32 is computed over Header + Body (everything except the CRC tail itself)
	unsigned int payloadSize = sizeof(PacketHeader) + pktHeader.Length;

	uint32_t computedCRC = CRC32::Calculate(buffer, payloadSize);

	// The CRC tail sits at the very end of the buffer
	uint32_t receivedCRC = 0U;
	std::memcpy(&receivedCRC, buffer + payloadSize, sizeof(uint32_t));

	if (computedCRC != receivedCRC) {
		std::cerr << "[Validation] CRC-32 mismatch. Packet may be corrupted or tampered with." << std::endl;

		return false;
	}

	return true;
};


void InFlightClient::CloseSocket(SOCKET* socketPtr) {
	if (*socketPtr != INVALID_SOCKET) {
		closesocket(*socketPtr);

		*socketPtr = INVALID_SOCKET;

		socketPtr = nullptr;
	};
};

bool InFlightClient::Initialize(int flightID) {
	// Seed random number generator for challenge generation.
	srand(static_cast<unsigned int>(time(nullptr)));

	if (!this->LoadConfig("server_config.txt")) {
		std::cerr << "[InFlightClient] Failed to load config. Ensure server_config.txt exists with SECRET=<value>." << std::endl;

		return false;
	};

	if (!this->InitializeWinsock()) {
		std::cerr << "[InFlightClient] Failed to initialize Winsock." << std::endl;

		return false;
	};

	if (!this->CreateSocket()) {
		std::cerr << "[InFlightClient] Failed to create listen socket." << std::endl;

		WSACleanup();

		return false;
	};

	this->isRunning = true;
	this->flightID = flightID;

	std::cout << "[InFlightClient] Initialized. Connected on port " << SERVER_PORT << std::endl;

	return true;
};

void InFlightClient::ValidateConnection() {
	if (!this->PerformHandshake(this->clientSocket, "In Flight Client")) {
		std::cerr << "[InFlightClient] server failed handshake. Dropping connection." << std::endl;

		this->CloseSocket(&(this->clientSocket));

		this->Shutdown();

		return;
	};

	std::cout << "[InFlightClient] Server handshake successful." << std::endl;
};

void InFlightClient::sendMessage(int messageType, std::string message) {
	Packet newPkt; //Packet object is created
	newPkt.SetFlightID(this->flightID); //populates the newPkt object with the data 
	newPkt.SetMessageType(messageType); //populates the newPkt object with the data
	newPkt.SetTimeStamp(static_cast<unsigned char>(time(nullptr)));
	unsigned int Size = 0;
	newPkt.SetData(message.c_str(), message.size());
	char* Tx = newPkt.SerializeData(Size);
	if (send(this->clientSocket, Tx, Size, 0) == SOCKET_ERROR)
	{
		std::cout << "Error sending connection packet\n";
	}
	logger.Log(message.c_str());
}

void InFlightClient::reciecveMessage()
{
	char rxBuffer[512] = {};
	int bytes = recv(this->clientSocket, rxBuffer, sizeof(rxBuffer), 0);
	if (bytes <= 0) {
		std::cout << "Error: No data recieved." << std::endl; //Error checking, no data was sent
	}
	Packet rxPkt(rxBuffer);
	// Performing a validation for corrupted packets. If the CRC check fails, we skip processing this packet and wait for the next one.
	if (rxPkt.CalculateCRC() != 0xFF00FF00U) { // Using the constant from Packet.h
		std::cout << "[Warning] Corrupted packet recieved!\n";
	}
	rxPkt.DisplayInFlightSide(std::cout);
	logger.Log(rxPkt.GetData());
}

void InFlightClient::Run() {
	sendMessage(0, "Connected");
	reciecveMessage();
	
	// Main loop for communication
	bool running = true;
	while (running)
	{
		std::cout << "\nSelect option:\n";
		std::cout << "1) Sent Message\n";
		std::cout << "2) Send Telemetry File\n";
		std::cout << "3) Exit\n";
		std::cout << "> ";

		// Get clients choice
		int choice;
		std::cin >> choice;
		(void)std::cin.ignore();

		// Different sends based on choice
		if (choice == 1) // Send one regular message at a time ***US-2
		{
			std::string msg;
			std::cout << "Enter message: ";
			(void)std::getline(std::cin, msg); // inflight client enters message

			sendMessage(0, msg);
		}
		else if (choice == 2)
		{
			std::ifstream file("telemetry.txt");

			if (!file)
			{
				std::cout << "Telemetry file not found.\n";
				continue;
			}

			std::string line;

			std::cout << "Sending telemetry...\n";

			while (std::getline(file, line))
			{
				std::string packet = "TELEMETRY|" + line;
				sendMessage(1, packet.c_str());
				
				Sleep(10); // small delay to prevent packet flooding
			}

			std::string endPacket = "TELEMETRY_END";
			sendMessage(1, endPacket.c_str());
		}
		else
		{
			// Handle third condition and any other condition
			break;
		}

		// Recieve response from groun control
		reciecveMessage();
	}
};

void InFlightClient::Shutdown() {
	this->isRunning = false;

	// Here we are closing all the sockets.
	this->CloseSocket(&(this->clientSocket));

	WSACleanup();

	std::cout << "[InFlightClient] Shutdown complete." << std::endl;
};

