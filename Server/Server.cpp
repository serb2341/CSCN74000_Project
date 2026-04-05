#include "Server.h"
#include "PacketHeader.h"
#include "VerificationPacket.h"
#include "CRC32.h"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>

Server::Server() {
	this->listeningSocket = INVALID_SOCKET;
	this->groundControlSocket = INVALID_SOCKET;
	this->airplaneSocket = INVALID_SOCKET;

	this->isRunning = false;

	this->serverState = ServerState::INITIALIZING;
};

Server::~Server() {
	this->Shutdown();
};

bool Server::LoadConfig(const std::string& configPath) {
	std::ifstream configFile(configPath);

	if (!configFile.is_open()) {
		std::cerr << "[Server] Could not open config file: " << configPath << std::endl;

		return false;
	};

	bool secretFound = false;
	bool logFileFound = false;

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

			std::cout << "[Server] Shared secret loaded from config." << std::endl;

			secretFound = true;
		}

		else if (key == "LOG_FILE") {
			this->logFilePath = value;

			std::cout << "[Server] Log file path loaded: " << value << std::endl;

			logFileFound = true;
		};
	};

	if (!secretFound) {
		std::cerr << "[Server] SECRET key not found in config." << std::endl;
	};
		

	if (!logFileFound) {
		std::cerr << "[Server] LOG_FILE key not found in config." << std::endl;
	};
		
	return secretFound && logFileFound;
};

bool Server::InitializeWinsock() {
	WSADATA wsaData;

	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) {
		std::cerr << "WSAStartup Failed. Error: " << result << std::endl;

		return false;
	};

	return true;
};

bool Server::CreateListeningSocket() {
	// Creating a TCP Socket.
	this->listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (this->listeningSocket == INVALID_SOCKET) {
		std::cerr << "Socket() failed. Error: " << WSAGetLastError() << std::endl;

		return false;
	};

	// Bind to all interfaces on SERVER_PORT.
	sockaddr_in serverAddr{};
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(static_cast<u_short>(SERVER_PORT));

	int result = bind(this->listeningSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));

	if (result == SOCKET_ERROR) {
		std::cerr << "Bind() failed. Error: " << WSAGetLastError() << std::endl;

		this->CloseSocket(&(this->listeningSocket));

		return false;
	};

	// Allowing exactly 2 pending connections in the backlog.
	result = listen(this->listeningSocket, 2);

	if (result == SOCKET_ERROR)
	{
		std::cerr << "Listen() failed. Error: " << WSAGetLastError() << std::endl;

		CloseSocket(&(this->listeningSocket));

		return false;
	};

	return true;
};


// ============================================================
//  Handshake
// ============================================================

uint32_t Server::ComputeSignature(uint32_t randomNumber) const {
	std::string payload = this->sharedSecret;

	payload.append((const char*)(&randomNumber), sizeof(uint32_t));

	return CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
};

bool Server::PerformHandshake(SOCKET clientSocket, const std::string& clientName) {
	// ----------------------------------------------------------------
	// STEP 1: Receive the client's CHALLENGE packet.
	// ----------------------------------------------------------------
	ChallengePacket clientChallenge{};

	int bytesReceived = recv(clientSocket, (char*)(&clientChallenge), sizeof(ChallengePacket), MSG_WAITALL);

	if (bytesReceived != sizeof(ChallengePacket)) {
		this->logger.LogSecurityException(clientName, "Step 1: Failed to receive challenge packet.");

		std::cerr << "[" << clientName << "] Handshake Step 1: Failed to receive challenge. Error: " << WSAGetLastError() << std::endl;

		return false;
	};

	// Validating the challenge packet type.
	if (static_cast<VerificationPacketType>(clientChallenge.Type) != VerificationPacketType::CHALLENGE) {
		this->logger.LogSecurityException(clientName, "Step 1: Unexpected packet type (expected CHALLENGE).");

		std::cerr << "[" << clientName << "] Handshake Step 1: Unexpected packet type." << std::endl;

		return false;
	};

	// Validate CRC-32 of the challenge packet (covers Type + Random only)
	uint32_t expectedChallengeCRC = CRC32::Calculate(reinterpret_cast<const char*>(&clientChallenge), sizeof(uint32_t) + sizeof(uint32_t));			// Type + Random

	if (clientChallenge.CRC32 != expectedChallengeCRC) {
		this->logger.LogSecurityException(clientName, "Step 1: CRC-32 validation failed on challenge. Connection terminated.");

		std::cerr << "[" << clientName << "] Handshake Step 1: CRC-32 validation failed on challenge." << std::endl;

		return false;
	};

	// Log the received challenge (US-39: source, dest, header content).
	this->logger.LogHandshake(clientName, "SERVER", "CHALLENGE", clientChallenge.Random, "Random");

	std::cout << "[" << clientName << "] Handshake Step 1: Challenge received and validated." << std::endl;



	// ----------------------------------------------------------------
	// STEP 2: Send our RESPONSE — Hash(secret + client's random).
	// ----------------------------------------------------------------
	ResponsePacket serverResponse{};
	serverResponse.Type = static_cast<uint32_t>(VerificationPacketType::RESPONSE);
	serverResponse.Signature = this->ComputeSignature(clientChallenge.Random);

	serverResponse.CRC32 = CRC32::Calculate((const char*)(&serverResponse), (sizeof(uint32_t) + sizeof(uint32_t)));

	int bytesSent = send(clientSocket, (const char*)(&serverResponse), sizeof(ResponsePacket), 0);

	if (bytesSent != sizeof(ResponsePacket)) {
		this->logger.LogSecurityException(clientName, "Step 2: Failed to send response.");

		std::cerr << "[" << clientName << "] Handshake Step 2: Failed to send response. Error: " << WSAGetLastError() << std::endl;

		return false;
	};

	this->logger.LogHandshake("SERVER", clientName, "RESPONSE", serverResponse.Signature, "Signature");

	std::cout << "[" << clientName << "] Handshake Step 2: Response sent." << std::endl;



	// ----------------------------------------------------------------
	// STEP 3: Send our CHALLENGE to the client.
	// ----------------------------------------------------------------
	ChallengePacket serverChallenge{};
	serverChallenge.Type = static_cast<uint32_t>(VerificationPacketType::CHALLENGE);
	serverChallenge.Random = static_cast<uint32_t>(rand());									// Server's random number.

	// CRC-32 covers Type + Random
	serverChallenge.CRC32 = CRC32::Calculate((const char*)(&serverChallenge), (sizeof(uint32_t) + sizeof(uint32_t)));		// Type + Random.

	bytesSent = send(clientSocket, (const char*)(&serverChallenge), sizeof(ChallengePacket), 0);

	if (bytesSent != sizeof(ChallengePacket)) {
		this->logger.LogSecurityException(clientName, "Step 3: Failed to send challenge.");

		std::cerr << "[" << clientName << "] Handshake Step 3: Failed to send challenge. Error: " << WSAGetLastError() << std::endl;

		return false;
	};

	this->logger.LogHandshake("SERVER", clientName, "CHALLENGE", serverChallenge.Random, "Random");

	std::cout << "[" << clientName << "] Handshake Step 3: Challenge sent." << std::endl;



	// -------------------------------------------------------------------
	// STEP 4: Receive the client's RESPONSE and validate their signature.
	// -------------------------------------------------------------------
	ResponsePacket clientResponse{};

	bytesReceived = recv(clientSocket, (char*)(&clientResponse), sizeof(ResponsePacket), MSG_WAITALL);

	if (bytesReceived != sizeof(ResponsePacket)) {
		this->logger.LogSecurityException(clientName, "Step 4: Failed to receive response packet.");

		std::cerr << "[" << clientName << "] Handshake Step 4: Failed to receive response. Error: " << WSAGetLastError() << std::endl;

		return false;
	};

	// Validate the response packet type.
	if (static_cast<VerificationPacketType>(clientResponse.Type) != VerificationPacketType::RESPONSE) {
		this->logger.LogSecurityException(clientName, "Step 4: Unexpected packet type (expected RESPONSE). Connection terminated.");

		std::cerr << "[" << clientName << "] Handshake Step 4: Unexpected packet type." << std::endl;

		return false;
	};

	// Validate CRC-32 of the response packet (covers Type + Signature).
	uint32_t expectedResponseCRC = CRC32::Calculate((const char*)(&clientResponse), (sizeof(uint32_t) + sizeof(uint32_t)));			// Type + Signature

	if (clientResponse.CRC32 != expectedResponseCRC) {
		this->logger.LogSecurityException(clientName, "Step 4: CRC-32 validation failed on response. Connection terminated.");

		std::cerr << "[" << clientName << "] Handshake Step 4: CRC-32 validation failed on response." << std::endl;

		return false;
	};


	// Validating the client's signature against what we expect.
	uint32_t expectedSignature = this->ComputeSignature(serverChallenge.Random);

	if (clientResponse.Signature != expectedSignature) {
		this->logger.LogSecurityException(clientName, "Step 4: Signature mismatch. Client failed authentication. Connection terminated.");

		std::cerr << "[" << clientName << "] Handshake Step 4: Signature mismatch. Client failed authentication." << std::endl;

		return false;
	};

	this->logger.LogHandshake(clientName, "SERVER", "RESPONSE", clientResponse.Signature, "Signature");

	std::cout << "[" << clientName << "] Handshake Step 4: Response validated. Handshake complete." << std::endl;

	return true;
};


// ============================================================
//  Relay Loop
// ============================================================

void Server::RelayLoop(SOCKET sourceSocket, SOCKET destinationSocket, const std::string& clientName, const std::string& destinationName) {
	std::cout << "[" << clientName << "] Relay thread started." << std::endl;

	// Each relay thread owns its own ClientState — no shared state collision.
	ClientState clientState = ClientState::RECEIVING;

	while (this->isRunning) {
		// First we start with only receiving the Header of the data packet.
		char headerBuffer[sizeof(PacketHeader)];

		std::memset(headerBuffer, 0, sizeof(PacketHeader));

		int bytesReceived = recv(sourceSocket, headerBuffer, sizeof(headerBuffer), MSG_WAITALL);		// The flag tells Winsock to not return until all header bytes are here.

		if (bytesReceived == 0) {
			std::cout << "[" << clientName << "] Client disconnected." << std::endl;

			this->logger.LogDisconnect(clientName);

			break;
		}

		else if ((bytesReceived == SOCKET_ERROR) || (bytesReceived != sizeof(PacketHeader))) {
			if (this->isRunning) {
				std::cerr << "[" << clientName << "] Header recv() failed. Error: " << WSAGetLastError() << std::endl;

				this->logger.LogDisconnect(clientName);
			};

			break;
		};


		// We serialize the Header.
		PacketHeader pktHeader{};

		std::memcpy(&pktHeader, headerBuffer, sizeof(PacketHeader));

		// Initializing the total packet size.
		unsigned int totalPktSize = sizeof(PacketHeader) + pktHeader.Length + sizeof(uint32_t);

		// Allocating full buffer and Assembling full packet.
		char* recvBuffer = new char[totalPktSize];

		// Copying the already received Header.
		std::memcpy(recvBuffer, headerBuffer, sizeof(PacketHeader));

		bytesReceived = recv(sourceSocket, recvBuffer + sizeof(PacketHeader), (static_cast<int>(totalPktSize) - static_cast<int>(sizeof(PacketHeader))), MSG_WAITALL);

		if (bytesReceived == 0) {
			std::cout << "[" << clientName << "] Client disconnected during body recv." << std::endl;

			this->logger.LogDisconnect(clientName);

			std::memset(recvBuffer, 0, totalPktSize);

			delete[] recvBuffer;
			recvBuffer = nullptr;

			break;
		}

		else if ((bytesReceived == SOCKET_ERROR) || (static_cast<unsigned int>(bytesReceived) != (static_cast<int>(totalPktSize) - static_cast<int>(sizeof(PacketHeader))))) {
			if (this->isRunning) {
				std::cerr << "[" << clientName << "] Body recv() failed. Error: " << WSAGetLastError() << std::endl;

				this->logger.LogDisconnect(clientName);
			};

			std::memset(recvBuffer, 0, totalPktSize);

			delete[] recvBuffer;
			recvBuffer = nullptr;

			break;
		};


		Server::SetClientState(clientState, ClientState::PROCESSING, clientName);

		// Validating the structure and CRC-32 before forwarding.
		if (!this->ValidatePacket((const char*)recvBuffer, totalPktSize))
		{
			std::cerr << "[" << clientName << "] Packet failed validation. Dropping packet." << std::endl;

			std::memset(recvBuffer, 0, totalPktSize);

			delete[] recvBuffer;
			recvBuffer = nullptr;

			// Back to RECEIVING — relay stays alive, just this packet is dropped.
			Server::SetClientState(clientState, ClientState::RECEIVING, clientName);

			continue; // Drop this packet — do NOT forward it, keep the relay alive
		};

		// Log the validated packet header fields.
		this->logger.LogPacket(
			std::to_string(pktHeader.FlightID),  // Source = FlightID
			destinationName,                      // Dest = other client
			pktHeader.FlightID,
			pktHeader.MessageType,
			pktHeader.Length,
			pktHeader.TimeStamp);


		Server::SetClientState(clientState, ClientState::TRANSMITTING, clientName);

		// From here on, we are forwarding the data packet to the destination client.
		int bytesSent = send(destinationSocket, recvBuffer, totalPktSize, 0);

		if (bytesSent == SOCKET_ERROR) {
			std::cerr << "[" << clientName << "] send() failed. Error: " << WSAGetLastError() << std::endl;

			std::memset(recvBuffer, 0, totalPktSize);

			delete[] recvBuffer;
			recvBuffer = nullptr;

			break;
		};

		std::cout << "[" << clientName << "] Relayed " << totalPktSize << " bytes (Body length: " << pktHeader.Length << ")." << std::endl;


		std::memset(recvBuffer, 0, totalPktSize);

		delete[] recvBuffer;
		recvBuffer = nullptr;

		Server::SetClientState(clientState, ClientState::RECEIVING, clientName);
	};

	std::cout << "[" << clientName << "] Relay thread exiting." << std::endl;

	this->SetServerState(ServerState::DISCONNECTING);

	this->isRunning = false;

	this->CloseSocket(&(this->groundControlSocket));
	this->CloseSocket(&(this->airplaneSocket));
};



// ============================================================
//  Packet Validation
// ============================================================

bool Server::ValidatePacket(const char* buffer, unsigned int totalSize) const
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


void Server::CloseSocket(SOCKET* socketPtr) {
	if (*socketPtr != INVALID_SOCKET) {
		closesocket(*socketPtr);

		*socketPtr = INVALID_SOCKET;

		socketPtr = nullptr;
	};
};

bool Server::Initialize() {
	// Seed random number generator for challenge generation.
	srand(static_cast<unsigned int>(time(nullptr)));

	if (!this->LoadConfig("server_config.txt")) {
		std::cerr << "[Server] Failed to load config. Ensure server_config.txt exists with SECRET=<value>." << std::endl;

		return false;
	};

	// Start the logger thread before anything else so all events are captured.
	if (!this->logger.Start(this->logFilePath)) {
		std::cerr << "[Server] Failed to start logger." << std::endl;

		return false;
	};

	if (!this->InitializeWinsock()) {
		std::cerr << "[Server] Failed to initialize Winsock." << std::endl;

		return false;
	};

	if (!this->CreateListeningSocket()) {
		std::cerr << "[Server] Failed to create listen socket." << std::endl;

		WSACleanup();

		return false;
	};

	// Transition: INITIALIZING --> LISTENING
	this->SetServerState(ServerState::LISTENING);

	this->isRunning = true;

	// Log the initial LISTENING state.
	this->logger.LogStateTransition("SERVER", "INITIALIZING", "LISTENING");

	std::cout << "[Server] Initialized. Listening on port " << SERVER_PORT << std::endl;

	return true;
};

void Server::AcceptClients() {
	// 1st connection - Ground Control.
	std::cout << "[Server] Waiting for Ground Control to connect..." << std::endl;

	this->groundControlSocket = accept(this->listeningSocket, nullptr, nullptr);

	if (this->groundControlSocket == INVALID_SOCKET) {
		std::cerr << "[Server] accept() failed for Ground Control. Error: " << WSAGetLastError() << std::endl;

		this->Shutdown();

		return;
	};

	std::cout << "[Server] Ground Control connected. Performing handshake..." << std::endl;


	// Transition: LISTENING --> VERIFICATION
	this->SetServerState(ServerState::VERIFICATION);

	if (!this->PerformHandshake(this->groundControlSocket, "Ground Control")) {
		std::cerr << "[Server] Ground Control failed handshake. Dropping connection." << std::endl;

		this->CloseSocket(&(this->groundControlSocket));

		// Transition: VERIFICATION --> DISCONNECTING
		this->SetServerState(ServerState::DISCONNECTING);

		this->Shutdown();

		return;
	};


	// Transition: VERIFICATION --> AUTHENTICATED
	this->SetServerState(ServerState::AUTHENTICATED);

	std::cout << "[Server] Ground Control handshake successful." << std::endl;

	
	// 2nd connection - In-flight Airplane.
	std::cout << "[Server] Waiting for Airplane to connect..." << std::endl;

	// Transition: AUTHENTICATED --> LISTENING (waiting for 2nd client)
	this->SetServerState(ServerState::LISTENING);

	this->airplaneSocket = accept(this->listeningSocket, nullptr, nullptr);

	if (this->airplaneSocket == INVALID_SOCKET) {
		std::cerr << "[Server] accept() failed for In-flight Airplane. Error: " << WSAGetLastError() << std::endl;

		this->Shutdown();

		return;
	};

	std::cout << "[Server] Airplane connected. Performing handshake..." << std::endl;


	// Transition: LISTENING --> VERIFICATION
	this->SetServerState(ServerState::VERIFICATION);


	if (!this->PerformHandshake(this->airplaneSocket, "Airplane")) {
		std::cerr << "[Server] Airplane failed handshake. Dropping connection." << std::endl;

		this->CloseSocket(&(this->airplaneSocket));

		// Transition: VERIFICATION --> DISCONNECTING
		this->SetServerState(ServerState::DISCONNECTING);

		this->Shutdown();

		return;
	};

	// Transition: VERIFICATION --> AUTHENTICATED
	this->SetServerState(ServerState::AUTHENTICATED);

	std::cout << "[Server] Airplane handshake successful." << std::endl;
	std::cout << "[Server] Both clients connected. Starting relay threads." << std::endl;

	// Closing the listening socket because no more connections are needed.
	this->CloseSocket(&(this->listeningSocket));

	// Here we spawn one relay thread per client.

	// Ground Control Client Thread.
	this->groundControlThread = std::thread(&Server::RelayLoop, this, this->groundControlSocket, this->airplaneSocket, std::string("Ground Control"), std::string("In-flight Airplane"));

	// In-flight Airplane Client Thread.
	this->airplaneThread = std::thread(&Server::RelayLoop, this, this->airplaneSocket, this->groundControlSocket, std::string("In-flight Airplane"), std::string("Ground Control"));
};

void Server::Run() {
	// We block the main thread until both relay threads have exited.
	if (this->groundControlThread.joinable()) {
		this->groundControlThread.join();
	};

	if (this->airplaneThread.joinable()) {
		this->airplaneThread.join();
	};

	std::cout << "[Server] Both relay threads have exited. Server shutting down." << std::endl;
};

void Server::Shutdown() {
	this->isRunning = false;

	// Here we are closing all the sockets.
	this->CloseSocket(&(this->listeningSocket));
	this->CloseSocket(&(this->groundControlSocket));
	this->CloseSocket(&(this->airplaneSocket));

	if (this->groundControlThread.joinable()) {
		this->groundControlThread.join();
	};

	if (this->airplaneThread.joinable()) {
		this->airplaneThread.join();
	};

	this->logger.Stop();

	WSACleanup();

	std::cout << "[Server] Shutdown complete." << std::endl;
};

// Maps ServerState enum to a readable string for console output.
static const char* ServerStateToString(ServerState state) {
	switch (state) {
	case ServerState::INITIALIZING: return "INITIALIZING";
	case ServerState::LISTENING:     return "LISTENING";
	case ServerState::VERIFICATION:  return "VERIFICATION";
	case ServerState::AUTHENTICATED: return "AUTHENTICATED";
	case ServerState::DISCONNECTING: return "DISCONNECTING";
	default:                         return "UNKNOWN";
	};
};

void Server::SetServerState(ServerState newState) {
	ServerState oldState = this->serverState.load();

	this->serverState.store(newState);

	std::string from = ServerStateToString(oldState);
	std::string to = ServerStateToString(newState);

	std::cout << "[Server] State: "
		<< from
		<< " --> "
		<< to
		<< std::endl;

	// File (non-blocking).
	this->logger.LogStateTransition("SERVER", from, to);
};

// Maps ClientState enum to a readable string for console output.
static const char* ClientStateToString(ClientState state) {
	switch (state)
	{
	case ClientState::RECEIVING:    return "RECEIVING";
	case ClientState::PROCESSING:   return "PROCESSING";
	case ClientState::TRANSMITTING: return "TRANSMITTING";
	default:                        return "UNKNOWN";
	};
};

void Server::SetClientState(ClientState& current, ClientState next, const std::string& clientName) {
	std::string from = ClientStateToString(current);
	std::string to = ClientStateToString(next);

	std::cout << "[" << clientName << "] State: "
		<< from
		<< " --> "
		<< to
		<< std::endl;

	// File (non-blocking).
	this->logger.LogClientStateTransition(clientName, from, to);

	current = next;
};