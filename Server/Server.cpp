#include "Server.h"
#include "PacketHeader.h"

Server::Server() {
	this->listeningSocket = INVALID_SOCKET;
	this->groundControlSocket = INVALID_SOCKET;
	this->airplaneSocket = INVALID_SOCKET;

	this->isRunning = false;
};

Server::~Server() {
	this->Shutdown();
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

void Server::RelayLoop(SOCKET sourceSocket, SOCKET destinationSocket, const std::string& clientName) {
	std::cout << "[" << clientName << "] Relay thread started." << std::endl;

	while (this->isRunning) {
		// First we start with only receiving the Header of the data packet.
		char headerBuffer[sizeof(PacketHeader)];

		std::memset(headerBuffer, 0, sizeof(PacketHeader));

		int bytesReceived = recv(sourceSocket, headerBuffer, sizeof(headerBuffer), MSG_WAITALL);		// The flag tells Winsock to not return until all header bytes are here.

		if (bytesReceived == 0) {
			std::cout << "[" << clientName << "] Client disconnected." << std::endl;

			break;
		}

		else if ((bytesReceived == SOCKET_ERROR) || (bytesReceived != sizeof(PacketHeader))) {
			if (this->isRunning) {
				std::cerr << "[" << clientName << "] Header recv() failed. Error: " << WSAGetLastError() << std::endl;
			};

			break;
		};


		// We serialize the Header.
		PacketHeader pktHeader{};

		std::memcpy(&pktHeader, headerBuffer, sizeof(PacketHeader));

		// Initializing the total packet size.
		unsigned int totalPktSize = sizeof(PacketHeader) + pktHeader.Length + sizeof(unsigned int);

		// Allocating full buffer and Assembling full packet.
		char* recvBuffer = new char[totalPktSize];

		// Copying the already received Header.
		std::memcpy(recvBuffer, headerBuffer, sizeof(PacketHeader));

		bytesReceived = recv(sourceSocket, recvBuffer + sizeof(PacketHeader), (static_cast<int>(totalPktSize) - static_cast<int>(sizeof(PacketHeader))), MSG_WAITALL);

		if (bytesReceived == 0) {
			std::cout << "[" << clientName << "] Client disconnected during body recv." << std::endl;

			break;
		};


		// From here on, we are forwarding the data packet to the destination client.
		int bytesSent = send(destinationSocket, recvBuffer, totalPktSize, 0);

		if (bytesSent == SOCKET_ERROR) {
			std::cerr << "[" << clientName << "] send() failed. Error: " << WSAGetLastError() << std::endl;

			break;
		};

		std::cout << "[" << clientName << "] Relayed " << totalPktSize << " bytes (Body length: " << pktHeader.Length << ")." << std::endl;


		std::memset(recvBuffer, 0, totalPktSize);

		delete[] recvBuffer;
		recvBuffer = nullptr;
	};

	std::cout << "[" << clientName << "] Relay thread exiting." << std::endl;

	this->isRunning = false;

	this->CloseSocket(&(this->groundControlSocket));
	this->CloseSocket(&(this->airplaneSocket));
};

void Server::CloseSocket(SOCKET* socketPtr) {
	if (*socketPtr != INVALID_SOCKET) {
		closesocket(*socketPtr);

		*socketPtr = INVALID_SOCKET;

		socketPtr = nullptr;
	};
};

bool Server::Initialize() {
	if (!this->InitializeWinsock()) {
		std::cerr << "[Server] Failed to initialize Winsock." << std::endl;

		return false;
	};

	if (!this->CreateListeningSocket()) {
		std::cerr << "[Server] Failed to create listen socket." << std::endl;

		WSACleanup();

		return false;
	};

	this->isRunning = true;

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

	std::cout << "[Server] Ground Control connected." << std::endl;

	
	// 2nd connection - In-flight Airplane.
	std::cout << "[Server] Waiting for Airplane to connect..." << std::endl;

	this->airplaneSocket = accept(this->listeningSocket, nullptr, nullptr);

	if (this->airplaneSocket == INVALID_SOCKET) {
		std::cerr << "[Server] accept() failed for In-flight Airplane. Error: " << WSAGetLastError() << std::endl;

		this->Shutdown();

		return;
	};

	std::cout << "[Server] In-flight Airplane connected." << std::endl;
	std::cout << "[Server] Both clients connected. Starting relay threads." << std::endl;

	// Closing the listening socket because no more connections are needed.
	this->CloseSocket(&(this->listeningSocket));

	// Here we spawn one relay thread per client.

	// Ground Control Client Thread.
	this->groundControlThread = std::thread(&Server::RelayLoop, this, this->groundControlSocket, this->airplaneSocket, std::string("Ground Control"));

	// In-flight Airplane Client Thread.
	this->airplaneThread = std::thread(&Server::RelayLoop, this, this->airplaneSocket, this->groundControlSocket, std::string("In-flight Airplane"));
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

	WSACleanup();

	std::cout << "[Server] Shutdown complete." << std::endl;
};