#include "InFlightClient.h"
#include "VerificationPacket.h"
#include "Packet.h"
#include "CRC32.h"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <chrono>

#define SECRET_KEY_WORDING "SECRET"

Client::InFlightClient::InFlightClient() {
	this->clientSocket = INVALID_SOCKET;

	this->isRunning = false;
};

Client::InFlightClient::~InFlightClient() {
	this->Shutdown();
};

bool Client::InFlightClient::LoadConfig(const std::string& configPath) {
	bool result = false;

	std::ifstream configFile(configPath);

	if (!configFile.is_open()) {
		std::cerr << "[InFlightClient] Could not open config file: " << configPath << std::endl;
	}

	else {
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

			if (key == SECRET_KEY_WORDING) {
				std::string value = line.substr(delimPos + 1);

				this->sharedSecret = value;

				std::cout << "[InFlightClient] Shared secret loaded from config." << std::endl;

				result = true;

				break;
			};
		};

		if (!result) {
			std::cerr << "[InFlightClient] SECRET key not found in config file." << std::endl;
		};
	};

	return result;
};

bool Client::InFlightClient::InitializeWinsock() {
	bool isInitializationSuccessful = false;

	WSADATA wsaData;

	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) {
		std::cerr << "WSAStartup Failed. Error: " << result << std::endl;
	}

	else {
		isInitializationSuccessful = true;
	};

	return isInitializationSuccessful;
};

bool Client::InFlightClient::CreateSocket() {
	bool isSocketCreated = false;

	// Creating a TCP Socket.
	this->clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (this->clientSocket == INVALID_SOCKET) {
		std::cerr << "Socket() failed. Error: " << WSAGetLastError() << std::endl;
	}

	else {
		// Bind to all interfaces on SERVER_PORT.
		sockaddr_in SvrAddr;
		SvrAddr.sin_family = AF_INET;						//Address family type itnernet
		SvrAddr.sin_port = htons(54000);					//port (host to network conversion)

		static const char ipAddress[] = "127.0.0.1";
		(void)inet_pton(AF_INET, &ipAddress[0], &SvrAddr.sin_addr);

		int result = connect(this->clientSocket, reinterpret_cast<sockaddr*>(&SvrAddr), sizeof(SvrAddr));

		if (result == SOCKET_ERROR) {
			std::cerr << "connect() failed. Error: " << WSAGetLastError() << std::endl;

			this->CloseSocket(&(this->clientSocket));
		}

		else {
			isSocketCreated = true;
		};
	};

	return isSocketCreated;
};


// ============================================================
//  Handshake
// ============================================================

uint32_t Client::InFlightClient::ComputeSignature(uint32_t randomNumber) const {
	std::string payload = this->sharedSecret;

	(void)payload.append(reinterpret_cast<const char*>(&randomNumber), sizeof(uint32_t));

	return Checksum::CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
};

bool Client::InFlightClient::PerformHandshake(SOCKET clientSocket, const std::string& clientName) {
	bool result = false;

	// ----------------------------------------------------------------
	// STEP 1: Send the client's CHALLENGE packet.
	// ----------------------------------------------------------------
	Handshake::ChallengePacket clientChallenge{};
	clientChallenge.Type = static_cast<uint32_t>(Handshake::VerificationPacketType::CHALLENGE);
	clientChallenge.Random = static_cast<uint32_t>(rand());

	// CRC-32 covers Type + Random (8 bytes)
	clientChallenge.CRC32 = Checksum::CRC32::Calculate(
		reinterpret_cast<const char*>(&clientChallenge),
		sizeof(uint32_t) + sizeof(uint32_t));

	int bytesSent = send(
		clientSocket,
		reinterpret_cast<const char*>(&clientChallenge),
		sizeof(Handshake::ChallengePacket),
		0);

	if (bytesSent != sizeof(Handshake::ChallengePacket)) {
		std::cerr << "[" << clientName << "] Handshake Step 1: Failed to send challenge. Error: "
			<< WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "[Handshake] Step 1: Challenge sent." << std::endl;

		// ----------------------------------------------------------------
		// STEP 2: Receive the Server's RESPONSE and validate signature.
		// ----------------------------------------------------------------
		Handshake::ResponsePacket serverResponse{};
		int bytesReceived = recv(
			clientSocket,
			reinterpret_cast<char*>(&serverResponse),
			sizeof(Handshake::ResponsePacket),
			MSG_WAITALL);

		if (bytesReceived != sizeof(Handshake::ResponsePacket)) {
			std::cerr << "[Handshake] Step 2: Failed to receive response. Error: "
				<< WSAGetLastError() << std::endl;
		}
		else if (static_cast<Handshake::VerificationPacketType>(serverResponse.Type) != Handshake::VerificationPacketType::RESPONSE) {
			std::cerr << "[Handshake] Step 2: Unexpected packet type." << std::endl;
		}
		else {
			uint32_t expectedSvrResponseCRC = Checksum::CRC32::Calculate(
				reinterpret_cast<const char*>(&serverResponse),
				sizeof(uint32_t) + sizeof(uint32_t));

			if (serverResponse.CRC32 != expectedSvrResponseCRC) {
				std::cerr << "[Handshake] Step 2: CRC-32 validation failed." << std::endl;
			}
			else {
				uint32_t expectedSvrSignature = ComputeSignature(clientChallenge.Random);

				if (serverResponse.Signature != expectedSvrSignature) {
					std::cerr << "[Handshake] Step 2: Signature mismatch. Server failed authentication." << std::endl;
				}
				else {
					std::cout << "[Handshake] Step 2: Server response validated." << std::endl;

					// ----------------------------------------------------------------
					// STEP 3: Receive the Server's CHALLENGE.
					// ----------------------------------------------------------------
					Handshake::ChallengePacket serverChallenge{};
					bytesReceived = recv(
						clientSocket,
						reinterpret_cast<char*>(&serverChallenge),
						sizeof(Handshake::ChallengePacket),
						MSG_WAITALL);

					if (bytesReceived != sizeof(Handshake::ChallengePacket)) {
						std::cerr << "[Handshake] Step 3: Failed to receive server challenge. Error: "
							<< WSAGetLastError() << std::endl;
					}
					else if (static_cast<Handshake::VerificationPacketType>(serverChallenge.Type) != Handshake::VerificationPacketType::CHALLENGE) {
						std::cerr << "[Handshake] Step 3: Unexpected packet type." << std::endl;
					}
					else {
						uint32_t expectedSvrChallengeCRC = Checksum::CRC32::Calculate(
							reinterpret_cast<const char*>(&serverChallenge),
							sizeof(uint32_t) + sizeof(uint32_t));

						if (serverChallenge.CRC32 != expectedSvrChallengeCRC) {
							std::cerr << "[Handshake] Step 3: CRC-32 validation failed." << std::endl;
						}
						else {
							std::cout << "[Handshake] Step 3: Server challenge received and validated." << std::endl;

							// ----------------------------------------------------------------
							// STEP 4: Send the client's RESPONSE.
							// ----------------------------------------------------------------
							Handshake::ResponsePacket clientResponse{};
							clientResponse.Type = static_cast<uint32_t>(Handshake::VerificationPacketType::RESPONSE);
							clientResponse.Signature = ComputeSignature(serverChallenge.Random);
							clientResponse.CRC32 = Checksum::CRC32::Calculate(
								reinterpret_cast<const char*>(&clientResponse),
								sizeof(uint32_t) + sizeof(uint32_t));

							bytesSent = send(
								clientSocket,
								reinterpret_cast<const char*>(&clientResponse),
								sizeof(Handshake::ResponsePacket),
								0);

							if (bytesSent != sizeof(Handshake::ResponsePacket)) {
								std::cerr << "[Handshake] Step 4: Failed to send response. Error: "
									<< WSAGetLastError() << std::endl;
							}
							else {
								std::cout << "[Handshake] Step 4: Response sent. Handshake complete." << std::endl;
								result = true;
							};
						};
					};
				};
			};
		};
	};

	return result;
};



// ============================================================
//  Packet Validation
// ============================================================

bool Client::InFlightClient::ValidatePacket(const char* buffer, unsigned int totalSize) const {
	bool isPacketValid = false;

	// ---- Structural check ----
	// totalSize must be at least Header + CRC tail (body can be zero length).
	if (totalSize < (sizeof(Communication::PacketHeader) + sizeof(uint32_t))) {
		std::cerr << "[Validation] Packet too small to be valid." << std::endl;
	}
	else {
		// Extracting the header to read Length.
		Communication::PacketHeader pktHeader{};
		(void)std::memcpy(&pktHeader, buffer, sizeof(Communication::PacketHeader));

		// Verify the declared length matches the actual received size
		unsigned int expectedSize = sizeof(Communication::PacketHeader) + pktHeader.Length + sizeof(uint32_t);

		if (totalSize != expectedSize) {
			std::cerr << "[Validation] Structural mismatch: expected " << expectedSize << " bytes, got " << totalSize << " bytes." << std::endl;
		}
		else {
			// ---- CRC-32 integrity check ----
			// CRC-32 is computed over Header + Body (everything except the CRC tail itself)
			unsigned int payloadSize = sizeof(Communication::PacketHeader) + pktHeader.Length;

			uint32_t computedCRC = Checksum::CRC32::Calculate(buffer, payloadSize);

			// The CRC tail sits at the very end of the buffer
			uint32_t receivedCRC = 0U;
			(void)std::memcpy(&receivedCRC, buffer + payloadSize, sizeof(uint32_t)); //-V2563

			if (computedCRC != receivedCRC) {
				std::cerr << "[Validation] CRC-32 mismatch. Packet may be corrupted or tampered with." << std::endl;
			}
			else {
				isPacketValid = true;
			};
		};
	};

	return isPacketValid;
};


void Client::InFlightClient::CloseSocket(SOCKET* socketPtr) {
	if (*socketPtr != INVALID_SOCKET) {
		(void)closesocket(*socketPtr);

		*socketPtr = INVALID_SOCKET;

		socketPtr = nullptr;
	};
};

bool Client::InFlightClient::Initialize(int flightID) {
	bool isInitialized = false;

	// Seed random number generator for challenge generation.
	srand(static_cast<unsigned int>(time(nullptr)));

	if (!this->LoadConfig("server_config.txt")) {
		std::cerr << "[InFlightClient] Failed to load config. Ensure server_config.txt exists with SECRET=<value>." << std::endl;
	}
	else if (!this->InitializeWinsock()) {
		std::cerr << "[InFlightClient] Failed to initialize Winsock." << std::endl;
	}
	else if (!this->CreateSocket()) {
		std::cerr << "[InFlightClient] Failed to create listen socket." << std::endl;

		(void)WSACleanup();
	}
	else {
		this->isRunning = true;
		this->flightID = flightID;

		std::cout << "[InFlightClient] Initialized. Connected on port " << std::endl;

		isInitialized = true;
	};

	return isInitialized;
};

void Client::InFlightClient::ValidateConnection() {
	bool handshakeSuccessful = this->PerformHandshake(this->clientSocket, "In Flight Client");

	if (!handshakeSuccessful) {
		std::cerr << "[InFlightClient] server failed handshake. Dropping connection." << std::endl;

		this->CloseSocket(&(this->clientSocket));
		this->Shutdown();
	}

	else {
		std::cout << "[InFlightClient] Server handshake successful." << std::endl;
	};

	return;
};

void Client::InFlightClient::sendMessage(int messageType, const char* message, unsigned int size) {
	Communication::Packet newPkt; //Packet object is created
	newPkt.SetFlightID(this->flightID); //populates the newPkt object with the data 
	newPkt.SetMessageType(messageType); //populates the newPkt object with the data
	newPkt.SetTimeStamp(std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::system_clock::now().time_since_epoch()
	).count());
	unsigned int Size = 0;
	newPkt.SetData(message, size);
	char* Tx = newPkt.SerializeData(Size);
	if (send(this->clientSocket, Tx, Size, 0) == SOCKET_ERROR)
	{
		std::cout << "Error sending connection packet\n";
	}
	logger.Log(message, size);
}

void Client::InFlightClient::receiveMessage() {
	bool shouldShutdownClient = false;

	// ---- Phase 1: Receiving the fixed-size header. ----
	char headerBuffer[sizeof(Communication::PacketHeader)];

	int bytesReceived = recv(this->clientSocket, &headerBuffer[0], sizeof(headerBuffer), MSG_WAITALL);

	if (bytesReceived <= 0) {
		std::cout << "[InFlightClient] Server disconnected." << std::endl;

		shouldShutdownClient = true;
	}
	else if (bytesReceived != sizeof(Communication::PacketHeader)) {
		std::cerr << "[InFlightClient] Header recv() failed. Error: " << WSAGetLastError() << std::endl;
	}
	else {
		// ---- Phase 2: Reading Length from header and allocating exact buffer. ----
		Communication::PacketHeader pktHead{};

		(void)std::memcpy(&pktHead, &headerBuffer[0], sizeof(pktHead));

		char* recvBuffer = new char[sizeof(pktHead) + pktHead.Length + sizeof(uint32_t)];   // The data size is not known at compile time or object construction time and therefore dynamic memory needs to be used.Previous allocation is released before new allocation, preventing memory leaks.

		(void)std::memset(recvBuffer, 0, sizeof(pktHead) + pktHead.Length + sizeof(uint32_t));

		(void)std::memcpy(recvBuffer, &pktHead, sizeof(pktHead));

		// ---- Phase 3: Receiving Body + CRC tail. ----
		bytesReceived = recv(this->clientSocket, recvBuffer + sizeof(pktHead), pktHead.Length + sizeof(uint32_t), MSG_WAITALL); //-V2563

		if (bytesReceived <= 0) {
			std::cout << "[InFlightClient] Server disconnected during body recv." << std::endl;

			shouldShutdownClient = true;
		}
		else if (bytesReceived != (pktHead.Length + sizeof(uint32_t))) {
			std::cerr << "[InFlightClient] Body recv() failed. Error: " << WSAGetLastError() << std::endl;
		}
		else {
			// ---- Phase 4: Validating structure and CRC-32. ----
			if (!this->ValidatePacket(recvBuffer, sizeof(pktHead) + pktHead.Length + sizeof(uint32_t))) {
				std::cout << "[Warning] Corrupted packet received! Dropping." << std::endl;

				(void)std::memset(recvBuffer, 0, sizeof(pktHead) + pktHead.Length + sizeof(uint32_t));
			}
			else {
				// ---- Phase 5: Deserializing and Displaying Packet. ----
				Communication::Packet rxPkt(recvBuffer);

				rxPkt.DisplayInFlightSide(std::cout);

				logger.Log(rxPkt.GetData(), rxPkt.GetBodyLength());
			};
		};

		delete[] recvBuffer;  //Deletes dynamically allocated memory
		recvBuffer = nullptr;
	};

	if (shouldShutdownClient) {
		this->Shutdown();
	};
};

void Client::InFlightClient::Run() {
	char msg[] = "Connected";
	sendMessage(0, &msg[0], sizeof(msg) - 1);
	receiveMessage();
	
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

			sendMessage(0, msg.c_str(), msg.length());
		}
		else if (choice == 2)
		{
			std::ifstream file("telemetry.txt", std::ios::binary | std::ios::ate);

			if (!file) {
				std::cout << "Telemetry file not found.\n";

				continue;
			};

			std::streamsize size = file.tellg();

			(void)file.seekg(0, std::ios::beg);				// Moving the pointer back to beginning of the file.

			std::string bodyHeading = "TELEMETRY|";

			// Allocating heap memory.
			char* telBuffer = new char[size + bodyHeading.length()];  // The data size is not known at compile time or object construction time and therefore dynamic memory needs to be used.Previous allocation is released before new allocation, preventing memory leaks.

			if (!telBuffer) {
				std::cout << "Failed to allocate dynamic memory to telemetry file.\n";

				continue;
			};

			(void)std::memset(telBuffer, 0, (size + bodyHeading.length()));

			(void)std::memcpy(telBuffer, bodyHeading.c_str(), bodyHeading.length());

			if (file.read(telBuffer + bodyHeading.length(), size)) { //-V2563
				std::cout << "Sending telemetry...\n";

				this->sendMessage(1, telBuffer, size);
			};

			delete[] telBuffer;  //Deletes dynamically allocated memory
			telBuffer = nullptr;
			
			std::cout << "In Flight Client | Telemetry file successfully sent" << std::endl;
			/*std::ifstream file("telemetry.txt");

			if (!file)
			{
				std::cout << "Telemetry file not found.\n";
				continue;
			}*/

			//std::string line;

			//std::cout << "Sending telemetry...\n";

			//std::string packet = "TELEMETRY|";

			//while (std::getline(file, line))
			//{
			//	packet += line;
			//	sendMessage(1, packet.c_str());
			//	
			//	// Sleep(10); // small delay to prevent packet flooding
			//}

			// std::string endPacket = "TELEMETRY_END";
			// sendMessage(1, endPacket.c_str());
		}
		else
		{
			// Handle third condition and any other condition
			break;
		}

		// Recieve response from ground control
		receiveMessage();
	}
};

void Client::InFlightClient::Shutdown() {
	this->isRunning = false;

	// Here we are closing all the sockets.
	this->CloseSocket(&(this->clientSocket));

	(void)WSACleanup();

	std::cout << "[InFlightClient] Shutdown complete." << std::endl;
};

