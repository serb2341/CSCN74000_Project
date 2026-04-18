#pragma once

#ifndef CLIENT_H
#define CLIENT_H
//#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <thread>
#include <atomic>
#include <iostream>
#include <string>
#include <cstdint>
#include "Logger.h"


#pragma comment(lib, "Ws2_32.lib")

namespace InFlightClient {
	class InFlightClient {
	friend class Test_Handshake_Integration;
	friend class Test_PacketRelay_Integration;
	friend class Test_BidirectionalExchange_Integration;
	friend class Test_TelemetryPath_Integration;
	friend class Test_Disconnection_Integration;
	friend class Test_FlightID_Integration;
	friend class Test_HandshakeThenData_Integration;


	private:
		SOCKET clientSocket;

		std::atomic<bool> isRunning;		// Set to false for graceful shutdown.

		std::string sharedSecret;			// Shared Secret key.

		int flightID;

		InFlightLogging::Logger logger{ "inflightclient_log.txt" };

	public:
		InFlightClient();

		~InFlightClient();

		// Initializes the WinSock Library (WSAStartup).
		bool InitializeWinsock();

		// Creates, binds, and connects clientSocket.
		bool CreateSocket();

		// Executes the full 4-packet mutual verification handshake with the client.
		// Returns true if the handshake succeeds, false if it fails at any step.
		// On failure the caller should close the socket and not start a relay thread.
		bool PerformHandshake(SOCKET clientSocket, const std::string& clientName);

		// Recieves messages
		void receiveMessage();

		// Sends messages
		void sendMessage(int messageType, const char* message, unsigned int size);

		// Reads shared secret from a key=value .txt config file.
		// Returns true if the SECRET key is found and loaded.
		bool LoadConfig(const std::string& configPath);

		// Computes the expected signature: CRC-32 over (sharedSecret bytes + randomNumber bytes).
		uint32_t ComputeSignature(uint32_t randomNumber) const;

		// Safely closes a SOCKET handle and resets it to INVALID_SOCKET.
		void CloseSocket(SOCKET* sock);

		// Validates packet structure and CRC-32 integrity.
		// buffer    - pointer to the full assembled packet (Header + Body + CRC tail)
		// totalSize - total byte count of the assembled packet
		// Returns true if both structural and CRC checks pass.
		bool ValidatePacket(const char* buffer, unsigned int totalSize) const;

		// This function is used to initialize Winsock and Create the socket.
		// Returns true on success.
		bool Initialize(int flightID);

		// This function performs 4 step handshake between client and server
		void ValidateConnection();

		// Performs In-Flight Client functionality
		void Run();

		// This function will close all sockets.
		void Shutdown();
	};
};

#endif // CLIENT_H