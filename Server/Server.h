#pragma once

#ifndef SERVER_H
#define SERVER_H

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

#define SERVER_PORT 54000					// This is the default port that the server listens on.
#define CONFIG_FILE_NAME "server_config.txt"
#define MAX_PENDING_CONNECTIONS 2
#define SOCKET_RECV_TIMEOUT_MS 1000U

// ============================================================
//  Server-wide state — sequential lifecycle, one at a time.
// ============================================================
enum class ServerState
{
	INITIALIZING,	// Default startup state.
	LISTENING,      // Server is bound and waiting for client connections.
	VERIFICATION,   // A client has connected. 4-packet mutual handshake is in progress.
	AUTHENTICATED,  // Handshake passed. Client is verified, about to enter relay.
	DISCONNECTING   // A client disconnected or shutdown was triggered. Cleanup in progress.
};

// ============================================================
//  Per-client state - runs concurrently inside each relay thread.
// ============================================================
enum class ClientState
{
	RECEIVING,      // Thread is blocked on recv(), waiting for incoming data.
	PROCESSING,     // Packet received. Running structural + CRC-32 validation.
	TRANSMITTING    // Packet validated. Calling send() to forward to destination.
};

class Server {
private:
	SOCKET listeningSocket;
	SOCKET groundControlSocket;
	SOCKET airplaneSocket;

	std::thread groundControlThread;
	std::thread airplaneThread;

	std::atomic<bool> isRunning;		// Set to false for graceful shutdown.
	std::atomic<ServerState> serverState;

	// ---------- Connection tracking ----------
	// Set to false by the relay thread when its client disconnects.
	// Used by Run() to decide whether to re-accept one or both clients.
	std::atomic<bool> groundControlConnected;
	std::atomic<bool> airplaneConnected;

	Logging::Logger logger;

	std::string sharedSecret;			// Shared Secret key.
	std::string logFilePath;

	bool winsockInitialized;

	// Reads shared secret from a key=value .txt config file.
	// Returns true if the SECRET key is found and loaded.
	bool LoadConfig(const std::string& configPath);

	// Initializes the WinSock Library (WSAStartup).
	bool InitializeWinsock();

	// Creates, binds, and begins listening on listeningSocket.
	bool CreateListeningSocket();

	// Accepts and handshakes the Ground Control client.
	// Returns true on success.
	bool AcceptGroundControl();

	// Accepts and handshakes the Airplane client.
	// Returns true on success.
	bool AcceptAirplane();

	// Executes the full 4-packet mutual verification handshake with the client.
	// Returns true if the handshake succeeds, false if it fails at any step.
	// On failure the caller should close the socket and not start a relay thread.
	bool PerformHandshake(SOCKET clientSocket, const std::string& clientName);

	// Computes the expected signature: CRC-32 over (sharedSecret bytes + randomNumber bytes).
	uint32_t ComputeSignature(uint32_t randomNumber) const;

	// Relay loop executed on each client thread.
	// Receives raw bytes from sourceSocket and forwards them to destinationSocket.
	// clientName is used only for console log messages.
	void RelayLoop(SOCKET sourceSocket, SOCKET destinationSocket, const std::string& clientName, const std::string& destinationName);

	// Safely closes a SOCKET handle and resets it to INVALID_SOCKET.
	void CloseSocket(SOCKET* sock);

	// Transitions the server-wide state and logs the change to the console.
	void SetServerState(ServerState newState);

	// Transitions a per-client state and logs the change to the console.
	void SetClientState(ClientState& current, ClientState next, const std::string& clientName);

public:
	Server();

	~Server();

	// This function is used to initialize Winsock and Create the listening socket.
	// Returns true on success.
	bool Initialize();

	// This function blocks until ground control connects, and then blocks until airplane connects.
	// This will spawn one relay thread per client.
	void AcceptClients();

	// Waits for both relay threads to finish.
	void Run();

	// This function will signal both receive threads to stop and close all sockets.
	void Shutdown();

	// Validates packet structure and CRC-32 integrity.
	// buffer    - pointer to the full assembled packet (Header + Body + CRC tail)
	// totalSize - total byte count of the assembled packet
	// Returns true if both structural and CRC checks pass.
	bool ValidatePacket(const char* buffer, unsigned int totalSize) const;
};

#endif // SERVER_H