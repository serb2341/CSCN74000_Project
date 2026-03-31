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

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_PORT 54000					// This is the default port that the server listens on.

//#define RECV_BUFFER_SIZE 500				// This is the size of the buffer where the incoming/outgoing message will be stored.

class Server {
private:
	SOCKET listeningSocket;
	SOCKET groundControlSocket;
	SOCKET airplaneSocket;

	std::thread groundControlThread;
	std::thread airplaneThread;

	std::atomic<bool> isRunning;		// Set to false for graceful shutdown.

	// Initializes the WinSock Library (WSAStartup).
	bool InitializeWinsock();

	// Creates, binds, and begins listening on listeningSocket.
	bool CreateListeningSocket();

	// Relay loop executed on each client thread.
	// Receives raw bytes from sourceSocket and forwards them to destinationSocket.
	// clientName is used only for console log messages.
	void RelayLoop(SOCKET sourceSocket, SOCKET destinationSocket, const std::string& clientName);

	// Safely closes a SOCKET handle and resets it to INVALID_SOCKET.
	void CloseSocket(SOCKET* sock);

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
};

#endif // SERVER_H