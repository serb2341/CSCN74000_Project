#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <ctime>
#include "Packet.h"
//#include "VerificationPacket.h"
#include "Handshake.h"
//#include "CRC32.h"

#pragma comment(lib, "Ws2_32.lib")



int main() {

    //Starts Windows Sockets DLL
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // creates a TCP socket called clientSocket
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(54000); // Server port from Server.h
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //IP address


    // Get the secret from the config file
    std::string secret = Handshake::LoadSecret("server_config.txt");

    if (secret.empty()) {
        std::cerr << "[Server] SECRET key not found in config file." << std::endl;
        return 1;
    }

    //initializes socket. SOCK_STREAM: TCP
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "Connection failed.\n";
        (void)closesocket(clientSocket); //Closes clientSocket
        WSACleanup();
        return 1;
    }


    // Pass the secret into the handshake logic
    if (!Handshake::Execute(clientSocket, secret)) {
        std::cerr << "[Error] Handshake failed. Connection closed." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Handshake Complete. Waiting for Flight Client...\n";

    // ---------------SUDHAN ADDED THIS-------------------
    // Wait to receive a message before being able to send anything
    char rxBuffer[512] = {};
    int bytes = recv(clientSocket, rxBuffer, sizeof(rxBuffer), 0);

    Packet rxPkt_test(rxBuffer);

    // getting the flight ID from the incoming packet to use in the response packet
    unsigned int flightID;
    flightID = rxPkt_test.GetFlightID();

    std::cout << "\n[Incoming] ";
    rxPkt_test.DisplayGroundControlSide(std::cout);

    // Send Response
    std::cout << "Enter Reply: ";
    std::string msg;
    std::getline(std::cin, msg);

    Packet txPkt;
    txPkt.SetFlightID(flightID);
    txPkt.SetData(msg.c_str(), msg.size());

    unsigned int txSize = 0;
    char* txData = txPkt.SerializeData(txSize);
    send(clientSocket, txData, txSize, 0);

    Packet rxPkt(rxBuffer);
    // ---------------SUDHAN ADDED THIS-------------------

    // Communication Loop 
    bool running = true;
    while (running) {
        // Wait to receive a message before being able to send anything
        char rxBuffer[512] = {};
        int bytes = recv(clientSocket, rxBuffer, sizeof(rxBuffer), 0);
        if (bytes <= 0) break;

        Packet rxPkt(rxBuffer);

		// Performing a validation for corrupted packets. If the CRC check fails, we skip processing this packet and wait for the next one.
        if (rxPkt.CalculateCRC() != 0xFF00FF00U) { // Using the constant from Packet.h
            std::cout << "[Warning] Corrupted packet received! Ignoring...\n";
            continue; // Skip this iteration and wait for a clean packet
        }

		// getting the flight ID from the incoming packet to use in the response packet
        unsigned int flightID;
        flightID = rxPkt.GetFlightID();

        std::cout << "\n[Incoming] ";
        rxPkt.DisplayGroundControlSide(std::cout);

        // Send Response
        std::cout << "Enter Reply: ";
        std::string msg;
        std::getline(std::cin, msg);

        Packet txPkt;
        txPkt.SetFlightID(flightID);
        txPkt.SetData(msg.c_str(), msg.size());

        unsigned int txSize = 0;
        char* txData = txPkt.SerializeData(txSize);
        send(clientSocket, txData, txSize, 0);
    }

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}