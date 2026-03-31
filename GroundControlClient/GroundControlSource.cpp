#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <ctime>
#include "Packet.h"
#include "VerificationPacket.h"
#include "CRC32.h"

#pragma comment(lib, "Ws2_32.lib")



// Helper for Handshake Signature - Must match Server logic
uint32_t ComputeSignature(uint32_t random, const std::string& secret) {
    std::string payload = secret;
    payload.append((const char*)(&random), sizeof(uint32_t));
    return CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
}

int main() {
    const std::string SHARED_SECRET = "secret"; // WARNING: This is a dummy value for now. Must match server_config.txt

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


    //initializes socket. SOCK_STREAM: TCP
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "Connection failed.\n";
        (void)closesocket(clientSocket); //Closes clientSocket
        WSACleanup();
        return 1;
    }



	// ***** 4-Step Verification Handshake *****
    
    // --- STEP 1: Send Challenge 
    ChallengePacket gcChallenge;
    gcChallenge.Type = static_cast<uint32_t>(VerificationPacketType::CHALLENGE);
    gcChallenge.Random = static_cast<uint32_t>(rand());
    gcChallenge.CRC32 = CRC32::Calculate((char*)&gcChallenge, 8);
    send(clientSocket, (char*)&gcChallenge, sizeof(ChallengePacket), 0);

    // --- STEP 2: Receive Response ---
    ResponsePacket svrResponse;
    recv(clientSocket, (char*)&svrResponse, sizeof(ResponsePacket), MSG_WAITALL);  // MSG_WAITALL will ensure the full packet is received
    if (svrResponse.Signature != ComputeSignature(gcChallenge.Random, SHARED_SECRET)) {
        std::cout << "Server authentication failed.\n";
        return 1;
    }

    // --- STEP 3: Receive Server Challenge ---
    ChallengePacket svrChallenge;
    recv(clientSocket, (char*)&svrChallenge, sizeof(ChallengePacket), MSG_WAITALL);

    // --- STEP 4: Send Response ---
    ResponsePacket gcResponse;
    gcResponse.Type = static_cast<uint32_t>(VerificationPacketType::RESPONSE);
    gcResponse.Signature = ComputeSignature(svrChallenge.Random, SHARED_SECRET);
    gcResponse.CRC32 = CRC32::Calculate((char*)&gcResponse, 8);
    send(clientSocket, (char*)&gcResponse, sizeof(ResponsePacket), 0);

    std::cout << "Handshake Complete. Waiting for Flight Client...\n";

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