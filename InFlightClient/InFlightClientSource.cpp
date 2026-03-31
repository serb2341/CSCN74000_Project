#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#include <windows.networking.sockets.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include "Packet.h"
#include "VerificationPacket.h"
#include "CRC32.h"
# include <ctime>


#pragma comment(lib, "Ws2_32.lib")


// Helper for Handshake Signature - Must match Server logic
uint32_t ComputeSignature(uint32_t random, const std::string& secret) {
    std::string payload = secret;
    payload.append((const char*)(&random), sizeof(uint32_t));
    return CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
}


int main(int argc, char* argv[])
{
    const std::string SHARED_SECRET = "secret"; // WARNING: This is a dummy value for now. Must match server_config.txt


    if (argc < 2)
    {
        std::cout << "[Client] Enter FlightID upon startup\n";
        return 1;
    }

    int flightId = std::stoi(argv[1]); //***US - 10

    //starts Winsock DLLs
    WSADATA wsaData;
    if ((WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) //Starts Windows Sockets DLL
    {
        return 1;
    }

    //initializes socket. SOCK_STREAM: TCP
    SOCKET ClientSocket;
    ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //creates a TCP socket called ClientSocket
    if (ClientSocket == INVALID_SOCKET)
    {
        (void)WSACleanup(); //Ends Windows Sockets DLLs
        return 1;
    }

    //Connect socket to specified server
    sockaddr_in SvrAddr;
    SvrAddr.sin_family = AF_INET;						//Address family type itnernet
    SvrAddr.sin_port = htons(54000);					//port (host to network conversion)
    SvrAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //IP address
    if ((connect(ClientSocket, (struct sockaddr*)&SvrAddr, sizeof(SvrAddr))) == SOCKET_ERROR)  //binds ClientSocket to port 27000
    {
        (void)closesocket(ClientSocket); //Closes ClientSocket
        (void)WSACleanup();   //Ends Windows Sockets DLLs
        return 1;
    }

    // ***** 4-Step Verification Handshake *****
    // --- STEP 1: Send Challenge 
    ChallengePacket gcChallenge;
    gcChallenge.Type = static_cast<uint32_t>(VerificationPacketType::CHALLENGE);
    gcChallenge.Random = static_cast<uint32_t>(rand());
    gcChallenge.CRC32 = CRC32::Calculate((char*)&gcChallenge, 8);
    send(ClientSocket, (char*)&gcChallenge, sizeof(ChallengePacket), 0);

    // --- STEP 2: Receive Response ---
    ResponsePacket svrResponse;
    recv(ClientSocket, (char*)&svrResponse, sizeof(ResponsePacket), MSG_WAITALL);  // MSG_WAITALL will ensure the full packet is recieved
    if (svrResponse.Signature != ComputeSignature(gcChallenge.Random, SHARED_SECRET)) {
        std::cout << "Server authentication failed.\n";
        return 1;
    }

    // --- STEP 3: Receive Server Challenge ---
    ChallengePacket svrChallenge;
    recv(ClientSocket, (char*)&svrChallenge, sizeof(ChallengePacket), MSG_WAITALL);

    // --- STEP 4: Send Response ---
    ResponsePacket gcResponse;
    gcResponse.Type = static_cast<uint32_t>(VerificationPacketType::RESPONSE);
    gcResponse.Signature = ComputeSignature(svrChallenge.Random, SHARED_SECRET);
    gcResponse.CRC32 = CRC32::Calculate((char*)&gcResponse, 8);
    send(ClientSocket, (char*)&gcResponse, sizeof(ResponsePacket), 0);

    std::cout << "Handshake Complete.\n";
    // ***** 4-Step Verification Handshake *****

    // Send initial message with Flight ID - *** US-10
    Packet newPkt; //Packet object is created
    newPkt.SetFlightID(flightId); //populates the newPkt object with the data 
    newPkt.SetMessageType(0); //populates the newPkt object with the data
    newPkt.SetTimeStamp(static_cast<unsigned char>(time(nullptr)));
    unsigned int Size = 0;
    std::string firstMessage = "Connected";
    newPkt.SetData(firstMessage.c_str(), firstMessage.size());
    char* Tx = newPkt.SerializeData(Size);
    if (send(ClientSocket, Tx, Size, 0) == SOCKET_ERROR)
    {
        std::cout << "Error sending connection packet\n";
    }

    // Receives information about active ground control *** US-5
    char rxBuffer[512] = {};
    int bytes = recv(ClientSocket, rxBuffer, sizeof(rxBuffer), 0);
    if (bytes <= 0) {
        std::cout << "Error: No data recieved." << std::endl; //Error checking, no data was sent
    }
    Packet rxPkt(rxBuffer);
    // Performing a validation for corrupted packets. If the CRC check fails, we skip processing this packet and wait for the next one.
    if (rxPkt.CalculateCRC() != 0xFF00FF00U) { // Using the constant from Packet.h
        std::cout << "[Warning] Corrupted packet recieved!\n";
    }
    rxPkt.DisplayInFlightSide(std::cout);

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

            newPkt.SetFlightID(flightId);
            newPkt.SetMessageType(0);
            newPkt.SetTimeStamp(static_cast<unsigned char>(time(nullptr)));
            newPkt.SetData(msg.c_str(), msg.size());
            Size = 0;
            Tx = newPkt.SerializeData(Size);

            if (send(ClientSocket, Tx, Size, 0) == SOCKET_ERROR) //sends message to the Server 
            {
                std::cout << "Error: No data sent." << std::endl; //Error checking, no data was sent

            }
        }
        else if (choice == 2)
        {
            // Will be handled in Sprint 2
        }
        else
        {
            // Handle third condition and any other condition
            break;
        }

        // Recieve response from groun control
        char RxBuffer[512] = {};				//Buffer for recieving data
        int bytes = recv(ClientSocket, RxBuffer, sizeof(RxBuffer), 0);
        if (bytes <= 0) {
            running = false;
        }
        Packet rxPkt(RxBuffer);
        // Performing a validation for corrupted packets. If the CRC check fails, we skip processing this packet and wait for the next one.
        if (rxPkt.CalculateCRC() != 0xFF00FF00U) { // Using the constant from Packet.h
            std::cout << "[Warning] Corrupted packet recieved! Ignoring...\n";
            continue; // Skip this iteration and wait for a clean packet
        }
        rxPkt.DisplayInFlightSide(std::cout); //Display response
    }

    (void)closesocket(ClientSocket);
    (void)WSACleanup();

    return 0;
}
