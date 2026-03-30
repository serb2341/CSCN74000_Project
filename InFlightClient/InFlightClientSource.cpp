#include <windows.networking.sockets.h>
#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <sstream>
#include "Packet.h"
# include <ctime>


#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: pilot_client <FlightID>\n";
        return 1;
    }

    int flightId = std::stoi(argv[1]); //***US - 10

    //starts Winsock DLLs
    WSADATA wsaData;
    if ((WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) //Starts Windows Sockets DLL
    {
        return 0;
    }

    //initializes socket. SOCK_STREAM: TCP
    SOCKET ClientSocket;
    ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //creates a TCP socket called ClientSocket
    if (ClientSocket == INVALID_SOCKET)
    {
        WSACleanup(); //Ends Windows Sockets DLLs
        return 0;
    }

    //Connect socket to specified server
    sockaddr_in SvrAddr;
    SvrAddr.sin_family = AF_INET;						//Address family type itnernet
    SvrAddr.sin_port = htons(27000);					//port (host to network conversion)
    SvrAddr.sin_addr.s_addr = inet_addr("127.0.0.1");	//IP address
    if ((connect(ClientSocket, (struct sockaddr*)&SvrAddr, sizeof(SvrAddr))) == SOCKET_ERROR)  //binds ClientSocket to port 27000
    {
        closesocket(ClientSocket); //Closes ClientSocket
        WSACleanup();   //Ends Windows Sockets DLLs
        return 0;
    }

    Packet newPkt; //Packet object is created
    
    //Sends the FlightID in the header to the Server  *** US-10
    newPkt.SetFlightID(flightId); //populates the newPkt object with the data 
    newPkt.SetMessageType(0); //populates the newPkt object with the data
    newPkt.SetTimeStamp((unsigned char)time(nullptr));
    unsigned int Size = 0;
    std::string firstMessage = "Connected";
    newPkt.SetData(firstMessage.c_str(), firstMessage.size());
    char* Tx = newPkt.SerializeData(Size);
    if (send(ClientSocket, Tx, Size, 0) == SOCKET_ERROR)
    {
        std::cout << "Error sending connection packet\n";
    }

    // Receives information about active ground control *** US-5
    char RxBuffer[512] = {};				//Buffer for receiving data
    if (recv(ClientSocket, RxBuffer, sizeof(RxBuffer), 0) == SOCKET_ERROR) //Receives to the RxBuffer
    {
        std::cout << "Error: No data recieved." << std::endl; //Error checking, no data was sent
    }

    Packet RxPkt(RxBuffer); //uses the overloaded constructor to fill the Packet object called RxPkt

    RxPkt.DisplayInFlightSide(std::cout);


    while (true)
    {
        std::cout << "\nSelect option:\n";
        std::cout << "1) Sent Message\n";
        std::cout << "2) Send Telemetry File\n";
        std::cout << "3) Exit\n";
        std::cout << "> ";

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) // Send one regular message at a time ***US-2
        {
            std::string msg;
            std::cout << "Enter message: ";
            std::getline(std::cin, msg); // inflight client enters message
            
            newPkt.SetFlightID(flightId);
            newPkt.SetMessageType(0);
            newPkt.SetTimeStamp((unsigned char)time(nullptr));
            newPkt.SetData((char*)msg.c_str(), msg.size());
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


        char RxBuffer[512] = {};				//Buffer for receiving data
        if (recv(ClientSocket, RxBuffer, sizeof(RxBuffer),0) < 0) //Receives to the RxBuffer
        {
            break;
        }

        Packet RxPkt(RxBuffer); //uses the overloaded constructor to fill the Packet object called RxPkt

        RxPkt.DisplayInFlightSide(std::cout);
    }


    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}