#pragma once

#ifndef GROUND_CONTROL_CLIENT_H
#define GROUND_CONTROL_CLIENT_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

//#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <atomic>
#include <iostream>
#include "Logger.h" 

#pragma comment(lib, "Ws2_32.lib")


namespace GroundControlClient {

    class GroundControlClient {
        friend class Test_Handshake_Integration;
        friend class Test_PacketRelay_Integration;
        friend class Test_BidirectionalExchange_Integration;
        friend class Test_TelemetryPath_Integration;
        friend class Test_Disconnection_Integration;
        friend class Test_FlightID_Integration;
        friend class Test_HandshakeThenData_Integration;



    private:
        SOCKET clientSocket;
        std::atomic<bool> isRunning;
        std::string sharedSecret;
        unsigned int activeFlightID;

        // Logger instance 
        GroundControlLogging::Logger logger{ "groundcontrol_log.txt" };

        // Private Helpers 
        bool LoadConfig(const std::string& configPath);
        bool InitializeWinsock();
        bool CreateSocket();
        bool ValidatePacket(const char* buffer) const;
        void CloseSocket(SOCKET* sock);

        // Messaging Logic
        void receiveMessage();
        void sendMessage(int messageType, const std::string& message);

    public:
        GroundControlClient();
        ~GroundControlClient();

        // Public Interface
        bool Initialize();
        void ValidateConnection();
        void Run();
        void Shutdown();
    };
}

#endif