#pragma once
#include <winsock2.h>
#include <string>
#include <iostream>
#include <fstream>
#include "VerificationPacket.h"
#include "CRC32.h"

class Handshake {
private:
    // Helper to compute the expected signature (Secret + Random Number)
    static uint32_t ComputeSignature(uint32_t random, const std::string& secret) {
        std::string payload = secret;
        (void)payload.append(reinterpret_cast<const char*>(&random), sizeof(uint32_t));
        return Checksum::CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
    }

public:
    static bool Execute(SOCKET clientSocket, const std::string& sharedSecret) {
        // ----------------------------------------------------------------
        // STEP 1: Send the client's CHALLENGE packet.
        // ----------------------------------------------------------------
        ChallengePacket clientChallenge{};
        clientChallenge.Type = static_cast<uint32_t>(VerificationPacketType::CHALLENGE);
        clientChallenge.Random = static_cast<uint32_t>(rand());
        // CRC-32 covers Type + Random (8 bytes)
        clientChallenge.CRC32 = Checksum::CRC32::Calculate(reinterpret_cast<const char*>(&clientChallenge), sizeof(uint32_t) + sizeof(uint32_t));

        int bytesSent = send(clientSocket, reinterpret_cast<const char*>(&clientChallenge), sizeof(ChallengePacket), 0);
        if (bytesSent != sizeof(ChallengePacket)) {
            std::cerr << "[Handshake] Step 1: Failed to send challenge. Error: " << WSAGetLastError() << std::endl;
            return false;
        }
        std::cout << "[Handshake] Step 1: Challenge sent." << std::endl;


        // ----------------------------------------------------------------
        // STEP 2: Receive the Server's RESPONSE and validate signature.
        // ----------------------------------------------------------------
        ResponsePacket serverResponse{};
        int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&serverResponse), sizeof(ResponsePacket), MSG_WAITALL);

        if (bytesReceived != sizeof(ResponsePacket)) {
            std::cerr << "[Handshake] Step 2: Failed to receive response. Error: " << WSAGetLastError() << std::endl;
            return false;
        }

        // Validate Type
        if (static_cast<VerificationPacketType>(serverResponse.Type) != VerificationPacketType::RESPONSE) {
            std::cerr << "[Handshake] Step 2: Unexpected packet type." << std::endl;
            return false;
        }

        // Validate CRC-32 (Type + Signature)
        uint32_t expectedSvrResponseCRC = Checksum::CRC32::Calculate(reinterpret_cast<const char*>(&serverResponse), sizeof(uint32_t) + sizeof(uint32_t));
        if (serverResponse.CRC32 != expectedSvrResponseCRC) {
            std::cerr << "[Handshake] Step 2: CRC-32 validation failed." << std::endl;
            return false;
        }

        // Validate Signature
        uint32_t expectedSvrSignature = ComputeSignature(clientChallenge.Random, sharedSecret);
        if (serverResponse.Signature != expectedSvrSignature) {
            std::cerr << "[Handshake] Step 2: Signature mismatch. Server failed authentication." << std::endl;
            return false;
        }
        std::cout << "[Handshake] Step 2: Server response validated." << std::endl;


        // ----------------------------------------------------------------
        // STEP 3: Receive the Server's CHALLENGE.
        // ----------------------------------------------------------------
        ChallengePacket serverChallenge{};
        bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&serverChallenge), sizeof(ChallengePacket), MSG_WAITALL);

        if (bytesReceived != sizeof(ChallengePacket)) {
            std::cerr << "[Handshake] Step 3: Failed to receive server challenge. Error: " << WSAGetLastError() << std::endl;
            return false;
        }

        // Validate Type
        if (static_cast<VerificationPacketType>(serverChallenge.Type) != VerificationPacketType::CHALLENGE) {
            std::cerr << "[Handshake] Step 3: Unexpected packet type." << std::endl;
            return false;
        }

        // Validate CRC-32
        uint32_t expectedSvrChallengeCRC = Checksum::CRC32::Calculate(reinterpret_cast<const char*>(&serverChallenge), sizeof(uint32_t) + sizeof(uint32_t));
        if (serverChallenge.CRC32 != expectedSvrChallengeCRC) {
            std::cerr << "[Handshake] Step 3: CRC-32 validation failed." << std::endl;
            return false;
        }
        std::cout << "[Handshake] Step 3: Server challenge received and validated." << std::endl;


        // ----------------------------------------------------------------
        // STEP 4: Send the client's RESPONSE.
        // ----------------------------------------------------------------
        ResponsePacket clientResponse{};
        clientResponse.Type = static_cast<uint32_t>(VerificationPacketType::RESPONSE);
        clientResponse.Signature = ComputeSignature(serverChallenge.Random, sharedSecret);
        clientResponse.CRC32 = Checksum::CRC32::Calculate(reinterpret_cast<const char*>(&clientResponse), sizeof(uint32_t) + sizeof(uint32_t));

        bytesSent = send(clientSocket, reinterpret_cast<const char*>(&clientResponse), sizeof(ResponsePacket), 0);
        if (bytesSent != sizeof(ResponsePacket)) {
            std::cerr << "[Handshake] Step 4: Failed to send response. Error: " << WSAGetLastError() << std::endl;
            return false;
        }
        std::cout << "[Handshake] Step 4: Response sent. Handshake complete." << std::endl;

        return true;
    }

    // Helper to read secret from the config file 
    static std::string LoadSecret(const std::string& configPath) {
        std::ifstream configFile(configPath);
        std::string line;
        if (configFile.is_open()) {
            while (std::getline(configFile, line)) {
                // Skip empty lines and comments (lines starting with #)
                if (line.empty() || line[0] == '#') {
                    continue;
                };

                size_t delimPos = line.find('=');
                if (delimPos != std::string::npos) {
                    std::string key = line.substr(0, delimPos);
                    std::string value = line.substr(delimPos + 1);

                    if (key == "SECRET") {
                        configFile.close();
						return value; // returns the secret value if found
                    }
                }
            }
            configFile.close();
        }
        return "";
    }
};