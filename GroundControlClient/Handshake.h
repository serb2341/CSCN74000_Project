#pragma once
#include <winsock2.h>
#include <string>
#include <iostream>
#include <fstream>
#include "VerificationPacket.h"
#include "CRC32.h"

#define SECRET_KEY_WORDING "SECRET"

namespace GroundControlMutualVerification {
    class Handshake {
    private:
        // Helper to compute the expected signature (Secret + Random Number)
        static uint32_t ComputeSignature(uint32_t random, const std::string& secret) {
            std::string payload = secret;
            (void)payload.append(reinterpret_cast<const char*>(&random), sizeof(uint32_t));
            return GroundControlChecksum::CRC32::Calculate(payload.c_str(), static_cast<unsigned int>(payload.size()));
        }

    public:
        static bool Execute(SOCKET clientSocket, const std::string& sharedSecret) {
            bool isHandshakeSuccessful = false;

            // ----------------------------------------------------------------
            // STEP 1: Send the client's CHALLENGE packet.
            // ----------------------------------------------------------------
            GroundControlVerificationPacket::ChallengePacket clientChallenge{};
            clientChallenge.Type = static_cast<uint32_t>(GroundControlVerificationPacket::VerificationPacketType::CHALLENGE);
            clientChallenge.Random = static_cast<uint32_t>(rand());
            // CRC-32 covers Type + Random (8 bytes)
            clientChallenge.CRC32 = GroundControlChecksum::CRC32::Calculate(reinterpret_cast<const char*>(&clientChallenge), sizeof(uint32_t) + sizeof(uint32_t));

            int bytesSent = send(clientSocket, reinterpret_cast<const char*>(&clientChallenge), sizeof(GroundControlVerificationPacket::ChallengePacket), 0);
            if (bytesSent != sizeof(GroundControlVerificationPacket::ChallengePacket)) {
                std::cerr << "[Handshake] Step 1: Failed to send challenge. Error: " << WSAGetLastError() << std::endl;
            }

            else {
                std::cout << "[Handshake] Step 1: Challenge sent." << std::endl;

                // ----------------------------------------------------------------
                // STEP 2: Receive the Server's RESPONSE and validate signature.
                // ----------------------------------------------------------------
                GroundControlVerificationPacket::ResponsePacket serverResponse{};
                int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&serverResponse), sizeof(GroundControlVerificationPacket::ResponsePacket), MSG_WAITALL);

                if (bytesReceived != sizeof(GroundControlVerificationPacket::ResponsePacket)) {
                    std::cerr << "[Handshake] Step 2: Failed to receive response. Error: " << WSAGetLastError() << std::endl;
                }

                else if (static_cast<GroundControlVerificationPacket::VerificationPacketType>(serverResponse.Type) != GroundControlVerificationPacket::VerificationPacketType::RESPONSE) {
                    // Validate Type
                    std::cerr << "[Handshake] Step 2: Unexpected packet type." << std::endl;
                }

                else {
                    // Validate CRC-32 (Type + Signature)
                    uint32_t expectedSvrResponseCRC = GroundControlChecksum::CRC32::Calculate(reinterpret_cast<const char*>(&serverResponse), sizeof(uint32_t) + sizeof(uint32_t));

                    if (serverResponse.CRC32 != expectedSvrResponseCRC) {
                        std::cerr << "[Handshake] Step 2: CRC-32 validation failed." << std::endl;
                    }

                    else {
                        // Validate Signature
                        uint32_t expectedSvrSignature = ComputeSignature(clientChallenge.Random, sharedSecret);

                        if (serverResponse.Signature != expectedSvrSignature) {
                            std::cerr << "[Handshake] Step 2: Signature mismatch. Server failed authentication." << std::endl;
                        }

                        else {
                            std::cout << "[Handshake] Step 2: Server response validated." << std::endl;

                            // ----------------------------------------------------------------
                            // STEP 3: Receive the Server's CHALLENGE.
                            // ----------------------------------------------------------------
                            GroundControlVerificationPacket::ChallengePacket serverChallenge{};
                            bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&serverChallenge), sizeof(GroundControlVerificationPacket::ChallengePacket), MSG_WAITALL);

                            if (bytesReceived != sizeof(GroundControlVerificationPacket::ChallengePacket)) {
                                std::cerr << "[Handshake] Step 3: Failed to receive server challenge. Error: " << WSAGetLastError() << std::endl;
                            }

                            else if (static_cast<GroundControlVerificationPacket::VerificationPacketType>(serverChallenge.Type) != GroundControlVerificationPacket::VerificationPacketType::CHALLENGE) {
                                // Validate Type
                                std::cerr << "[Handshake] Step 3: Unexpected packet type." << std::endl;
                            }

                            else {
                                // Validate CRC-32
                                uint32_t expectedSvrChallengeCRC = GroundControlChecksum::CRC32::Calculate(reinterpret_cast<const char*>(&serverChallenge), sizeof(uint32_t) + sizeof(uint32_t));

                                if (serverChallenge.CRC32 != expectedSvrChallengeCRC) {
                                    std::cerr << "[Handshake] Step 3: CRC-32 validation failed." << std::endl;
                                }

                                else {
                                    std::cout << "[Handshake] Step 3: Server challenge received and validated." << std::endl;

                                    // ----------------------------------------------------------------
                                    // STEP 4: Send the client's RESPONSE.
                                    // ----------------------------------------------------------------
                                    GroundControlVerificationPacket::ResponsePacket clientResponse{};
                                    clientResponse.Type = static_cast<uint32_t>(GroundControlVerificationPacket::VerificationPacketType::RESPONSE);
                                    clientResponse.Signature = ComputeSignature(serverChallenge.Random, sharedSecret);
                                    clientResponse.CRC32 = GroundControlChecksum::CRC32::Calculate(reinterpret_cast<const char*>(&clientResponse), sizeof(uint32_t) + sizeof(uint32_t));

                                    bytesSent = send(clientSocket, reinterpret_cast<const char*>(&clientResponse), sizeof(GroundControlVerificationPacket::ResponsePacket), 0);

                                    if (bytesSent != sizeof(GroundControlVerificationPacket::ResponsePacket)) {
                                        std::cerr << "[Handshake] Step 4: Failed to send response. Error: " << WSAGetLastError() << std::endl;
                                    }

                                    else {
                                        std::cout << "[Handshake] Step 4: Response sent. Handshake complete." << std::endl;
                                        isHandshakeSuccessful = true;
                                    };
                                };
                            };
                        };
                    };
                };
            };

            return isHandshakeSuccessful;
        };

        // Helper to read secret from the config file 
        static std::string LoadSecret(const std::string& configPath) {
            std::string loadedSecret = "";

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
                        
                        if (key == SECRET_KEY_WORDING) {
                            std::string value = line.substr(delimPos + 1);

                            loadedSecret = value; // returns the secret value if found

                            break;
                        };
                    };
                };

                configFile.close();
            };

            return loadedSecret;
        };
    };
};