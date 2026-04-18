#include "GroundControlClient.h"
#include "Handshake.h"
#include "Packet.h"
#include "CRC32.h"
#include <fstream>

/**
 * Constructor: Sets the initial state of the object by assigning the socket to an invalid
 * handle and ensuring the running status and ID tracking start at zero.
 */
Client::GroundControlClient::GroundControlClient()
    : clientSocket(INVALID_SOCKET), isRunning(false), activeFlightID(0) {
}

/**
 * Destructor: Triggers the shutdown sequence to ensure that any active network
 * connections or system resources are released when the object is destroyed.
 */
Client::GroundControlClient::~GroundControlClient() {
    Shutdown();
}

/**
 * Orchestrates the startup sequence by coordinating configuration loading,
 * network API initialization, and the establishment of the server connection.
 */
bool Client::GroundControlClient::Initialize() {
    bool isClientInitialized = false;

    // Attempt to load the security credentials from the configuration file
    if (!LoadConfig("server_config.txt")) {
    }

    // Request the necessary Windows Sockets version from the operating system
    else if (!InitializeWinsock()) {
    }

    // Construct the socket and attempt to reach the server at the defined address
    else if (!CreateSocket()) {
    }

    else {
        // Transition to a running state only after all setup phases succeed
        isRunning = true;
        isClientInitialized = true;
    };

    return isClientInitialized;
};

/**
 * Uses the Handshake helper to parse the configuration file and extract the
 * secret key required for the mutual authentication process.
 */
bool Client::GroundControlClient::LoadConfig(const std::string& configPath) {
    bool isConfigLoaded = false;

    // Extract the shared secret to be used during the validation handshake
    sharedSecret = MutualVerification::Handshake::LoadSecret(configPath);

    // Stop initialization if the secret is missing to prevent unauthenticated access
    if (sharedSecret.empty()) {
        std::cerr << "[GC] Error: Shared secret not found in " << configPath << std::endl;
    }

    else {
        isConfigLoaded = true;
    };

    return isConfigLoaded;
};

 // Performs the low-level WSAStartup call required to enable network functionality on Windows environments.

bool Client::GroundControlClient::InitializeWinsock() {
    WSADATA wsaData;
    // Confirm the system can provide the requested Winsock 2.2 version
    return (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
}

/**
 * Configures the network address parameters and attempts to link the
 * local socket to the remote server endpoint.
 */
bool Client::GroundControlClient::CreateSocket() {
    bool isSocketCreated = false;

    // Instantiate a TCP-based stream socket
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (clientSocket == INVALID_SOCKET) {
    }

    else {
        // Define the destination IP and port for the Ground Control link
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(54564);

        static const char ipAddress[] = "127.0.0.1";
        (void)inet_pton(AF_INET, &ipAddress[0], &serverAddr.sin_addr);

        // Initiate the connection request to the server
        if (connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            CloseSocket(&clientSocket);
        }

        else {
            isSocketCreated = true;
        };
    };

    return isSocketCreated;
};

/**
 * Executes the security handshake required by the server to prove the
 * client's identity using a challenge-response mechanism.
 */
void Client::GroundControlClient::ValidateConnection() {
    // Run the 4-packet exchange to verify both the server and the client
    if (!MutualVerification::Handshake::Execute(clientSocket, sharedSecret)) {
        std::cerr << "[GC] Handshake failed. Connection is untrusted.\n";
        Shutdown();
    }
}

/**
 * Encapsulates a text string into a formal packet structure, computes
 * its integrity checksum, and transmits the resulting data over the wire.
 */
void Client::GroundControlClient::sendMessage(int messageType, const std::string& message) {
    Communication::Packet txPkt;

    // Populate the packet header with the target flight ID and message type
    txPkt.SetFlightID(activeFlightID);
    txPkt.SetMessageType(messageType);
    txPkt.SetData(message.c_str(), static_cast<unsigned int>(message.size()));

    // Convert the packet object into a contiguous stream of bytes for transmission
    unsigned int size = 0;
    char* txData = txPkt.SerializeData(size);

    // Transfer the serialized bytes through the established network socket
    (void)send(clientSocket, txData, size, 0);

    // Record the sent message in the audit log along with its technical header data
    logger.Log(0, activeFlightID, "[SENT] " + message, txPkt.GetHeader());
}

/**
 * Implements a multi-step reception process that dynamically adjusts to the
 * size of incoming packets, preventing memory overflows.
 */
void Client::GroundControlClient::receiveMessage() {
    bool shouldStopClient = false;

    // Retrieve the header to identify the packet type and length
    char headerBuffer[sizeof(Communication::PacketHeader)];
    int bytes = recv(clientSocket, &headerBuffer[0], sizeof(headerBuffer), MSG_WAITALL);

    // Monitor the socket for disconnection or communication errors
    if (bytes <= 0) {
        shouldStopClient = true;
    }

    else {
        // Process the header to capture the sender's ID and payload dimensions
        Communication::PacketHeader head {};
        (void)std::memcpy(&head, &headerBuffer[0], sizeof(Communication::PacketHeader));
        activeFlightID = head.FlightID;

        // Create a buffer on the heap sized for this specific packet (dynamic allocation)
        unsigned int fullSize = sizeof(Communication::PacketHeader) + head.Length + sizeof(uint32_t);
        char* buffer = new char[fullSize];  //The data size is not known at compile time or object construction time and therefore dynamic memory needs to be used. Previous allocation is released before new allocation, preventing memory leaks.

        // Copy the existing header data into the beginning of the newly allocated buffer
        (void)std::memcpy(buffer, &headerBuffer[0], sizeof(Communication::PacketHeader));

        // Read the variable-length body and the trailing integrity check
        bytes = recv(clientSocket, buffer + sizeof(Communication::PacketHeader), head.Length + sizeof(uint32_t), MSG_WAITALL); //-V2563

        // If recv returns 0, the connection was closed gracefully by the server/airplane
        // If recv returns -1 (SOCKET_ERROR), the connection was lost or aborted
        if (bytes <= 0) {
            std::cout << "\n[ALERT] Communication lost. The aircraft has disconnected." << std::endl;

            // Signal the main loop to stop
            shouldStopClient = true;
        }

        else {
            //  Confirm the packet arrived without corruption via a CRC check
            if (ValidatePacket(buffer)) {
                Communication::Packet rxPkt(buffer);
                std::string msgContent(rxPkt.GetData(), rxPkt.GetBodyLength());

                // Divert telemetry data to a file while showing text on the console
                if (head.MessageType == 1) {
                    // Write telemetry chunks to a dedicated file for later analysis
                    std::ofstream telemFile("received_telemetry.txt", std::ios::app);
                    telemFile << msgContent << std::endl;
                    telemFile.close();
                    std::cout << "\n[SYSTEM] Telemetry chunk saved to disk." << std::endl;
                }

                else if (msgContent == "Connected") {
                    // Alert the operator that a specific airplane has entered the airspace
                    std::cout << "\n[ALERT] Airplane " << head.FlightID << " has connected." << std::endl;
                }

                else {
                    // Render standard communications for the ground control operator
                    rxPkt.DisplayGroundControlSide(std::cout);
                };

                // ALog the reception event including the full raw header state
                logger.Log(head.FlightID, 0, msgContent, head);
            };
        };

        // Release the heap buffer to prevent resource leaks / Memory clean up
        delete[] buffer;  //Deletes dynamically allocated memory
        buffer = nullptr;
    };

    if (shouldStopClient) {
        isRunning = false;
    };
};

/**
 * Verifies that the data received from the network matches the checksum
 * calculated by the sender, ensuring transmission accuracy.
 */
bool Client::GroundControlClient::ValidatePacket(const char* buffer) const {
    Communication::PacketHeader head;
    (void)std::memcpy(&head, buffer, sizeof(Communication::PacketHeader));

    // Focus the CRC check on the header and body combined
    unsigned int payloadSize = sizeof(Communication::PacketHeader) + head.Length;

    // Re-calculate the checksum locally using the same algorithm as the sender
    uint32_t computed = Checksum::CRC32::Calculate(buffer, payloadSize);

    // Retrieve the checksum that was appended to the packet by the sender
    uint32_t received;
    (void)std::memcpy(&received, buffer + payloadSize, sizeof(uint32_t)); //-V2563

    // Check for a match between local calculation and received value
    return (computed == received);
}

/**
 * Manages the high-level communication flow, strictly enforcing that the
 * client waits for an airplane message before permitting a response.
 */
void Client::GroundControlClient::Run() {
    std::cout << "Waiting for In-Flight Client check-in...\n";

    while (isRunning) {
        // Enforce the ordered communication requirement by blocking on reception
        receiveMessage();

        // Break the loop if the connection was lost during the wait
        if (!isRunning) { 
            break;
        };

        // Allow user input only after a message has been successfully received
        std::cout << "Enter Reply: ";
        std::string reply;
        (void)std::getline(std::cin, reply);

        // Forward the operator's response back to the airplane
        sendMessage(0, reply);
    }
}

/**
 * Provides a safe cleanup mechanism for socket handles to prevent
 * attempts to use an already-closed connection.
 */
void Client::GroundControlClient::CloseSocket(SOCKET* sock) {
    if (*sock != INVALID_SOCKET) {
        (void)closesocket(*sock);
        *sock = INVALID_SOCKET;
    }
}

/**
 * Coordinates the orderly termination of the client by stopping loops
 * and cleaning up the Winsock environment.
 */
void Client::GroundControlClient::Shutdown() {
    isRunning = false;
    CloseSocket(&clientSocket);
    (void)WSACleanup();
}


