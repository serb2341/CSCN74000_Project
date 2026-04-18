#pragma once
#include <string>
#include <fstream>
#include <ctime>
#include "Packet.h"

namespace GroundControlLogging {
    class Logger {
    private:
        std::ofstream logFile;
    public:
        Logger(const std::string& filename);
        ~Logger();

        // This function logs a message with source and destination IDs, along with a timestamp. The PacketHeader can be used to include additional metadata if needed.
        void Log(unsigned int src, unsigned int dest, const std::string& msg, const GroundControlCommunication::PacketHeader& header);
    };
};