#pragma once
#include <thread>
#include <atomic>
#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>


#pragma once
#include <string>
#include <fstream>
#include <ctime>
#include "Packet.h"

namespace Logging {
    class Logger {
    private:
        std::ofstream logFile;
    public:
        Logger(const std::string& filename);

        ~Logger();

        void Log(const char* message, unsigned int size);
    };
};