#pragma once
#include <thread>
#include <atomic>
#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>

class Logger {
private:
    std::ofstream logFile;
public:
    Logger(const std::string& filename)
    {
        logFile.open(filename, std::ios::app);

        if (!logFile.is_open())
        {
            std::cerr << "[Logger] Failed to open log file.\n";
        }
    }

    ~Logger()
    {
        if (logFile.is_open())
        {
            logFile.close();
        }
    }

    void Log(const char* message, unsigned int size)
    {
        std::time_t now = std::time(nullptr);
        char timeStr[26];
        ctime_s(timeStr, sizeof(timeStr), &now);

        // Remove newline from ctime
        std::string timestamp(timeStr);
        timestamp.pop_back();
        
        if (logFile.is_open())
        {
            logFile << "[" << timestamp << "] ";

            logFile.write(message, size);

            logFile << std::endl;
        }

    }
};