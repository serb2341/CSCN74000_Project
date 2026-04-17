#pragma once

#include "Logger.h"



Logging::Logger::Logger(const std::string& filename)
    {
        logFile.open(filename, std::ios::app);

        if (!logFile.is_open())
        {
            std::cerr << "[Logger] Failed to open log file.\n";
        }
    }

Logging::Logger::~Logger()
    {
        if (logFile.is_open())
        {
            logFile.close();
        }
    }

void Logging::Logger::Log(const char* message, unsigned int size)
{
    std::time_t now = std::time(nullptr);
    char timeStr[26];
    (void)ctime_s(&timeStr[0], sizeof(timeStr), &now);

    // Remove newline from ctime
    std::string timestamp(timeStr);
    timestamp.pop_back();

    if (logFile.is_open())
    {
        logFile << "[" << timestamp << "] ";

        (void)logFile.write(message, size);

        logFile << std::endl;
    }

}