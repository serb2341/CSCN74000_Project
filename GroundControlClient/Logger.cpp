#include "Logger.h"
#include <iostream>


/**
 * Constructor: Opens the log file in "Append" mode.
 * This ensures that new logs are added to the end of the file rather than
 * overwriting previous flight data.
 */
Logging::Logger::Logger(const std::string& filename) {

    // Open the file with the app (append) flag.
    logFile.open(filename, std::ios::app);

    // Verify if the file was successfully opened to prevent silent failures.
    if (!logFile.is_open()){
        std::cerr << "[Logger] Failed to open log file.\n";}
}


/**
 * Destructor: Ensures the file stream is safely closed when the
 * Logger object goes out of scope, preventing memory leaks or file corruption.
 */
Logging::Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}


/**
 * Formats and writes communication data to the log file.
 * This function captures Source, Destination, and the technical content of the Packet Header.
 */
void Logging::Logger::Log(unsigned int src, unsigned int dest, const std::string& msg, const Communication::PacketHeader& header) {

    // Captures current system time for chronological tracking.
    std::time_t now = std::time(nullptr);
    char timeStr[26];
    (void)ctime_s(&timeStr[0], sizeof(timeStr), &now);

    // Clean up the timestamp string by removing the trailing newline character.
    std::string ts(timeStr);
    if (!ts.empty() && ts.back() == '\n') {
        ts.pop_back();
    };

	// Write to file with structured formatting for clarity. 
    // Each log entry includes the timestamp, source, destination, header details, and the message content.
    if (logFile.is_open()) {
        logFile << "[" << ts << "] SRC: " << src << " | DEST: " << dest << "\n"
            << "HEADER CONTENT -> FlightID: " << header.FlightID
            << " | Type: " << header.MessageType
            << " | Len: " << header.Length
            << " | TS: " << header.TimeStamp << "\n"
            << "MESSAGE: " << msg << "\n" << std::endl;
        (void)logFile.flush();
    }
}