#pragma once

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace ServerLogging {
	// Maximum number of entries the queue can hold before drops occur.
	static const unsigned int LOG_QUEUE_MAX = 500U;

	class Logger {
	private:
		std::queue<std::string> queue;
		std::mutex mutex;
		std::condition_variable cv;
		std::thread thread;
		std::ofstream file;
		std::atomic<bool> isRunning;

		// This is used for ms timestamps.
		std::chrono::steady_clock::time_point startTime;

		// This logger thread functions empties the queue and writes to a file.
		void LoggerThreadFunc();

		// Returns elapsed ms since Start() was called.
		unsigned long long ElapsedMs() const;

		// Builds the timestamp prefix string: "[00123ms]".
		std::string TimestampPrefix() const;

		std::string ToHexString(const char* data, unsigned int length);

	public:
		Logger();

		~Logger();

		// Opens the log file and starts the logger thread.
		// logFilePath is the path to the output .txt file.
		// Return true on Success.
		bool Start(const std::string& logFilePath);

		// Signals the logger thread to flush remaining entries and stop.
		// Blocks until the thread has exited.
		void Stop();

		// Enqueues a pre-formatted log entry for writing.
		// Non-blocking - returns immediately.
		// If the queue is full, drops the entry and prints a console warning.
		void Log(const std::string& entry);

		// Logs a server wide state transition.
		void LogStateTransition(const std::string& entity, const std::string& fromState, const std::string& toState);

		// Logs a per-client state transition inside a relay thread.
		void LogClientStateTransition(const std::string& clientName, const std::string& fromState, const std::string& toState);

		// Logs one of the 4 handshake packets.
		// value = Random or Signature.
		// valueLabel = "Random" or "Signature".
		void LogHandshake(const std::string& source, const std::string& destination, const std::string& packetType, uint32_t value, const std::string& valueLabel);

		// Logs a security exception (handshake failure).
		void LogSecurityException(const std::string& clientName, const std::string& reason);

		// Logs a relayed data packet header.
		void LogPacket(const std::string& source, const std::string& destination, unsigned int flightID, unsigned int messageType, unsigned int length, uint32_t timeStamp, const char* body);

		// Logs a client disconnect event.
		void LogDisconnect(const std::string& clientName);
	};
};