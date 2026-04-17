#include "Logger.h"

Logging::Logger::Logger() {
	this->isRunning = false;
};

Logging::Logger::~Logger() {
	this->Stop();
};

// ============================================================
//  Start / Stop
// ============================================================

bool Logging::Logger::Start(const std::string& logFilePath) {
	bool isFileOpeningSuccessful = false;

	this->file.open(logFilePath, std::ios::out | std::ios::app);

	if (!this->file.is_open()) {
		std::cerr << "[Logger] Failed to open log file: " << logFilePath << std::endl;

		isFileOpeningSuccessful = false;
	}

	else {
		this->startTime = std::chrono::steady_clock::now();

		this->isRunning = true;

		this->thread = std::thread(&Logger::LoggerThreadFunc, this);

		std::cout << "[Logger] Started. Writing to: " << logFilePath << std::endl;

		isFileOpeningSuccessful = true;
	};

	return isFileOpeningSuccessful;
};

void Logging::Logger::Stop() {
	{
		std::lock_guard<std::mutex> lock(this->mutex);

		this->isRunning = false;
	};

	// Waking the logger thread so it can drain remaining entries and exit.
	this->cv.notify_all();

	if (this->thread.joinable()) {
		this->thread.join();
	};
	
	if (this->file.is_open()) {
		(void)this->file.flush();

		this->file.close();
	};
};

// ============================================================
//  Log — non-blocking enqueue
// ============================================================

void Logging::Logger::Log(const std::string& entry) {
	std::lock_guard<std::mutex> lock(this->mutex);

	if (this->queue.size() >= LOG_QUEUE_MAX) {
		// Queue is full so we drop the entry and warn on console.
		std::cerr << "[Logger] WARNING: Log queue full. Entry dropped." << std::endl;

		return;
	};

	this->queue.push(entry);

	this->cv.notify_one();
};

// ============================================================
//  Logger thread — drains queue and writes to file
// ============================================================

void Logging::Logger::LoggerThreadFunc() {
	while (true) {
		std::unique_lock<std::mutex> lock(this->mutex);

		// Wait until there is something in the queue or we are stopping.
		this->cv.wait(lock, [this]
			{
				return !(this->queue.empty()) || !(this->isRunning);
			}
		);

		// Drain everything currently in the queue under the lock.
		std::queue<std::string> localQueue;

		std::swap(localQueue, this->queue);

		lock.unlock();


		// Write to file outside the lock so relay threads are never blocked by file.
		while (!(localQueue.empty())) {
			if (this->file.is_open()) {
				// If the OS has locked the file, is_open() is still true but
				// write will fail silently so we catch this via fail() and
				// continue relaying without crashing.
				this->file << localQueue.front() << "\n";

				if (this->file.fail()) {
					std::cerr << "[Logger] WARNING: File write failed (OS lock?). Entry skipped." << std::endl;

					this->file.clear(); // Clear error state so next write can try again.
				};
			};

			localQueue.pop();
		};

		(void)this->file.flush();

		// Exit only after the queue is fully drained.
		if (!this->isRunning) {
			std::lock_guard<std::mutex> exitLock(this->mutex);

			if (this->queue.empty()) {
				break;
			};
		};
	};
};


// ============================================================
//  Formatting helpers
// ============================================================

unsigned long long Logging::Logger::ElapsedMs() const {
	auto now = std::chrono::steady_clock::now();

	return static_cast<unsigned long long>(
		std::chrono::duration_cast<std::chrono::milliseconds>(now - this->startTime).count()
	);
};

std::string Logging::Logger::TimestampPrefix() const {
	auto now = std::chrono::system_clock::now();

	std::time_t now_c = std::chrono::system_clock::to_time_t(now);

	std::tm parts;

	// Using localtime_s on windows for thread safety.
	(void)localtime_s(&parts, &now_c);

	std::ostringstream oss;

	oss << "[" << std::setfill('0')
		<< std::setw(2) << parts.tm_mday << "/"
		<< std::setw(2) << (parts.tm_mon + 1) << "/"
		<< (parts.tm_year + 1900) << " "
		<< std::setw(2) << parts.tm_hour << ":"
		<< std::setw(2) << parts.tm_min << ":"
		<< std::setw(2) << parts.tm_sec << "]";

	return oss.str();

	/*std::ostringstream oss;

	oss << "[" << std::setw(7) << std::setfill('0') << this->ElapsedMs() << "ms]";

	return oss.str();*/
};

void Logging::Logger::LogStateTransition(const std::string& entity, const std::string& fromState, const std::string& toState) {
	std::ostringstream oss;

	oss << this->TimestampPrefix() << " [STATE]		" << entity << ": " << fromState << " --> " << toState;

	this->Log(oss.str());
};

void Logging::Logger::LogClientStateTransition(const std::string& clientName, const std::string& fromState, const std::string& toState) {
	std::ostringstream oss;

	oss << this->TimestampPrefix() << " [STATE]		" << clientName << ": " << fromState << " --> " << toState;

	this->Log(oss.str());
};

void Logging::Logger::LogHandshake(const std::string& source, const std::string& destination, const std::string& packetType, uint32_t value, const std::string& valueLabel) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [HANDSHAKE] "
		<< "Source: " << source
		<< " | Dest: " << destination
		<< " | Type: " << packetType
		<< " | " << valueLabel
		<< ": 0x" << std::uppercase << std::hex
		<< std::setw(8) << std::setfill('0') << value;

	Log(oss.str());
};

void Logging::Logger::LogSecurityException(const std::string& clientName, const std::string& reason) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [SECURITY]  "
		<< clientName << " | " << reason;

	Log(oss.str());
};

void Logging::Logger::LogPacket(const std::string& source, const std::string& destination, unsigned int flightID, unsigned int messageType, unsigned int length, uint32_t timeStamp, const char* buffer) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [PACKET]    "
		<< "Source: " << source
		<< " | Dest: " << destination
		<< " | FlightID: " << std::dec << flightID
		<< " | MsgType: " << messageType
		<< " | Length: " << length
		<< " | TimeStamp: " << timeStamp
		<< " | Body: ";

	// Log the body if it exists
	if (length > 0 && buffer != nullptr) {
		(void)oss.write(buffer, length);
	}

	else if (length > 0) {
		oss << "[DATA MISSING]";
	}

	else {
		oss << "[EMPTY]";
	};


	// Log the CRC32.
	if (buffer != nullptr) {
		uint32_t CRCvalue;

		(void)std::memcpy(&CRCvalue, buffer + length, sizeof(uint32_t)); //-V2563

		oss << " | CRC32: "
			<< "0x" << std::uppercase << std::hex
			<< std::setw(8) << std::setfill('0') << CRCvalue;
	};

	this->Log(oss.str());
};

void Logging::Logger::LogDisconnect(const std::string& clientName) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [DISCONNECT] "
		<< clientName << " disconnected.";

	Log(oss.str());
};

// Helper to convert raw bytes to Hex
std::string Logging::Logger::ToHexString(const char* data, unsigned int length) {
	std::ostringstream oss;

	for (unsigned int i = 0; i < length; ++i) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(data[i]) & 0xFF) << " "; //-V2563
	};

	return oss.str();
};