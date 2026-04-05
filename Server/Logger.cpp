#include "Logger.h"

Logger::Logger() {
	this->isRunning = false;
};

Logger::~Logger() {
	this->Stop();
};

// ============================================================
//  Start / Stop
// ============================================================

bool Logger::Start(const std::string& logFilePath) {
	this->file.open(logFilePath, std::ios::out | std::ios::app);

	if (!this->file.is_open()) {
		std::cerr << "[Logger] Failed to open log file: " << logFilePath << std::endl;

		return false;
	};

	this->startTime = std::chrono::steady_clock::now();

	this->isRunning = true;

	this->thread = std::thread(&Logger::LoggerThreadFunc, this);

	std::cout << "[Logger] Started. Writing to: " << logFilePath << std::endl;

	return true;
};

void Logger::Stop() {
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
		this->file.flush();

		this->file.close();
	};
};

// ============================================================
//  Log — non-blocking enqueue
// ============================================================

void Logger::Log(const std::string& entry) {
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

void Logger::LoggerThreadFunc() {
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

		this->file.flush();

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

unsigned long long Logger::ElapsedMs() const {
	auto now = std::chrono::steady_clock::now();

	return static_cast<unsigned long long>(
		std::chrono::duration_cast<std::chrono::milliseconds>(now - this->startTime).count()
	);
};

std::string Logger::TimestampPrefix() const {
	std::ostringstream oss;

	oss << "[" << std::setw(7) << std::setfill('0') << this->ElapsedMs() << "ms]";

	return oss.str();
};

void Logger::LogStateTransition(const std::string& entity, const std::string& fromState, const std::string& toState) {
	std::ostringstream oss;

	oss << this->TimestampPrefix() << " [STATE]		" << entity << ": " << fromState << " --> " << toState;

	this->Log(oss.str());
};

void Logger::LogClientStateTransition(const std::string& clientName, const std::string& fromState, const std::string& toState) {
	std::ostringstream oss;

	oss << this->TimestampPrefix() << " [STATE]		" << clientName << ": " << fromState << " --> " << toState;

	this->Log(oss.str());
};

void Logger::LogHandshake(const std::string& source, const std::string& destination, const std::string& packetType, uint32_t value, const std::string& valueLabel) {
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

void Logger::LogSecurityException(const std::string& clientName, const std::string& reason) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [SECURITY]  "
		<< clientName << " | " << reason;

	Log(oss.str());
};

void Logger::LogPacket(const std::string& source, const std::string& destination, unsigned int flightID, unsigned int messageType, unsigned int length, uint32_t timeStamp) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [PACKET]    "
		<< "Source: " << source
		<< " | Dest: " << destination
		<< " | FlightID: " << std::dec << flightID
		<< " | MsgType: " << messageType
		<< " | Length: " << length
		<< " | TimeStamp: " << timeStamp;

	Log(oss.str());
};

void Logger::LogDisconnect(const std::string& clientName) {
	std::ostringstream oss;

	oss << TimestampPrefix()
		<< " [DISCONNECT] "
		<< clientName << " disconnected.";

	Log(oss.str());
};