#include "pch.h"
#include "CppUnitTest.h"

#include "../Server/Logger.h"

#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdio>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ServerTests {
    // Reads the entire content of a file into a string.
    static std::string ReadFile(const std::string& path) {
        std::ifstream f(path);

        if (!f.is_open()) {    
            return "";
        };

        return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    };

    // Deletes a file if it exists — used for test cleanup.
    static void DeleteTestFile(const std::string& path) {
        std::remove(path.c_str());
    };

    TEST_CLASS(LoggerTests) {
    public:

        // --------------------------------------------------------
        // Start / Stop
        // --------------------------------------------------------

        TEST_METHOD(SVR_LOG_TEST_001_Start_ValidPath_ReturnsTrue) {
            ServerLogging::Logger logger;

            const std::string path = "test_start.txt";

            bool result = logger.Start(path);

            logger.Stop();

            DeleteTestFile(path);

            Assert::IsTrue(result, L"Logger::Start must return true when given a valid file path.");
        };

        TEST_METHOD(SVR_LOG_TEST_002_Start_CreatesFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_creates.txt";

            DeleteTestFile(path);

            logger.Start(path);
            logger.Stop();

            std::ifstream f(path);

            bool exists = f.is_open();

            f.close();

            DeleteTestFile(path);

            Assert::IsTrue(exists, L"Logger::Start must create the log file on disk.");
        };

        TEST_METHOD(SVR_LOG_TEST_003_Stop_CanBeCalledTwice_DoesNotCrash) {
            ServerLogging::Logger logger;
            const std::string path = "test_doublestop.txt";

            logger.Start(path);

            logger.Stop();
            logger.Stop();  // second call must be safe

            DeleteTestFile(path);

            Assert::IsTrue(true, L"Calling Stop() twice must not crash.");
        };

        // --------------------------------------------------------
        // Log — entries written to file
        // --------------------------------------------------------

        TEST_METHOD(SVR_LOG_TEST_004_Log_EntryAppearsInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_entry.txt";

            DeleteTestFile(path);

            logger.Start(path);

            logger.Log("TEST_ENTRY_12345");

            // Give logger thread time to flush.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("TEST_ENTRY_12345") != std::string::npos, L"A logged entry must appear in the output file.");
        };

        TEST_METHOD(SVR_LOG_TEST_005_Log_MultipleEntries_AllAppearInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_multi.txt";

            DeleteTestFile(path);

            logger.Start(path);

            logger.Log("ENTRY_ONE");
            logger.Log("ENTRY_TWO");
            logger.Log("ENTRY_THREE");

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("ENTRY_ONE") != std::string::npos, L"ENTRY_ONE must be in log.");
            Assert::IsTrue(content.find("ENTRY_TWO") != std::string::npos, L"ENTRY_TWO must be in log.");
            Assert::IsTrue(content.find("ENTRY_THREE") != std::string::npos, L"ENTRY_THREE must be in log.");
        };

        TEST_METHOD(SVR_LOG_TEST_006_Log_EntriesWrittenInOrder) {
            ServerLogging::Logger logger;

            const std::string path = "test_order.txt";

            DeleteTestFile(path);

            logger.Start(path);

            logger.Log("FIRST");
            logger.Log("SECOND");
            logger.Log("THIRD");

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            size_t posFirst = content.find("FIRST");
            size_t posSecond = content.find("SECOND");
            size_t posThird = content.find("THIRD");

            Assert::IsTrue(posFirst < posSecond, L"FIRST must appear before SECOND in log.");
            Assert::IsTrue(posSecond < posThird, L"SECOND must appear before THIRD in log.");
        };

        // --------------------------------------------------------
        // Formatting helpers — verify fields appear in output
        // --------------------------------------------------------

        TEST_METHOD(SVR_LOG_TEST_007_LogStateTransition_FieldsAppearInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_state.txt";

            DeleteTestFile(path);

            logger.Start(path);
            logger.LogStateTransition("SERVER", "LISTENING", "VERIFICATION");

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("[STATE]") != std::string::npos, L"[STATE] tag must be present.");
            Assert::IsTrue(content.find("LISTENING") != std::string::npos, L"From-state must appear.");
            Assert::IsTrue(content.find("VERIFICATION") != std::string::npos, L"To-state must appear.");
            Assert::IsTrue(content.find("SERVER") != std::string::npos, L"Entity name must appear.");
        };

        TEST_METHOD(SVR_LOG_TEST_008_LogHandshake_FieldsAppearInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_handshake.txt";

            DeleteTestFile(path);

            logger.Start(path);
            logger.LogHandshake("Ground Control", "SERVER", "CHALLENGE", 0xDEADBEEFU, "Random");

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("[HANDSHAKE]") != std::string::npos, L"[HANDSHAKE] tag must be present.");
            Assert::IsTrue(content.find("Ground Control") != std::string::npos, L"Source must appear.");
            Assert::IsTrue(content.find("CHALLENGE") != std::string::npos, L"Packet type must appear.");
            Assert::IsTrue(content.find("DEADBEEF") != std::string::npos, L"Random value (hex) must appear.");
        };

        TEST_METHOD(SVR_LOG_TEST_009_LogSecurityException_FieldsAppearInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_security.txt";

            DeleteTestFile(path);

            logger.Start(path);
            logger.LogSecurityException("Airplane", "Step 1: CRC-32 validation failed.");

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("[SECURITY]") != std::string::npos, L"[SECURITY] tag must be present.");
            Assert::IsTrue(content.find("Airplane") != std::string::npos, L"Client name must appear.");
            Assert::IsTrue(content.find("CRC-32") != std::string::npos, L"Reason must appear.");
        };

        TEST_METHOD(SVR_LOG_TEST_010_LogPacket_AllFieldsAppearInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_packet.txt";

            DeleteTestFile(path);

            logger.Start(path);
            logger.LogPacket("101", "Ground Control", 101U, 2U, 55U, 128U, nullptr);

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("[PACKET]") != std::string::npos, L"[PACKET] tag must be present.");
            Assert::IsTrue(content.find("101") != std::string::npos, L"FlightID must appear.");
            Assert::IsTrue(content.find("Ground Control") != std::string::npos, L"Destination must appear.");
        };

        TEST_METHOD(SVR_LOG_TEST_011_LogDisconnect_FieldsAppearInFile) {
            ServerLogging::Logger logger;

            const std::string path = "test_disconnect.txt";

            DeleteTestFile(path);

            logger.Start(path);
            logger.LogDisconnect("Ground Control");

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            logger.Stop();

            std::string content = ReadFile(path);
            DeleteTestFile(path);

            Assert::IsTrue(content.find("[DISCONNECT]") != std::string::npos, L"[DISCONNECT] tag must be present.");
            Assert::IsTrue(content.find("Ground Control") != std::string::npos, L"Client name must appear.");
        };

        // --------------------------------------------------------
        // Non-blocking guarantee (US-41)
        // --------------------------------------------------------

        TEST_METHOD(SVR_LOG_TEST_012_Log_DoesNotBlockCaller) {
            // The relay thread must not wait for file I/O.
            // Log() should return in well under 10ms even with 100 entries.
            ServerLogging::Logger logger;

            const std::string path = "test_nonblocking.txt";

            DeleteTestFile(path);

            logger.Start(path);

            auto start = std::chrono::steady_clock::now();

            for (int i = 0; i < 100; ++i)
            {
                logger.Log("NON_BLOCKING_ENTRY");
            }

            auto end = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            logger.Stop();
            DeleteTestFile(path);

            // 100 enqueue calls should complete in well under 100ms total.
            Assert::IsTrue(ms < 100LL, L"Logger::Log must be non-blocking — 100 calls should complete in under 100ms.");
        };
    };
};