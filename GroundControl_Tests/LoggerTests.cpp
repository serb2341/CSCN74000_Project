#include "pch.h"
#include "CppUnitTest.h"

#include "../GroundControlClient/Logger.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

static const std::string TEST_LOG_FILE = "unit_test_logger_output.txt";

// Helper function to delete the test log file if it exists
static void CleanupLogFile()
{
    std::remove(TEST_LOG_FILE.c_str());
}

// Helper function to read the entire log file into a string
static std::string ReadLogFile()
{
    std::ifstream f(TEST_LOG_FILE);
    std::string content((std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    return content;
}



namespace GroundControl_Tests {
    TEST_CLASS(LoggerTests) {
public:


    // After constructing a Logger, the file should exist on disk
    TEST_METHOD(GC_Logger_TEST01_Constructor_CreatesFile)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            // destructor closes file
        }
        std::ifstream f(TEST_LOG_FILE);
        Assert::IsTrue(f.good());
        CleanupLogFile();
    }

    // Log writes content that contains the message string
    TEST_METHOD(GC_Logger_TEST02_Log_WritesMessageToFile)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            hdr.FlightID = 1u;
            hdr.MessageType = 0u;
            hdr.Length = 5u;
            hdr.TimeStamp = 0u;
            log.Log(1u, 0u, "TestMessage", hdr);
        }
        std::string content = ReadLogFile();
        Assert::IsTrue(content.find("TestMessage") != std::string::npos);
        CleanupLogFile();
    }

    // Log entry contains SRC and DEST values
    TEST_METHOD(GC_Logger_TEST03_Log_ContainsSrcAndDest)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            log.Log(42u, 99u, "SrcDestTest", hdr);
        }
        std::string content = ReadLogFile();
        Assert::IsTrue(content.find("42") != std::string::npos);
        Assert::IsTrue(content.find("99") != std::string::npos);
        CleanupLogFile();
    }

    // Log entry contains the FlightID from the header
    TEST_METHOD(GC_Logger_TEST04_Log_ContainsFlightID)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            hdr.FlightID = 777u;
            log.Log(0u, 0u, "FlightTest", hdr);
        }
        std::string content = ReadLogFile();
        Assert::IsTrue(content.find("777") != std::string::npos);
        CleanupLogFile();
    }

    // Multiple Log calls should append (all messages present in file)
    TEST_METHOD(GC_Logger_TEST05_Log_MultipleCalls_AllMessagesPresent)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            log.Log(1u, 2u, "MessageOne", hdr);
            log.Log(1u, 2u, "MessageTwo", hdr);
            log.Log(1u, 2u, "MessageThree", hdr);
        }
        std::string content = ReadLogFile();
        Assert::IsTrue(content.find("MessageOne") != std::string::npos);
        Assert::IsTrue(content.find("MessageTwo") != std::string::npos);
        Assert::IsTrue(content.find("MessageThree") != std::string::npos);
        CleanupLogFile();
    }

    // Destructor should close the file (subsequent Logger opens in append mode)
    TEST_METHOD(GC_Logger_TEST06_AppendMode_SecondLoggerAppendsNotOverwrites)
    {
        CleanupLogFile();
        {
            Logging::Logger log1(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            log1.Log(1u, 2u, "First", hdr);
        }
        {
            Logging::Logger log2(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            log2.Log(1u, 2u, "Second", hdr);
        }
        std::string content = ReadLogFile();
        Assert::IsTrue(content.find("First") != std::string::npos);
        Assert::IsTrue(content.find("Second") != std::string::npos);
        CleanupLogFile();
    }

    // Log with empty message string should not crash
    TEST_METHOD(GC_Logger_TEST07_Log_EmptyMessage_DoesNotCrash)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            log.Log(0u, 0u, "", hdr);
        }
        // If we get here without crashing the test passes
        Assert::IsTrue(true);
        CleanupLogFile();
    }

    // Log header fields (MessageType, Length, TimeStamp) appear in output
    TEST_METHOD(GC_Logger_TEST08_Log_ContainsHeaderFields)
    {
        CleanupLogFile();
        {
            Logging::Logger log(TEST_LOG_FILE);
            Communication::PacketHeader hdr{};
            hdr.FlightID = 10u;
            hdr.MessageType = 5u;
            hdr.Length = 20u;
            hdr.TimeStamp = 999u;
            log.Log(10u, 0u, "HeaderFieldTest", hdr);
        }
        std::string content = ReadLogFile();
        Assert::IsTrue(content.find("5") != std::string::npos); // MessageType
        Assert::IsTrue(content.find("20") != std::string::npos); // Length
        Assert::IsTrue(content.find("999") != std::string::npos); // TimeStamp
        CleanupLogFile();
    }
};

};