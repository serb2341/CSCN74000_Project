#include "pch.h"

#include "gtest/gtest.h"

#include "..\InFlightClient\Logger.h"

#include <fstream>
#include <cstdio>


namespace InFlightClientTests
{
    // ------------------------------------------------------
    // Logger Test Class
    // ------------------------------------------------------
    class LoggerTests : public ::testing::Test {
    protected:

        // Removes all of the created files at end of testing
        void TearDown() override {
            std::remove("test_logger.txt");
        }
    };


    // Tests that logger creates a file if it does not exist
    TEST_F(LoggerTests, FLIGHT_CLT_LOG_TEST_001_Log_CreatesFile_DoesNotExist)
    {
        // Arrange
        const std::string filename = "test_logger.txt";

        std::remove("test_logger.txt");

        // Act
        InFlightLogging::Logger logger(filename);

        std::ifstream file(filename);
        
        // Assert
        ASSERT_TRUE(file.is_open());
    }

    // Tests that logger works when file already exists
    TEST_F(LoggerTests, FLIGHT_CLT_LOG_TEST_002_Log_OpensFile)
    {
        // Arrange
        const std::string filename = "test_logger.txt";

        InFlightLogging::Logger logger_first(filename);

        // Act
        InFlightLogging::Logger logger_second(filename);

        std::ifstream file(filename);

        // Assert
        ASSERT_TRUE(file.is_open());
    }

    // Tests that logger successfully writes to file
    TEST_F(LoggerTests, FLIGHT_CLT_LOG_TEST_003_Log_WritesToFile)
    {
        // Arrange
        const std::string filename = "test_logger.txt";
        InFlightLogging::Logger logger(filename);
        const char msg[] = "LOG_TEST_MESSAGE";

        // Act
        logger.Log(msg, sizeof(msg) - 1);

        std::ifstream file(filename);

        std::string line;
        std::getline(file, line);

        // Assert
        EXPECT_NE(line.find("LOG_TEST_MESSAGE"), std::string::npos);
        EXPECT_NE(line.find('['), std::string::npos);
        EXPECT_NE(line.find(']'), std::string::npos);
    }

    // Tests that logger writes empty message to file
    TEST_F(LoggerTests, FLIGHT_CLT_LOG_TEST_004_Log_WritesToFile_EmptyMessage)
    {
        // Arrange
        const std::string filename = "test_logger.txt";
        InFlightLogging::Logger logger(filename);
        const char msg[] = "";

        // Act
        logger.Log(msg, sizeof(msg) - 1);

        std::ifstream file(filename);
        ASSERT_TRUE(file.is_open());

        std::string line;
        std::getline(file, line);

        // Assert
        EXPECT_NE(line.find('['), std::string::npos);
        EXPECT_NE(line.find(']'), std::string::npos);
    }

    // Tests that logger writes multiple lines to file
    TEST_F(LoggerTests, FLIGHT_CLT_LOG_TEST_005_Log_WritesMultipleLinesToFile)
    {
        // Arrange
        const std::string filename = "test_logger.txt";
        InFlightLogging::Logger logger(filename);
        const char msg1[] = "LOG1_TEST_MESSAGE";
        const char msg2[] = "LOG2_TEST_MESSAGE";
        const char msg3[] = "LOG3_TEST_MESSAGE";

        // Act
        logger.Log(msg1, sizeof(msg1) - 1);
        logger.Log(msg2, sizeof(msg2) - 1);
        logger.Log(msg3, sizeof(msg3) - 1);

        std::ifstream file(filename);

        std::string line;

        // Assert
        std::getline(file, line);
        EXPECT_NE(line.find("LOG1_TEST_MESSAGE"), std::string::npos);
        std::getline(file, line);
        EXPECT_NE(line.find("LOG2_TEST_MESSAGE"), std::string::npos);
        std::getline(file, line);
        EXPECT_NE(line.find("LOG3_TEST_MESSAGE"), std::string::npos);
    }

    // Tests that logger writes to file in order
    TEST_F(LoggerTests, FLIGHT_CLT_LOG_TEST_006_Log_WritesToFileInOrder)
    {
        // Arrange
        const std::string filename = "test_logger.txt";
        InFlightLogging::Logger logger(filename);
        const char msg1[] = "LOG1_TEST_MESSAGE";
        const char msg2[] = "LOG2_TEST_MESSAGE";
        const char msg3[] = "LOG3_TEST_MESSAGE";

        // Act
        logger.Log(msg1, sizeof(msg1) - 1);
        logger.Log(msg2, sizeof(msg2) - 1);
        logger.Log(msg3, sizeof(msg3) - 1);

        std::ifstream file(filename);

        std::string line1, line2, line3;

        std::getline(file, line1);
        std::getline(file, line2);
        std::getline(file, line3);

        EXPECT_NE(line1.find("LOG1_TEST_MESSAGE"), std::string::npos);
        EXPECT_NE(line2.find("LOG2_TEST_MESSAGE"), std::string::npos);
        EXPECT_NE(line3.find("LOG3_TEST_MESSAGE"), std::string::npos);
    }
}