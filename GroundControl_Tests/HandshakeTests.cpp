#include "pch.h"
#include "CppUnitTest.h"

#include "../GroundControlClient/VerificationPacket.h"
#include "../GroundControlClient/Packet.h"
#include "../GroundControlClient/Handshake.h"


#include <cstring>
#include <fstream>
#include <string>
#include <filesystem>
#include <vector>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// Helper function: writes a temp config file and returns its path
static std::string WriteTempConfig(const std::string& content)
{
    std::string path = "temp_test_config.txt";
    std::ofstream f(path, std::ios::trunc);
    f << content;
    f.close();
    return path;
}

namespace GroundControl_Tests
{
    TEST_CLASS(HandshakeTests)
    {
    public:

        // Standard well-formed config
        TEST_METHOD(GC_Handshake_TEST01_LoadSecret_ValidConfig_ReturnsSecret)
        {
            std::string path = WriteTempConfig("SECRET=mysecretkey\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::AreEqual(std::string("mysecretkey"), secret);
        }

        // Config with comment lines before the secret
        TEST_METHOD(GC_Handshake_TEST02_LoadSecret_CommentLines_SkipsThemAndFindsSecret)
        {
            std::string path = WriteTempConfig("# This is a comment\nSECRET=abc123\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::AreEqual(std::string("abc123"), secret);
        }

        // Config with blank lines before the secret
        TEST_METHOD(GC_Handshake_TEST03_LoadSecret_BlankLinesBeforeSecret_StillFindsSecret)
        {
            std::string path = WriteTempConfig("\n\nSECRET=blanktest\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::AreEqual(std::string("blanktest"), secret);
        }

        // Secret appears after other key-value pairs
        TEST_METHOD(GC_Handshake_TEST04_LoadSecret_OtherKeysPresent_FindsCorrectKey)
        {
            std::string path = WriteTempConfig("HOST=localhost\nPORT=54000\nSECRET=rightkey\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::AreEqual(std::string("rightkey"), secret);
        }

        // No SECRET key present → should return empty string
        TEST_METHOD(GC_Handshake_TEST05_LoadSecret_MissingKey_ReturnsEmpty)
        {
            std::string path = WriteTempConfig("HOST=localhost\nPORT=54000\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::IsTrue(secret.empty());
        }

        // File does not exist → should return empty string (not crash)
        TEST_METHOD(GC_Handshake_TEST06_LoadSecret_NonexistentFile_ReturnsEmpty)
        {
            std::string secret = MutualVerification::Handshake::LoadSecret("does_not_exist_xyz.txt");
            Assert::IsTrue(secret.empty());
        }

        // Empty file → should return empty string
        TEST_METHOD(GC_Handshake_TEST07_LoadSecret_EmptyFile_ReturnsEmpty)
        {
            std::string path = WriteTempConfig("");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::IsTrue(secret.empty());
        }

        // SECRET key with empty value (SECRET=)
        TEST_METHOD(GC_Handshake_TEST08_LoadSecret_EmptyValue_ReturnsEmptyString)
        {
            std::string path = WriteTempConfig("SECRET=\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::IsTrue(secret.empty());
        }

        // Partial key that starts with SECRET but isn't SECRET (e.g. SECRETKEY=x)
        TEST_METHOD(GC_Handshake_TEST09_LoadSecret_PartialKeyMatch_DoesNotMatch)
        {
            std::string path = WriteTempConfig("SECRETKEY=shouldnotmatch\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            // "SECRETKEY" != "SECRET", so should return empty
            Assert::IsTrue(secret.empty());
        }

        // Only takes the FIRST occurrence of SECRET
        TEST_METHOD(GC_Handshake_TEST10_LoadSecret_DuplicateKeys_ReturnsFirst)
        {
            std::string path = WriteTempConfig("SECRET=first\nSECRET=second\n");
            std::string secret = MutualVerification::Handshake::LoadSecret(path);
            Assert::AreEqual(std::string("first"), secret);
        }
    };
}