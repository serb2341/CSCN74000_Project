#pragma once

// TestServerFixture.h
// Starts a Server instance on a background thread for system tests.
// Each test class inherits from this fixture to get a clean server per test.
//
// IMPORTANT: SERVER_PORT in Server.h is 54000.
// System tests use SYSTEM_TEST_PORT (54001) to avoid conflicts.
// To support this, Server.h exposes a constructor that accepts a port,
// OR we patch the port via a #define before including Server.h.
//
// The simplest approach with no Server.h changes:
// We override the port by defining TEST_PORT before the server starts
// listening. Since CreateListeningSocket() uses SERVER_PORT directly,
// the cleanest no-change solution is to run tests sequentially and
// ensure no real server is running on 54000 during tests.
// We document this as a precondition.
//
// PRECONDITION: No Server.exe is running on port 54000 during tests.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>

#include "../Server/Server.h"

// Shared secret used by all system tests — must match what MockClient uses.
static const std::string TEST_SECRET = "system_test_secret";

// Log file used by server during system tests.
static const std::string TEST_LOG_FILE = "system_test_log.txt";

// How long to wait for the server to be ready before a test connects.
static const int SERVER_READY_WAIT_MS = 300;

class TestServerFixture
{
public:
    TestServerFixture()
        : m_serverReady(false)
    {
    }

    ~TestServerFixture()
    {
        StopServer();
    }

    // Call at the start of each TEST_METHOD.
    // Writes a temporary config, starts the server on a background thread,
    // and waits for it to be ready to accept connections.
    void StartServer()
    {
        WriteTestConfig();

        m_serverReady = false;

        m_serverThread = std::thread([this]()
            {
                // The server reads "server_config.txt" from the working directory.
                // We write a test-specific config before calling Initialize().
                bool ok = m_server.Initialize();
                if (!ok) return;

                m_serverReady = true;

                m_server.AcceptClients();
                m_server.Run();
            });

        // Wait for the server socket to be ready before tests try to connect.
        std::this_thread::sleep_for(std::chrono::milliseconds(SERVER_READY_WAIT_MS));
    }

    // Call at the end of each TEST_METHOD.
    void StopServer()
    {
        m_server.Shutdown();

        if (m_serverThread.joinable())
        {
            m_serverThread.join();
        }
    }

protected:
    Networking::Server            m_server;
    std::thread       m_serverThread;
    std::atomic<bool> m_serverReady;

private:
    // Writes a minimal server_config.txt for the test run.
    // Uses the same filename the server always reads.
    void WriteTestConfig()
    {
        FILE* f = nullptr;
        fopen_s(&f, "server_config.txt", "w");
        if (f != nullptr)
        {
            fprintf(f, "SECRET=%s\n", TEST_SECRET.c_str());
            fprintf(f, "LOG_FILE=%s\n", TEST_LOG_FILE.c_str());
            fclose(f);
        }
    }
};