#include "pch.h"
#include "CppUnitTest.h"

#include "TestServerFixture.h"
#include "MockClient.h"

#include <thread>
#include <chrono>
#include <string>
#include <atomic>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// ================================================================
//  PRECONDITION: No Server.exe must be running on port 54000
//  while these tests execute. Tests are run sequentially by
//  the VS Test Runner — each test gets its own server instance.
// ================================================================

namespace ServerSystemTests
{
    TEST_CLASS(SystemTests)
    {
    public:

        // ============================================================
        //  ST-01: Both clients connect and handshake successfully.
        //
        //  Verifies:
        //  - Server accepts Ground Control as 1st connection.
        //  - Server accepts Airplane as 2nd connection.
        //  - Both complete the 4-packet mutual verification.
        //  - Server transitions to relay state (both threads running).
        // ============================================================
        TEST_METHOD(ST01_BothClients_ConnectAndHandshake)
        {
            TestServerFixture fixture;
            fixture.StartServer();

            MockClient groundControl(TEST_SECRET);
            MockClient airplane(TEST_SECRET);

            // GC connects first (server expects GC as 1st connection).
            bool gcConnected = groundControl.Connect();
            Assert::IsTrue(gcConnected, L"ST-01: Ground Control must connect to server.");

            bool gcHandshake = groundControl.PerformHandshake();
            Assert::IsTrue(gcHandshake, L"ST-01: Ground Control handshake must succeed.");

            // Airplane connects second.
            bool apConnected = airplane.Connect();
            Assert::IsTrue(apConnected, L"ST-01: Airplane must connect to server.");

            bool apHandshake = airplane.PerformHandshake();
            Assert::IsTrue(apHandshake, L"ST-01: Airplane handshake must succeed.");

            groundControl.Disconnect();
            airplane.Disconnect();
            fixture.StopServer();
        }

        // ============================================================
        //  ST-02: Client with wrong secret is rejected.
        //
        //  Verifies:
        //  - A client using the wrong shared secret produces a wrong
        //    signature in Step 4.
        //  - The server closes the connection (handshake returns false).
        //  - PerformHandshake() on the mock returns false.
        // ============================================================
        TEST_METHOD(ST02_WrongSecret_HandshakeFails)
        {
            TestServerFixture fixture;
            fixture.StartServer();

            // Use the WRONG secret — signature will not match server's.
            MockClient badClient("wrong_secret_entirely");

            bool connected = badClient.Connect();
            Assert::IsTrue(connected, L"ST-02: Client TCP connection must succeed initially.");

            bool handshake = badClient.PerformHandshake();

            // The server will detect the signature mismatch at Step 4
            // and close the connection, so PerformHandshake must return false.
            Assert::IsFalse(handshake,
                L"ST-02: Handshake must fail when client uses wrong shared secret.");

            badClient.Disconnect();
            fixture.StopServer();
        }

        // ============================================================
        //  ST-03: Airplane sends a packet — Ground Control receives it.
        //
        //  Verifies end-to-end relay in the Airplane → GC direction:
        //  - Packet is serialized correctly by MockClient.
        //  - Server receives, validates CRC-32, forwards.
        //  - GC receives the body intact.
        // ============================================================
        TEST_METHOD(ST03_AirplaneSendsPacket_GroundControlReceivesIt)
        {
            TestServerFixture fixture;
            fixture.StartServer();

            MockClient groundControl(TEST_SECRET);
            MockClient airplane(TEST_SECRET);

            groundControl.Connect();
            groundControl.PerformHandshake();
            airplane.Connect();
            airplane.PerformHandshake();

            // Give server time to start relay threads.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            const std::string sentBody = "Hello from Airplane";

            // Run GC receive on a separate thread so it doesn't block the test.
            std::string receivedBody;
            std::atomic<bool> receiveComplete(false);

            std::thread gcReceiveThread([&]()
                {
                    receiveComplete = groundControl.ReceivePacket(receivedBody);
                });

            // Airplane sends the packet.
            bool sent = airplane.SendPacket(101U, 0U, sentBody.c_str(),
                static_cast<unsigned int>(sentBody.size()));
            Assert::IsTrue(sent, L"ST-03: Airplane must send packet successfully.");

            gcReceiveThread.join();

            Assert::IsTrue(receiveComplete.load(),
                L"ST-03: Ground Control must receive the packet.");

            Assert::AreEqual(sentBody, receivedBody,
                L"ST-03: Received body must exactly match what Airplane sent.");

            groundControl.Disconnect();
            airplane.Disconnect();
            fixture.StopServer();
        }

        // ============================================================
        //  ST-04: Ground Control sends a packet — Airplane receives it.
        //
        //  Verifies end-to-end relay in the GC → Airplane direction:
        //  - Symmetric to ST-03, tests the other relay thread.
        // ============================================================
        TEST_METHOD(ST04_GroundControlSendsPacket_AirplaneReceivesIt)
        {
            TestServerFixture fixture;
            fixture.StartServer();

            MockClient groundControl(TEST_SECRET);
            MockClient airplane(TEST_SECRET);

            groundControl.Connect();
            groundControl.PerformHandshake();
            airplane.Connect();
            airplane.PerformHandshake();

            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            const std::string sentBody = "Cleared for landing";

            std::string receivedBody;
            std::atomic<bool> receiveComplete(false);

            std::thread apReceiveThread([&]()
                {
                    receiveComplete = airplane.ReceivePacket(receivedBody);
                });

            bool sent = groundControl.SendPacket(0U, 1U, sentBody.c_str(),
                static_cast<unsigned int>(sentBody.size()));
            Assert::IsTrue(sent, L"ST-04: Ground Control must send packet successfully.");

            apReceiveThread.join();

            Assert::IsTrue(receiveComplete.load(),
                L"ST-04: Airplane must receive the packet.");

            Assert::AreEqual(sentBody, receivedBody,
                L"ST-04: Received body must exactly match what Ground Control sent.");

            groundControl.Disconnect();
            airplane.Disconnect();
            fixture.StopServer();
        }

        // ============================================================
        //  ST-05: Server drops a packet with a corrupted CRC-32.
        //
        //  Verifies US-16 requirement 3:
        //  "A packet that fails CRC-32 verification is not forwarded."
        //
        //  Strategy:
        //  - Airplane sends a valid packet first (proves relay works).
        //  - Airplane then sends a packet with a flipped CRC byte.
        //  - Airplane then sends a second valid "SENTINEL" packet.
        //  - GC must receive VALID1 and SENTINEL, but NOT the corrupt one.
        //  - If GC receives SENTINEL without receiving garbage, the corrupt
        //    packet was silently dropped as required.
        // ============================================================
        TEST_METHOD(ST05_CorruptCRC_PacketDropped_NotForwarded)
        {
            TestServerFixture fixture;
            fixture.StartServer();

            MockClient groundControl(TEST_SECRET);
            MockClient airplane(TEST_SECRET);

            groundControl.Connect();
            groundControl.PerformHandshake();
            airplane.Connect();
            airplane.PerformHandshake();

            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // ---- Send VALID packet 1 ----
            const std::string valid1 = "VALID1";
            airplane.SendPacket(101U, 0U, valid1.c_str(),
                static_cast<unsigned int>(valid1.size()));

            // ---- Build and send CORRUPT packet ----
            // Manually construct a packet buffer and flip a CRC byte.
            {
                Communication::Packet pkt;
                pkt.SetFlightID(101U);
                pkt.SetMessageType(0U);
                pkt.SetTimeStamp(1U);
                const char corruptBody[] = "CORRUPT";
                pkt.SetData(corruptBody, 7U);

                unsigned int totalSize = 0U;
                char* buf = pkt.SerializeData(totalSize);

                // Make a mutable copy and corrupt the CRC tail.
                char* badBuf = new char[totalSize];
                std::memcpy(badBuf, buf, totalSize);
                badBuf[totalSize - 1] ^= 0xFF;  // flip last byte of CRC

                airplane.SendRaw(badBuf, totalSize);
                delete[] badBuf;
            }

            // ---- Send SENTINEL packet ----
            const std::string sentinel = "SENTINEL";
            airplane.SendPacket(101U, 0U, sentinel.c_str(),
                static_cast<unsigned int>(sentinel.size()));

            // ---- GC receives — must get VALID1 then SENTINEL, not CORRUPT ----
            std::string body1, body2;
            bool got1 = groundControl.ReceivePacket(body1, 2000U);
            bool got2 = groundControl.ReceivePacket(body2, 2000U);

            Assert::IsTrue(got1, L"ST-05: GC must receive first valid packet.");
            Assert::IsTrue(got2, L"ST-05: GC must receive sentinel packet.");

            Assert::AreEqual(valid1, body1, L"ST-05: First received body must be VALID1.");
            Assert::AreEqual(sentinel, body2, L"ST-05: Second received body must be SENTINEL (corrupt packet dropped).");

            groundControl.Disconnect();
            airplane.Disconnect();
            fixture.StopServer();
        }

        //// ============================================================
        ////  ST-06: Server drops a structurally invalid packet.
        ////
        ////  Verifies US-16 requirement 4:
        ////  "A packet that fails structural validation is not forwarded."
        ////
        ////  Strategy: same sentinel approach as ST-05.
        ////  The malformed packet has a Length field that doesn't match
        ////  the actual buffer size, causing a structural mismatch.
        //// ============================================================
        //TEST_METHOD(ST06_StructurallyInvalidPacket_Dropped_NotForwarded)
        //{
        //    TestServerFixture fixture;
        //    fixture.StartServer();

        //    MockClient groundControl(TEST_SECRET);
        //    MockClient airplane(TEST_SECRET);

        //    groundControl.Connect();
        //    groundControl.PerformHandshake();
        //    airplane.Connect();
        //    airplane.PerformHandshake();

        //    std::this_thread::sleep_for(std::chrono::milliseconds(100));

        //    // ---- Send VALID packet 1 ----
        //    const char valid1[] = "VALID1";
        //    airplane.SendPacket(101U, 0U, valid1,
        //        static_cast<unsigned int>(strlen(valid1)));

        //    // ---- Build and send STRUCTURALLY INVALID packet ----
        //    // Build a real packet but lie about Length in the header.
        //    {
        //        Communication::Packet pkt;
        //        pkt.SetFlightID(101U);
        //        pkt.SetMessageType(0U);
        //        pkt.SetTimeStamp(1U);
        //        const char body[] = "INVALID";
        //        pkt.SetData(body, 7U);

        //        unsigned int totalSize = 0U;
        //        char* buf = pkt.SerializeData(totalSize);

        //        char* badBuf = new char[totalSize];
        //        std::memcpy(badBuf, buf, totalSize);

        //        // Inflate Length field in the header so declared size >
        //        // actual bytes, causing a structural mismatch on the server.
        //        // Length sits at offset 9 in PacketHeader (after FlightID=4,
        //        // MessageType=4, TimeStamp=1).
        //        unsigned int fakeLength = 9999U;
        //        std::memcpy(badBuf + 9, &fakeLength, sizeof(unsigned int));

        //        // Note: the server reads header (13 bytes), then tries to
        //        // recv 9999 + 4 bytes of body+CRC. The recv will block
        //        // until timeout or disconnect. To avoid hanging the test,
        //        // we instead corrupt totalSize by truncating the send —
        //        // server receives a body shorter than the declared Length,
        //        // causing the structural check to fail.
        //        //
        //        // Reset to a valid-looking but wrong length (body=10, reality=7).
        //        unsigned int wrongLength = 10U;
        //        std::memcpy(badBuf + 9, &wrongLength, sizeof(unsigned int));

        //        // Send only the real totalSize bytes — server reads 13 header,
        //        // then tries recv(10+4=14) but only 7+4=11 bytes follow.
        //        // MSG_WAITALL will return fewer bytes than requested, failing
        //        // the body recv check.
        //        airplane.SendRaw(badBuf, totalSize);
        //        delete[] badBuf;
        //    }

        //    // Give the server time to detect and drop the bad packet.
        //    std::this_thread::sleep_for(std::chrono::milliseconds(200));

        //    // ---- Send SENTINEL ----
        //    const char sentinel[] = "SENTINEL";
        //    airplane.SendPacket(101U, 0U, sentinel,
        //        static_cast<unsigned int>(strlen(sentinel)));

        //    // ---- GC should receive VALID1 then SENTINEL ----
        //    std::string body1, body2;
        //    bool got1 = groundControl.ReceivePacket(body1, 2000U);
        //    bool got2 = groundControl.ReceivePacket(body2, 2000U);

        //    Assert::IsTrue(got1, L"ST-06: GC must receive the first valid packet.");
        //    Assert::IsTrue(got2, L"ST-06: GC must receive the sentinel packet.");

        //    Assert::AreEqual(std::string(valid1), body1, L"ST-06: First body must be VALID1.");
        //    Assert::AreEqual(std::string(sentinel), body2, L"ST-06: Second body must be SENTINEL (invalid packet dropped).");

        //    groundControl.Disconnect();
        //    airplane.Disconnect();
        //    fixture.StopServer();
        //}

        // ============================================================
        //  ST-07: Multiple packets relay correctly in sequence.
        //
        //  Verifies the relay loop handles multiple consecutive packets
        //  without losing or reordering them.
        // ============================================================
        TEST_METHOD(ST07_MultiplePackets_RelayedInOrder)
        {
            TestServerFixture fixture;
            fixture.StartServer();

            MockClient groundControl(TEST_SECRET);
            MockClient airplane(TEST_SECRET);

            groundControl.Connect();
            groundControl.PerformHandshake();
            airplane.Connect();
            airplane.PerformHandshake();

            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            const int PACKET_COUNT = 5;
            std::string sentBodies[PACKET_COUNT] = {
                "Message One",
                "Message Two",
                "Message Three",
                "Message Four",
                "Message Five"
            };

            // Receive on GC thread concurrently.
            std::string receivedBodies[PACKET_COUNT];
            std::atomic<int> receiveCount(0);

            std::thread gcThread([&]()
                {
                    for (int i = 0; i < PACKET_COUNT; ++i)
                    {
                        if (groundControl.ReceivePacket(receivedBodies[i], 3000U))
                        {
                            ++receiveCount;
                        }
                    }
                });

            // Airplane sends all packets.
            for (int i = 0; i < PACKET_COUNT; ++i)
            {
                airplane.SendPacket(101U,
                    static_cast<unsigned int>(i),
                    sentBodies[i].c_str(),
                    static_cast<unsigned int>(sentBodies[i].size()));

                // Small delay to keep packets distinct on the stream.
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }

            gcThread.join();

            Assert::AreEqual(PACKET_COUNT, receiveCount.load(),
                L"ST-07: All 5 packets must be received by Ground Control.");

            for (int i = 0; i < PACKET_COUNT; ++i)
            {
                Assert::AreEqual(sentBodies[i], receivedBodies[i],
                    L"ST-07: Each packet body must match what was sent, in order.");
            }

            groundControl.Disconnect();
            airplane.Disconnect();
            fixture.StopServer();
        }
    };
}