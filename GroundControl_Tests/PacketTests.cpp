#include "pch.h"
#include "CppUnitTest.h"

#include "../GroundControlClient/Packet.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace GroundControl_Tests {
    TEST_CLASS(PacketTests) {
public:

    // Default-constructed packet should have zeroed header fields
    TEST_METHOD(DefaultConstructor_ZeroedHeader)
    {
        GroundControlCommunication::Packet pkt;
        Assert::AreEqual(0u, pkt.GetFlightID());
        Assert::AreEqual(0u, pkt.GetBodyLength());
    }

    // GetData on a default-constructed packet should return nullptr
    TEST_METHOD(DefaultConstructor_NullData)
    {
        GroundControlCommunication::Packet pkt;
        Assert::IsNull(pkt.GetData());
    }
    };

    TEST_CLASS(PacketSetterTests)
    {
    public:
        TEST_METHOD(SetFlightID_ReflectsInGetter)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(42u);
            Assert::AreEqual(42u, pkt.GetFlightID());
        }

        TEST_METHOD(SetMessageType_ReflectsInHeader)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetMessageType(7u);
            Assert::AreEqual(7u, pkt.GetHeader().MessageType);
        }

        TEST_METHOD(SetTimeStamp_ReflectsInHeader)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetTimeStamp(123456u);
            Assert::AreEqual(static_cast<uint32_t>(123456u), pkt.GetHeader().TimeStamp);
        }

        TEST_METHOD(SetData_UpdatesBodyLength)
        {
            GroundControlCommunication::Packet pkt;
            const std::string body = "Hello";
            pkt.SetData(body.c_str(), static_cast<unsigned int>(body.size()));
            Assert::AreEqual(static_cast<unsigned int>(body.size()), pkt.GetBodyLength());
        }

        TEST_METHOD(SetData_ContentMatchesInput)
        {
            GroundControlCommunication::Packet pkt;
            const std::string body = "TestPayload";
            pkt.SetData(body.c_str(), static_cast<unsigned int>(body.size()));
            std::string retrieved(pkt.GetData(), pkt.GetBodyLength());
            Assert::AreEqual(body, retrieved);
        }

        // Calling SetData twice should replace the old data
        TEST_METHOD(SetData_CalledTwice_UsesLatestData)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetData("first", 5u);
            pkt.SetData("second", 6u);
            Assert::AreEqual(6u, pkt.GetBodyLength());
            std::string retrieved(pkt.GetData(), pkt.GetBodyLength());
            Assert::AreEqual(std::string("second"), retrieved);
        }

        // SetData with nullptr should not crash or alter state
        TEST_METHOD(SetData_NullptrInput_NoChange)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetData("init", 4u);
            pkt.SetData(nullptr, 5u); // should be ignored
            Assert::AreEqual(4u, pkt.GetBodyLength());
        }

        // SetData with size 0 should not crash
        TEST_METHOD(SetData_ZeroSize_NoChange)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetData("init", 4u);
            pkt.SetData("other", 0u); // size 0 should be ignored
            Assert::AreEqual(4u, pkt.GetBodyLength());
        }
    };

    TEST_CLASS(PacketSerializationTests)
    {
    public:
        // Serialized size = header + body + CRC(4 bytes)
        TEST_METHOD(SerializeData_CorrectTotalSize)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(1u);
            pkt.SetData("Hi", 2u);

            unsigned int size = 0u;
            pkt.SerializeData(size);

            unsigned int expected = sizeof(GroundControlCommunication::PacketHeader) + 2u + sizeof(uint32_t);
            Assert::AreEqual(expected, size);
        }

        // Serialized buffer should not be null
        TEST_METHOD(SerializeData_ReturnsNonNullBuffer)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetData("data", 4u);
            unsigned int size = 0u;
            char* buf = pkt.SerializeData(size);
            Assert::IsNotNull(buf);
        }

        // Round-trip: serialize then deserialize must preserve FlightID and body
        TEST_METHOD(SerializeDeserialize_RoundTrip_PreservesFlightID)
        {
            GroundControlCommunication::Packet original;
            original.SetFlightID(99u);
            original.SetMessageType(2u);
            original.SetData("RoundTrip", 9u);

            unsigned int size = 0u;
            char* raw = original.SerializeData(size);

            GroundControlCommunication::Packet restored(raw);
            Assert::AreEqual(99u, restored.GetFlightID());
        }

        TEST_METHOD(SerializeDeserialize_RoundTrip_PreservesBody)
        {
            GroundControlCommunication::Packet original;
            original.SetFlightID(5u);
            original.SetData("PayloadData", 11u);

            unsigned int size = 0u;
            char* raw = original.SerializeData(size);

            GroundControlCommunication::Packet restored(raw);
            std::string body(restored.GetData(), restored.GetBodyLength());
            Assert::AreEqual(std::string("PayloadData"), body);
        }

        TEST_METHOD(SerializeDeserialize_RoundTrip_PreservesMessageType)
        {
            GroundControlCommunication::Packet original;
            original.SetMessageType(3u);
            original.SetData("X", 1u);

            unsigned int size = 0u;
            char* raw = original.SerializeData(size);

            GroundControlCommunication::Packet restored(raw);
            Assert::AreEqual(3u, restored.GetHeader().MessageType);
        }

        // Deserialize via DeserializeData method
        TEST_METHOD(DeserializeData_SameAsConstructorFromBuffer)
        {
            GroundControlCommunication::Packet original;
            original.SetFlightID(77u);
            original.SetData("msg", 3u);

            unsigned int size = 0u;
            char* raw = original.SerializeData(size);

            GroundControlCommunication::Packet via_ctor(raw);
            GroundControlCommunication::Packet via_method;
            via_method.DeserializeData(raw);

            Assert::AreEqual(via_ctor.GetFlightID(), via_method.GetFlightID());
            Assert::AreEqual(via_ctor.GetBodyLength(), via_method.GetBodyLength());
        }
    };

    TEST_CLASS(PacketCopyTests)
    {
    public:
        // Copy constructor should deep copy the body
        TEST_METHOD(CopyConstructor_DeepCopiesBody)
        {
            GroundControlCommunication::Packet original;
            original.SetFlightID(10u);
            original.SetData("CopyMe", 6u);

            GroundControlCommunication::Packet copy(original);
            Assert::AreEqual(10u, copy.GetFlightID());
            std::string body(copy.GetData(), copy.GetBodyLength());
            Assert::AreEqual(std::string("CopyMe"), body);
        }

        // Copy assignment should deep copy the body
        TEST_METHOD(CopyAssignment_DeepCopiesBody)
        {
            GroundControlCommunication::Packet original;
            original.SetFlightID(20u);
            original.SetData("Assign", 6u);

            GroundControlCommunication::Packet copy;
            copy = original;

            Assert::AreEqual(20u, copy.GetFlightID());
            std::string body(copy.GetData(), copy.GetBodyLength());
            Assert::AreEqual(std::string("Assign"), body);
        }

        // Modifying original after copy must not affect the copy
        TEST_METHOD(CopyConstructor_IndependentAfterCopy)
        {
            GroundControlCommunication::Packet original;
            original.SetData("Original", 8u);
            GroundControlCommunication::Packet copy(original);

            original.SetData("Modified", 8u); // mutate original
            std::string body(copy.GetData(), copy.GetBodyLength());
            Assert::AreEqual(std::string("Original"), body);
        }

        // Self-assignment must be safe
        TEST_METHOD(CopyAssignment_SelfAssignment_Safe)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(5u);
            pkt.SetData("Self", 4u);
            pkt = pkt; // self-assign
            Assert::AreEqual(5u, pkt.GetFlightID());
        }
    };

    TEST_CLASS(PacketGetHeaderTests)
    {
    public:
        // GetHeader must return a const reference with correct values
        TEST_METHOD(GetHeader_ReturnsCorrectFlightID)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetFlightID(123u);
            Assert::AreEqual(123u, pkt.GetHeader().FlightID);
        }

        TEST_METHOD(GetHeader_ReturnsCorrectLength)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetData("ABCDE", 5u);
            Assert::AreEqual(5u, pkt.GetHeader().Length);
        }

        TEST_METHOD(GetHeader_ReturnsCorrectMessageType)
        {
            GroundControlCommunication::Packet pkt;
            pkt.SetMessageType(9u);
            Assert::AreEqual(9u, pkt.GetHeader().MessageType);
        }
    };


    TEST_CLASS(PacketHeaderLayoutTests)
    {
    public:
        // PacketHeader must be exactly 16 bytes (4 × uint32_t/unsigned int, packed)
        TEST_METHOD(PacketHeader_IsSixteenBytes)
        {
            Assert::AreEqual(static_cast<size_t>(16u), sizeof(GroundControlCommunication::PacketHeader));
        }

        // Fields must be at the correct offsets within the packed struct
        TEST_METHOD(PacketHeader_FieldOffsets_AreCorrect)
        {
            GroundControlCommunication::PacketHeader hdr{};
            hdr.FlightID = 0x11111111U;
            hdr.MessageType = 0x22222222U;
            hdr.Length = 0x33333333U;
            hdr.TimeStamp = 0x44444444U;

            const char* raw = reinterpret_cast<const char*>(&hdr);

            unsigned int f, m, l;
            uint32_t t;
            std::memcpy(&f, raw + 0, 4);
            std::memcpy(&m, raw + 4, 4);
            std::memcpy(&l, raw + 8, 4);
            std::memcpy(&t, raw + 12, 4);

            Assert::AreEqual(0x11111111U, f);
            Assert::AreEqual(0x22222222U, m);
            Assert::AreEqual(0x33333333U, l);
            Assert::AreEqual(static_cast<uint32_t>(0x44444444U), t);
        }
    };
};