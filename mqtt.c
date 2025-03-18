// MQTT Library (includes framework only)
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "mqtt.h"
#include "timer.h"

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------
#define MAX_PACKET_SIZE 1518
// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

void connectMqtt()
{
    if (getTcpState(0) == TCP_ESTABLISHED)
    {
        uint8_t mqttData[100];
        uint16_t mqttDataSize = 0;
        // MQTT connect packet
        mqttData[mqttDataSize++] = 0x10; // connect
        mqttData[mqttDataSize++] = 16; // remaining length FILL IN LATER
        mqttData[mqttDataSize++] = 0x00; // protocol name length MSB
        mqttData[mqttDataSize++] = 0x04; // protocol name length LSB
        mqttData[mqttDataSize++] = 'M';  // protocol name
        mqttData[mqttDataSize++] = 'Q';  // protocol name
        mqttData[mqttDataSize++] = 'T';  // protocol name
        mqttData[mqttDataSize++] = 'T';  // protocol name
        mqttData[mqttDataSize++] = 0x04; // protocol level
        mqttData[mqttDataSize++] = 0x00; // connect flags
        mqttData[mqttDataSize++] = 0x00; // keep alive MSB
        mqttData[mqttDataSize++] = 0x3C; // keep alive LSB 60 seconds

        mqttData[mqttDataSize++] = 0x00; // client id length MSB
        mqttData[mqttDataSize++] = 0x04; // client id length LSB
        mqttData[mqttDataSize++] = 'A';  // client id
        mqttData[mqttDataSize++] = 'N';  // client id
        mqttData[mqttDataSize++] = 'G';  // client id
        mqttData[mqttDataSize++] = 'E';  // client id
        // make ether
        uint8_t buffer[MAX_PACKET_SIZE];
        etherHeader *data = (etherHeader*) buffer;
        sendTcpMessage(data, getsocket(0), PSH | ACK, mqttData, mqttDataSize);
    }
}
// ??????
void disconnectMqtt()
{
    if (getTcpState(0) == TCP_ESTABLISHED)
    {
        uint8_t mqttData[2];
        // MQTT disconnect packet
        mqttData[0] = 0xE0; // disconnect
        mqttData[1] = 0x00; // remaining length

        // make ether
        uint8_t buffer[MAX_PACKET_SIZE];
        etherHeader *data = (etherHeader*) buffer;
        socket *s = getsocket(0);
        sendTcpMessage(data, s, FIN | PSH | ACK, mqttData, 2);
        // increment sequence number cause its a handshake situation
        s->sequenceNumber += 1;
        setTcpState(0, TCP_FIN_WAIT_1);
    }
}







void publishMqtt(char strTopic[], char strData[])
{
    if (getTcpState(0) == TCP_ESTABLISHED)
    {
        uint8_t mqttData[100];
        uint16_t mqttDataSize = 0;
        uint16_t topicLength = strlen(strTopic);
        uint16_t dataLength = strlen(strData);
        // MQTT publish packet
        mqttData[mqttDataSize++] = 0x30; // publish
        mqttData[mqttDataSize++] = 2 + topicLength + dataLength; // remaining length
        mqttData[mqttDataSize++] = 0x00; // topic length MSB
        mqttData[mqttDataSize++] = topicLength; // topic length LSB
        strcpy((char*)&mqttData[mqttDataSize], strTopic); // topic
        mqttDataSize += topicLength;
        //bitSplicing((uint8_t*)strData, dataLength, &mqttData[mqttDataSize]);
        strcpy((char*)&mqttData[mqttDataSize], strData); // data
        mqttDataSize += dataLength;

        // make ether
        uint8_t buffer[MAX_PACKET_SIZE];
        etherHeader *data = (etherHeader*) buffer;
        sendTcpMessage(data, getsocket(0), PSH | ACK, mqttData, mqttDataSize);
    }
}

void subscribeMqtt(char strTopic[])
{
    if (getTcpState(0) == TCP_ESTABLISHED)
    {
        uint8_t mqttData[100];
        uint16_t mqttDataSize = 0;
        uint16_t topicLength = strlen(strTopic);

        // MQTT subscribe packet
        mqttData[mqttDataSize++] = 0x82; // subscribe header
        mqttData[mqttDataSize++] = topicLength + 5; // remaining length = 2 (packet id) + 2 (topic length) + topicLength + 1 (QoS)
        mqttData[mqttDataSize++] = 0x00; // packet id MSB
        mqttData[mqttDataSize++] = 0x01; // packet id LSB
        mqttData[mqttDataSize++] = 0x00; // topic length MSB
        mqttData[mqttDataSize++] = topicLength; // topic length LSB

        strcpy((char*)&mqttData[mqttDataSize], strTopic); // topic
        mqttDataSize += topicLength;

        mqttData[mqttDataSize++] = 0x00; // QoS level (0)

        // make ether
        uint8_t buffer[MAX_PACKET_SIZE];
        etherHeader *data = (etherHeader*) buffer;
        sendTcpMessage(data, getsocket(0), PSH | ACK, mqttData, mqttDataSize);
    }
}


void unsubscribeMqtt(char strTopic[])
{
    if (getTcpState(0) == TCP_ESTABLISHED)
    {
        uint8_t mqttData[100];
        uint16_t mqttDataSize = 0;
        uint16_t topicLength = strlen(strTopic);
        // MQTT unsubscribe packet
        mqttData[mqttDataSize++] = 0xA2; // unsubscribe
        mqttData[mqttDataSize++] = 2 + 2 + topicLength; // remaining length
        mqttData[mqttDataSize++] = 0x00; // packet id MSB
        mqttData[mqttDataSize++] = 0x01; // packet id LSB
        mqttData[mqttDataSize++] = 0x00; // topic length MSB
        mqttData[mqttDataSize++] = topicLength; // topic length LSB
        strcpy((char*)&mqttData[mqttDataSize], strTopic); // topic
        mqttDataSize += topicLength;

        // make ether
        uint8_t buffer[MAX_PACKET_SIZE];
        etherHeader *data = (etherHeader*) buffer;
        sendTcpMessage(data, getsocket(0), PSH | ACK, mqttData, mqttDataSize);
    }
}

//void bitSplicing(uint8_t data[], uint8_t size, uint8_t payload[])
//{
//    // Find the total number of bits in 'data'
//    uint16_t dataSize = size * 8;
//    // Calculate how many output bytes (payload octets) are needed (each holds 7 data bits)
//    uint16_t payloadSize = dataSize / 7;
//    if (dataSize % 7 != 0) payloadSize++;
//
//    // Process the bits, packing them 7 at a time, and use the MSB as a continuation flag.
//    uint16_t i = 0;      // Overall bit index in data
//    uint16_t j = 0;      // Index into the payload array (which holds 8-bit octets)
//    uint8_t bitCount = 0;
//    uint8_t bit = 0;
//    while (i < dataSize)
//    {
//        // Extract the i-th bit from data (LSB-first order)
//        bit = (data[i / 8] >> (i % 8)) & 0x01;
//        // Place that bit into the current payload byte at position bitCount
//        payload[j] |= (bit << bitCount);
//        // Move to the next bit position within the current payload byte
//        bitCount++;
//        // Once we have packed 7 bits in payload[j]:
//        if (bitCount == 7)
//        {
//            // If there are still more bits to process, set the continuation flag (bit 7)
//            if (i < dataSize - 1)
//                payload[j] |= 0x80; // set the 8th bit to 1
//            // Reset bitCount and move to the next payload byte
//            bitCount = 0;
//            j++;
//        }
//        i++;
//    }
//}

