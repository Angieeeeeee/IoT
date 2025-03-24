// TCP Library (includes framework only)
// Jason Losh
// Edits by Angelina Abuhilal 1002108627

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
#include "arp.h"
#include "tcp.h"
#include "timer.h"
#include "uart0.h"

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------
#define MAX_TCP_PORTS 4

uint16_t tcpPorts[MAX_TCP_PORTS];
uint8_t tcpPortCount = 0;
uint8_t tcpState[MAX_TCP_PORTS];
socket sockets[MAX_TCP_PORTS];

// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

// Instead of sending ARP request at the start, create a command tcp open that sends the arp request
void tcpOpen(void)
{
    uint8_t mqttip[4];
    getIpMqttBrokerAddress(mqttip);
    sendArpRequest(0, mqttip);
}

// Set TCP state
void setTcpState(uint8_t instance, uint8_t state)
{
    tcpState[instance] = state;
}

// Get TCP state
uint8_t getTcpState(uint8_t instance)
{
    return tcpState[instance];
}

// Get socket
socket *getsocket(uint8_t instance)
{
    return &sockets[instance];
}

// Determines whether packet is TCP packet
// Must be an IP packet
bool isTcp(etherHeader* ether)
{
    if (!isIp(ether)) return false;
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    bool ok;
    uint16_t tmp16;
    uint32_t sum = 0;
    uint16_t tcpLength = ntohs(ip->length)-ipHeaderLength;
    ok = (ip->protocol == PROTOCOL_TCP);
    if (ok)
    {
        sumIpWords(ip->sourceIp, 8, &sum);
        tmp16 = ip->protocol;
        sum += (tmp16 & 0xff) << 8;
        uint16_t len = htons(tcpLength);
        sumIpWords(&len, 2, &sum);
        sumIpWords(tcp, tcpLength, &sum);
        //tcp->checksum = getIpChecksum(sum);
        ok = (getIpChecksum(sum) == 0);
    }
    return ok;
}

bool isTcpSyn(etherHeader *ether)
{
    // check if SYN flag is set
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint16_t offsetfields = ntohs(tcp->offsetFields);
    bool ok = (offsetfields & SYN) == SYN; // AND with SYN flag
    return ok;
}

bool isTcpAck(etherHeader *ether)
{
    // check if ACK flag is set
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint16_t offsetfields = ntohs(tcp->offsetFields);
    bool ok = (offsetfields & ACK) == ACK; // AND with ACK flag
    return ok;
}
//-------------------------------------------------------------------------------------------------------------
//                               STATE MACHINE
//-------------------------------------------------------------------------------------------------------------

void sendTcpPendingMessages(etherHeader *ether)
{
    // TCP state machine here

    // when in CLOSED: send ARP request and start a timer, if ARP response is received, open port and send SYN
    // when in SYN_SENT: SYN/ACK rx -> send ACK, start a timer and resend if timer expires
    // when in ESTABLISHED: process incoming data, if FIN flag is sent start closing
    // when in CLOSE_WAIT: send FIN ACK
    // when in LAST_ACK: wait for ACK and close socket

    // set initial state to closed then call for sendTcpPendingMessages
    uint8_t state = getTcpState(0);
    switch (state)
    {
        case TCP_CLOSED: // send ARP request or process ARP response
            if (isArpResponse(ether))
            {
                // makes socket, sends SYN, and switches to SYN_SENT
                processTcpArpResponse(ether);
                socket *s = getsocket(0);
                s->sequenceNumber += 1;
            }
            break;
        case TCP_SYN_SENT:
            // i sent a SYN and this sees if i got a SYN/ACK back
            if (isTcpSyn(ether) && isTcpAck(ether))
            {
                processTcpResponse(ether); // update socket info and send ACK
                // switch to established
                setTcpState(0, TCP_ESTABLISHED);
            }
            break;
        case TCP_ESTABLISHED:
            // send and receive data
            processTcpResponse(ether);
            break;
        case TCP_CLOSE_WAIT:
            // just sent a FIN ACK back to initial FIN ACK, now sending final ACK
            ;
            socket *s = getsocket(0);
            sendTcpMessage(ether, s, ACK, NULL, 0);
            s->sequenceNumber += 1;
            setTcpState(0, TCP_LAST_ACK);
            break;
        case TCP_LAST_ACK:
            if (isTcpAck(ether))
                setTcpState(0, TCP_CLOSED);
            break;
        case TCP_FIN_WAIT_1:
            // I sent FIN ACK and am waiting for ACK
            processTcpResponse(ether);
            break;
        case TCP_FIN_WAIT_2:
            // if its a FIN ACK will send ACK and close
            processTcpResponse(ether);
            break;
        default:
            setTcpState(0, TCP_CLOSED);
            break;
    }
}

//-------------------------------------------------------------------------------------------------------------
//                               PROCESS RESPONSE
//-------------------------------------------------------------------------------------------------------------

void processTcpResponse(etherHeader *ether)
{
    // just checking
    if (!isTcp(ether)) return;

    // check if ack number is correct
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // only process MQTT
    if (tcp->sourcePort != htons(1883)) return;

    // update socket info for future messages
    socket *s = getsocket(0);

    uint16_t offsetFields = ntohs(tcp->offsetFields);

    // initial case with SYN and ACK to set up socket
    if (isTcpAck(ether))
    {
        // check if ack number is correct
        //if (tcp->acknowledgementNumber == htonl(s->sequenceNumber))
        //{
            // offsetFields is in network byte order, so convert to host first
            uint16_t rawOffsetFields = ntohs(tcp->offsetFields);

            // The top 4 bits of offsetFields specify the number of 4-byte words
            uint8_t tcpHeaderLength = (rawOffsetFields >> 12) * 4;
            uint16_t dataSize = ntohs(ip->length) - ipHeaderLength - tcpHeaderLength;

            if (isTcpSyn(ether)) //ACK in response to SYN ACK
            {
                // Initial ACK value (gets ISN from server)
                s->acknowledgementNumber += (ntohl(tcp->sequenceNumber) + 1);
                // send ACK back to server
                sendTcpMessage(ether, s, ACK, NULL, 0);
            }
            else if ((offsetFields & FIN) == FIN)
            {
                uint8_t state = getTcpState(0);
                // Im recieving a FIN ACK and need to send it back
                if (state == TCP_ESTABLISHED)
                {
                    s->acknowledgementNumber += 1;
                    sendTcpMessage(ether, s, FIN | ACK, NULL, 0);
                    s->sequenceNumber += 1;
                    setTcpState(0, TCP_CLOSE_WAIT);
                }
                // I sent a FIN ACK and got an ACK and then FIN ACK now sending ACK back
                else if (state == TCP_FIN_WAIT_1)
                {
                    s->acknowledgementNumber += 1;
                    sendTcpMessage(ether, s, ACK, NULL, 0);
                    // s->sequenceNumber += 1;
                    sendTcpMessage(ether, s, FIN | ACK, NULL, 0);
                    // s->sequenceNumber += 1;
                    setTcpState(0, TCP_CLOSED);
                }
            }
            else if ((offsetFields & PSH) == PSH)
            {
                uint16_t size = 0;
                uint8_t *data = tcp->data;
                uint8_t buffer[100] = {0};
                memcpy(buffer, data, dataSize);
                // buffer is the MQTT Packet
                uint8_t flag = buffer[0];
                flag = flag >> 4;
                if (flag == 2) // CONNACK
                {
                    // set MQTT_CONNECTED flag
                    setTcpState(1, MQTT_CONNECTED);
                }
                else if (flag == 3) // PUBLISH
                {
                    // putsUart0("Hey I received a publish message\n");
                    // print out the topic and data
                    uint16_t topicLength = buffer[2] << 8 | buffer[3];
                    uint16_t dataLength = buffer[1] - (topicLength + 2);
                    char topic[100] = {0};
                    char data[100] = {0};
                    uint16_t i;
                    for (i = 0; i < topicLength; i++)
                    {
                        topic[i] = buffer[i + 4];
                    }
                    for (i = 0; i < dataLength; i++)
                    {
                        data[i] = buffer[i + 4 + topicLength];
                    }
                    putsUart0(topic);
                    putcUart0(' ');
                    putsUart0(data);
                }
                else if (flag == 9) // SUBACK
                {
                    if (buffer[3] == 0)
                    {
                        // set MQTT_SUBSCRIBED flag
                        setTcpState(1, MQTT_SUBSCRIBED);
                    }
                }
                else if (flag == 12) // PUBACK
                {

                }
                else if (flag == 11) // UNSUBACK
                {
                    setTcpState(1, MQTT_CONNECTED);
                }
                //else return;
                s->acknowledgementNumber += dataSize; // update ack number
                sendTcpMessage(ether, s, ACK, NULL, 0);
            }
        //}
    }
    // data is coming in . works no need to touch
    else if (isTcpSyn(ether) && !isTcpAck(ether))
    {
        // check if SYN number is expected
        if (tcp->sequenceNumber == htonl(s->acknowledgementNumber))
        {
            // s->sequenceNumber = ntohs(tcp->acknowledgementNumber);

            // update ack number when data is received
            //uint16_t dataSize = ntohs(ip->length) - ipHeaderLength - sizeof(tcpHeader);

            // offsetFields is in network byte order, so convert to host first
            uint16_t rawOffsetFields = ntohs(tcp->offsetFields);

            // The top 4 bits of offsetFields specify the number of 4-byte words
            uint8_t tcpHeaderLength = (rawOffsetFields >> 12) * 4;

            // Now subtract the actual TCP header size (which may be > 20)
            uint16_t dataSize = ntohs(ip->length) - ipHeaderLength - tcpHeaderLength;

            if (dataSize > 0)
                s->acknowledgementNumber += (dataSize + 1); // update ack number
            else
                s->acknowledgementNumber += 1; // no data, just increment by 1

            // send ACK back to server
            sendTcpMessage(ether, s, ACK, NULL, 0);
        }
    }
    else if ((offsetFields & RST)== RST)
    {
        setTcpState(0, TCP_CLOSED);
    }
}

void processTcpArpResponse(etherHeader *ether)
{
    // take in arp response
    arpPacket *arp = (arpPacket*)ether->data;

    // check if its from the MQTT broker
    uint8_t mqttip[4];
    getIpMqttBrokerAddress(mqttip);
    // memcmp returns 0 if equal, making sure its from the MQTT broker
    if (memcmp(arp->sourceIp, mqttip, 4) != 0) return;

    setTcpState(0, TCP_SYN_SENT);
    // populate socket
    socket *s = getsocket(0);

    // loop to populate arrays
    uint8_t i;
    for (i = 0; i < 4; i++)
    {
        s->remoteIpAddress[i] = arp->sourceIp[i];
    }
    for (i = 0; i < 6; i++)
    {
        s->remoteHwAddress[i] = arp->sourceAddress[i];
    }

    s->remotePort = 1883; // MQTT hard coded
    s->localPort = 51000; // my port number
    s->sequenceNumber = 69; // random number for initial sequence number
    s->acknowledgementNumber = 0; // calcule ack number when data is sent
    s->state = getTcpState(0);

    sendTcpMessage(ether, s, SYN, NULL, 0);
}

void setTcpPortList(uint16_t ports[], uint8_t count)
{
}

bool isTcpPortOpen(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // check if destination port is in the list
    uint16_t destPort = ntohs(tcp->destPort);
    if (destPort == 1883) return true; // MQTT hard coded
    if (destPort == 51000) return true; // My port
    else return false;
}

// so far i dont use this function
void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
    sendTcpMessage(ether, s, flags, NULL, 0);
}

void sendTcpMessage(etherHeader *ether, socket *s, uint16_t flags, uint8_t data[], uint16_t dataSize)
{
        /*
         *              source port | destination port (same as UDP)
         *               sequence number (from ether)
         *                   ACK number (from ether)
         *  data offset OR ack flag | window
         *                 checksum | urgent pointer
         *
         */
    uint8_t i;
    uint8_t j;
    uint16_t tcpLength;
    uint8_t localHwAddress[HW_ADD_LENGTH];
    uint8_t localIpAddress[IP_ADD_LENGTH];

    // --- Build Ethernet Header ---
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s->remoteHwAddress[i]; // Destination MAC
        ether->sourceAddress[i] = localHwAddress[i];   // Source MAC
    }
    ether->frameType = htons(TYPE_IP); // Ethernet frame type (IP)

    // Fill IP Header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;                     // IPv4
    ip->size = 0x5;                    // 5 * 4 = 20 bytes (standard IP header size)
    ip->typeOfService = 0;             // No special handling
    ip->id = 0;                        // Identification (0 for now)
    ip->flagsAndOffset = 0;            // No fragmentation
    ip->ttl = 128;                     // Time to live
    ip->protocol = PROTOCOL_TCP;       // TCP protocol
    ip->headerChecksum = 0;            // Checksum (calculated later)
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s->remoteIpAddress[i]; // Destination IP
        ip->sourceIp[i] = localIpAddress[i];   // Source IP
    }
    uint8_t ipHeaderLength = ip->size * 4; // IP header length in bytes

    // Fill TCP Header
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    tcp->sourcePort = htons(s->localPort);  // Source port
    tcp->destPort = htons(s->remotePort);   // Destination port
    tcp->sequenceNumber = htonl(s->sequenceNumber); // Sequence number
    tcp->acknowledgementNumber = htonl(s->acknowledgementNumber); // Ack number
    tcp->offsetFields = htons((5 << 12) | (flags & 0x01FF)); // Data offset (5 * 4 = 20 bytes) and flags
    tcp->windowSize = htons(5804);           // Window size (example value)
    tcp->urgentPointer = 0;                 // Urgent pointer (not used)
    tcp->checksum = 0;                      // Checksum (calculated later)

    // copy in data
    uint8_t *dataCopy = tcp->data;
    for (j = 0; j < dataSize; j++)
    {
        dataCopy[j] = data[j]; // Copy payload data
    }

    tcpLength = sizeof(tcpHeader) + dataSize; // TCP header + payload
    uint16_t totalIpLength = ipHeaderLength + tcpLength; // IP header + TCP header + payload
    ip->length = htons(totalIpLength); // Set IP total length

    calcIpChecksum(ip); // Calculate IP checksum after setting length

    //checksum calculation
    uint32_t sum = 0;
    uint16_t tmp16;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    uint16_t len = htons(tcpLength);
    sumIpWords(&len, 2, &sum);
    sumIpWords(tcp, tcpLength, &sum);
    tcp->checksum = getIpChecksum(sum);

    uint16_t frameSize = sizeof(etherHeader) + totalIpLength;
    putEtherPacket(ether, frameSize);

    // update sequence number in socket for next message
    // dont increment when sending ACK if not during handshake
    if (dataSize > 0)
    s->sequenceNumber += dataSize; // update sequence number
}
