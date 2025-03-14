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
        // 32-bit sum over pseudo-header
        sumIpWords(ip->sourceIp, 8, &sum);
        tmp16 = ip->protocol;
        sum += (tmp16 & 0xff) << 8;
        sumIpWords(&tcpLength, 2, &sum);
        // add tcp header and data
        sumIpWords(tcp, tcpLength, &sum);
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
    bool ok = offsetfields & SYN; // AND with SYN flag
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

void sendTcpPendingMessages(etherHeader *ether)
{
    // put tcp state machine here

    // when in CLOSED: send ARP request and start a timer, if ARP response is received, open port and send SYN
    // when in SYN_SENT: SYN/ACK rx -> send ACK, start a timer and resend if timer expires
    // when in ESTABLISHED: process incoming data, if FIN flag is sent start closing
    // when in CLOSE_WAIT: send FIN ACK
    // when in LAST_ACK: wait for ACK and close socket

    // set initial state to closed then call for sendTcpPendingMessages
    uint8_t state = getTcpState(0);
    switch (state)
    {
        // am i alwyas trying to get out of the closed state?
        case TCP_CLOSED: // send ARP request or process ARP response
            if (isArpResponse(ether))
            {
                // makes socket and switches to SYN_SENT
                processTcpArpResponse(ether);
                sendTcpMessage(ether, getsocket(0), SYN, NULL, 0);
            }
            else
            {
                // send ARP request to MQTT broker
                uint8_t ip[4];
                getIpAddress(ip);
                uint8_t mqttip[4];
                getIpMqttBrokerAddress(mqttip);
                sendArpRequest(ether, ip, mqttip);
                //startOneshotTimer(callback, TIMEOUT_PERIOD);
            }
            break;
        case TCP_SYN_SENT:
            if (!isTcp(ether)) return;
            // i sent a SYN and this sees if i got a SYN/ACK back
            if (isTcpSyn(ether) && isTcpAck(ether))
            {
                processTcpResponse(ether); // update socket info and send ACK
                // start timer
                //startOneshotTimer(callback, TIMEOUT_PERIOD);
                // switch to established
                setTcpState(0, TCP_ESTABLISHED);
            }
            break;
        case TCP_ESTABLISHED:
            // send and receive data
            //startOneshotTimer(callback, TIMEOUT_PERIOD);
            // if the flag is RST or FIN, close the connection
            if (isTcp(ether))
            {
                ipHeader *ip = (ipHeader*)ether->data;
                uint8_t ipHeaderLength = ip->size * 4;
                tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
                uint16_t offsetFields = ntohs(tcp->offsetFields);
                if (offsetFields & FIN)
                {
                    setTcpState(0, TCP_CLOSE_WAIT);
                }
                else if (offsetFields & RST)
                {
                    setTcpState(0, TCP_CLOSED);
                }
                else
                {
                    processTcpResponse(ether); // get server data
                }
            }
            break;
        case TCP_CLOSE_WAIT:
            // send FIN ACK
            sendTcpMessage(ether, getsocket(0), FIN | ACK, NULL, 0);
            // start timer
            //startOneshotTimer(callback, TIMEOUT_PERIOD);
            setTcpState(0, TCP_LAST_ACK);
            break;
        case TCP_LAST_ACK:
            // check if ACK
            if (isTcp(ether) && isTcpAck(ether))
            {
                setTcpState(0, TCP_CLOSED);
                // close socket and free memory
            }
            break;
        default:
            setTcpState(0, TCP_CLOSED);
            break;
    }
}

void processTcpResponse(etherHeader *ether)
{
    // just checking
    if (!isTcp(ether)) return;

    // change window size in socket and check if ack number is correct
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // update socket info for future messages
    socket *s = getsocket(0);

    // update ack number when data is received
    uint16_t dataSize = ntohs(ip->length) - ipHeaderLength - sizeof(tcpHeader);
    if (dataSize > 0)
        s->acknowledgementNumber += dataSize; // update ack number
    else
        s->acknowledgementNumber += 1; // no data, just increment by 1

    if (tcp->sequenceNumber == s->acknowledgementNumber) // ack number needs to be syn + data size seq number updated in socket when data is sent
    {
        s->sequenceNumber = tcp->acknowledgementNumber;

        // check if data is present and process it
        uint16_t dataSize = ntohs(ip->length) - ipHeaderLength - sizeof(tcpHeader);
        if (dataSize > 0)
        {
            // process data here
            uint8_t *data = tcp->data;
            // MQTT happens here 
        }
    }
    sendTcpMessage(ether, s, ACK, NULL, 0); // send ACK back to server
}

void processTcpArpResponse(etherHeader *ether)
{
    // take in arp response
    arpPacket *arp = (arpPacket*)ether->data;
    // if its from mqtt broker, set state to SYN_SENT and make socket
    uint8_t mqttip[4];
    getIpMqttBrokerAddress(mqttip);
    if (!(arp->sourceIp == mqttip)) return;
    
    setTcpState(0, TCP_SYN_SENT);
    // populate socket
    socket *s = getsocket(0);

    // loop to populate both 
    uint8_t i;
    uint8_t j;
    for (i = 0; i < 4; i++)
    {
        s->remoteIpAddress[i] = arp->destIp[i];
    }
    for (j = 0; j < 6; j++)
    {
        s->remoteHwAddress[j] = arp->destAddress[j];
    }

    s->remotePort = 1883; // MQTT hard coded
    // local port is uint16_t 
    s->localPort = 49152; // random port number
    s->sequenceNumber = random32(); // random number for initial sequence number
    s->acknowledgementNumber = 0; // calcule ack number when data is sent
    s->state = getTcpState(0);
}

void setTcpPortList(uint16_t ports[], uint8_t count)
{
    tcpPortCount = count;
    uint8_t i;
    for (i = 0; i < count; i++)
    {
        tcpPorts[i] = ports[i];
    }
}

bool isTcpPortOpen(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // check if destination port is in the list
    uint16_t destPort = ntohs(tcp->destPort);
    if (destPort == 1883) return true; // MQTT hard coded
    return false;
}

// so far i dont use this function
void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
    // send TCP response based on flags and no data transfer

    // not TCP packet case
    if (!isTcp(ether)) return;
    // not open port case
    if (!isTcpPortOpen(ether))
    {
        sendTcpMessage(ether, s, RST, NULL, 0);
        setTcpState(s->state, TCP_CLOSED);
        return;
    }
    // send response flag
    sendTcpMessage(ether, s, flags, NULL, 0);
    // do i need to update window size, syn, ack, etc?
}

// Send TCP message
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
    uint16_t j;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t *copyData;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s->remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data; // up to here, ether is populated
    ip->rev = 0x4;
    ip->size = 0x5;
    ip->typeOfService = 0;
    //length
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
    // source ip
    // dest ip
    // data
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s->remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }
    uint8_t ipHeaderLength = ip->size * 4;

    // real work here boys
    //        |
    //        V
    // populating tcp header

    if (dataSize > 0)
        s->sequenceNumber += dataSize; // update sequence number
    else
        s->sequenceNumber += 1; // no data, just increment by 1

    // extracting from socket
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));
    tcp->sourcePort = htons(s->localPort);
    tcp->destPort = htons(s->remotePort);
    tcp->sequenceNumber = htons(s->sequenceNumber);
    tcp->acknowledgementNumber = htons(s->acknowledgementNumber);

    // data offset and flags
    uint8_t dataOffset = 20; // TCP header size
    uint16_t offsetsFlags = (dataOffset & 0xF) << OFS_SHIFT | (flags & 0xFFF);
    tcp->offsetFields = htons(offsetsFlags);

    // IS THE WINDOW HARD CODED?
    tcp->windowSize = htons(0xFFFF); // max window size

    //checksum
    tcpLength = ntohs(ip->length)-ipHeaderLength;
    copyData = tcp->data;
    for (j = 0; j < dataSize; j++)
        copyData[j] = data[j];
    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    sumIpWords(&tcpLength, 2, &sum);
    // add tcp header
    tcp->checksum = 0;
    sumIpWords(tcp, tcpLength, &sum);
    tcp->checksum = getIpChecksum(sum);

    // urgent pointer (padded cause idk where to get this)
    tcp->urgentPointer = 0;

    // send packet with size = ether + udp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}
