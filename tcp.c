// TCP Library (includes framework only)
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
    return (tcp->offsetFields & 0xF) == SYN; // check SYN flag
}

bool isTcpAck(etherHeader *ether)
{
    // check if ACK flag is set
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    return (tcp->offsetFields & 0xF) == ACK; // check ACK flag
}

void sendTcpPendingMessages(etherHeader *ether)
{
    //check if any of the TCP ports have pending messages
    uint8_t i;
    for (i = 0; i < tcpPortCount; i++)
    {
        uint8_t state = getTcpState(i);
        if (state == TCP_SYN_SENT)
        {
            sendTcpMessage(ether, s, SYN, NULL, 0);
        }
        else if (state == TCP_ESTABLISHED)
        {
            sendTcpMessage(ether, s, ACK, NULL, 0);
        }
        else if (state == TCP_FIN_WAIT_1)
        {
            sendTcpMessage(ether, s, FIN | ACK, NULL, 0);
        }
        else if (state == TCP_FIN_WAIT_2)
        {
            sendTcpMessage(ether, s, FIN | ACK, NULL, 0);
        }
        else if (state == TCP_TIME_WAIT)
        {
            sendTcpMessage(ether, s, FIN | ACK, NULL, 0);
        }
    }
}

void processTcpResponse(etherHeader *ether)
{
    // take in response and update TCP state machine
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // just checking
    if (!isTcp(ether)) return;
    if (!isTcpPortOpen(ether)) return;

    // find which instance the response is for
    uint8_t i;
    for (i = 0; i < tcpPortCount; i++)
    {
        if (tcpPorts[i] == ntohs(tcp->destPort))
            break;
    }

    // move to state based on flags
    if (tcp->flags & (SYN | ACK))
    {
        setTcpState(i, TCP_ESTABLISHED);
    }
    else if (tcp->flags & FIN)
    {
        setTcpState(i, TCP_FIN_WAIT_1);
    }
    else if (tcp->flags & ACK)
    {
        uint8_t state = getTcpState(i);
        if (state == TCP_FIN_WAIT_1)
        {
            setTcpState(i, TCP_FIN_WAIT_2);
        }
        else if (state == TCP_FIN_WAIT_2)
        {
            setTcpState(i, TCP_TIME_WAIT);
        }
    }
}

void processTcpArpResponse(etherHeader *ether)
{
    // take in arp response and update TCP state machine
    arpPacket *arp = (arpPacket*)ether->data;
    uint8_t i;
    for (i = 0; i < tcpPortCount; i++)
    {
        if (arp->sourceIp == tcpPorts[i])
            break;
    }
    setTcpState(i, TCP_SYN_SENT);

    // send SYN
    sendTcpMessage(ether, s, SYN, NULL, 0);
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
    uint8_t i;
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    
    // check if destination port is in the list
    uint16_t destPort = ntohs(tcp->destPort);
    for (i = 0; i < tcpPortCount; i++)
    {
        if (destPort == tcpPorts[i])
            return true;
    }
    return false;
}

void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
    //similar to sendTcpMessage
    uint8_t i;
    uint16_t j;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
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
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    ip->typeOfService = 0;
    ip->length = htons(sizeof(ipHeader) + sizeof(tcpHeader));
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s->remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }
    uint8_t ipHeaderLength = ip->size * 4;

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    tcp->sourcePort = htons(s->localPort);
    tcp->destPort = htons(s->remotePort);
    tcp->sequenceNumber = htonl(s->sequenceNumber);
    tcp->acknowledgementNumber = htonl(s->acknowledgementNumber);
    tcp->offsetFields = htons((0x5 << 12) | flags);
    tcp->windowSize = htons(0x2000);
    tcp->checksum = 0;
    tcp->urgentPointer = 0;

    // Calculate checksum
    tcpLength = sizeof(tcpHeader);
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    sumIpWords(&tcpLength, 2, &sum);
    sumIpWords(tcp, tcpLength, &sum);
    tcp->checksum = getIpChecksum(sum);

    // Send packet
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
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

    // extracting from socket 
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));
    tcp->sourcePort = htons(s->localPort);
    tcp->destPort = htons(s->remotePort);
    tcp->sequenceNumber = htons(s->sequenceNumber);
    tcp->acknowledgementNumber = htons(s->acknowledgementNumber);
 
    // data offset and flags
    uint8_t dataOffset = 0x5; // 20 bytes (standard idk)
    uint16_t offsetsFlag = (dataOffset & 0xF) << OFS_SHIFT | (flags & 0xFFF);
    tcp->offsetFields = htons(offsetsFlags);
 
    // window
    tcp->windowSize = htons(0x2000); // 8192 bytes 
 
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
    sumIpWords(udp, udpLength, &sum);
    tcp->checksum = getIpChecksum(sum);

    // urgent pointer (padded cause idk where to get this)
    tcp->urgentPointer = 0;
 
    // send packet with size = ether + udp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}
