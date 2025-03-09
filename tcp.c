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
    return false;
}

bool isTcpAck(etherHeader *ether)
{
    return false;
}

void sendTcpPendingMessages(etherHeader *ether)
{
}

void processTcpResponse(etherHeader *ether)
{
}

void processTcpArpResponse(etherHeader *ether)
{
}

void setTcpPortList(uint16_t ports[], uint8_t count)
{
}

bool isTcpPortOpen(etherHeader *ether)
{
    return false;
}

void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
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
    uint16_t offsetsFlag = (dataOffset & 0xF) << 12 | (flags & 0xFFF);
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
