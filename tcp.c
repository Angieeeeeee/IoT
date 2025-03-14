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
socket  sockets[MAX_TCP_PORTS];

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
    return (offsetfields & 0xFF) == SYN; // check SYN flag
}

bool isTcpAck(etherHeader *ether)
{
    // check if ACK flag is set
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint16_t offsetfields = ntohs(tcp->offsetFields);
    return (offsetFields & 0xFF) == ACK; // check ACK flag
}

void sendTcpPendingMessages(etherHeader *ether)
{
    // put tcp state machine here
    // when in closed: send ARP request and start a timer and resend if timer expires
    // when in ARP_SENT: record socket SYN, send SYN, start a timer and resend if timer expires and open port
    // when in SYN_SENT: SYN/ACK rx -> send ACK, start a timer and resend if timer expires
    // when in ESTABLISHED: send data, start a timer and resend if timer expires
    // set initial state to closed then call for sendTcpPendingMessages
    uint8_t state = getTcpState(0);
    switch (state)
    {
        case TCP_CLOSED:
            // send ARP request or process ARP response
            if (isArpResponse(ether))
            {
                processTcpArpResponse(ether);
                // makes socket and switches to SYN_SENT
            }
            else
            {
                // resend ARP request
                // placeholder functions till i understand how they work 
                sendArpRequest(ether, myIP ,mqttBrokerIp); // how do i get IPs
                startOneshotTimer(callback, TIMEOUT_PERIOD);
            }
            break;
        case TCP_SYN_SENT:
            if (!isTcp(ether)) return;
            // i sent a SYN and this sees if i got a SYN/ACK back
            if (isTcpSyn(ether) && isTcpAck(ether))
            {
                processTcpResponse(ether);
                // send ACK
                sendTcpResponse(ether, getsocket(0), ACK);
                // start timer
                startOneshotTimer(callback, TIMEOUT_PERIOD);
                // switch to established
                setTcpState(0, TCP_ESTABLISHED);
            }
            break;
        case TCP_SYN_RECEIVED:
            // idk what this state is for
            break;
        case TCP_ESTABLISHED:
            // send data
            // if the flag is RST or FIN, close the connection
            if (isTcp(ether))
            {
                ipHeader *ip = (ipHeader*)ether->data;
                uint8_t ipHeaderLength = ip->size * 4;
                tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
                uint16_t offsetFields = ntohs(tcp->offsetFields);
                if (offsetFields & RST || offsetFields & FIN)
                {
                    setTcpState(0, TCP_CLOSED);
                }
            }
            break;
        case TCP_CLOSE_WAIT:
            break;
        case TCP_CLOSING:
            break;
        case TCP_LAST_ACK:
            break;
        case TCP_TIME_WAIT:
            break;
        default:
            setTcpState(0, TCP_CLOSED);
            break;
    }
}

void processTcpResponse(etherHeader *ether)
{
    // change window size in socket and check if ack number is correct
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // just checking
    if (!isTcp(ether)) return;

    // update window size
    socket *s = getsocket(0);

    if (tcp->acknowledgementNumber == s->sequenceNumber) // ack number needs to be syn + data size
    {
        s->sequenceNumber = tcp->acknowledgementNumber;
        s->windowSize = tcp->windowSize;
    }
}

void processTcpArpResponse(etherHeader *ether)
{
    // take in arp response and update TCP state machine
    arpPacket *arp = (arpPacket*)ether->data;
    // if its from mqtt broker, set state to SYN_SENT and make socket
    if (!(arp->sourceIp == mqttBrokerIp)) return;
    setTcpState(0, TCP_SYN_SENT);
    // populate socket
    socket *s = getsocket(0);
    /*
    typedef struct _socket
    {
    uint8_t remoteIpAddress[4];
    uint8_t remoteHwAddress[6];
    uint16_t remotePort;
    uint16_t localPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgementNumber;
    uint8_t  state;
    } socket;

    typedef struct _arpPacket // 28 bytes
    {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareSize;
    uint8_t protocolSize;
    uint16_t op;
    uint8_t sourceAddress[6];
    uint8_t sourceIp[4];
    uint8_t destAddress[6];
    uint8_t destIp[4];
    } arpPacket;
    */
    s->remoteIpAddress = arp->sourceIp;
    s->remoteHwAddress = arp->sourceAddress;
    s->remotePort = 1883; // MQTT hard coded
    s->localPort = 1883; // MQTT hard coded
    s->sequenceNumber = 0;
    s->acknowledgementNumber = 0;
    //s->state = TCP_SYN_SENT; idk about the state 

    //send SYN
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
    if (destPort == 1883) return true; // MQTT hard coded
    return false;
}

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
 
    // get window size from initial sequence number from server 
    tcp->windowSize = htons(s->windowSize);
 
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
