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

// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

void connectMqtt()
{
    // connect to MQTT broker
    // send CONNECT message
    // send CONNACK message

}

void disconnectMqtt()
{


}

void publishMqtt(char strTopic[], char strData[])
{

}

void subscribeMqtt(char strTopic[])
{
    // send SUBSCRIBE message
    // send SUBACK message

}

void unsubscribeMqtt(char strTopic[])
{
    
}
