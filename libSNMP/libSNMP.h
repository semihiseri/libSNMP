#ifndef LIBSNMP_H
#define LIBSNMP_H

#include "settings.h"
#include "dataBlock.h"
#include "snmpUser.h"
#include "snmpObject.h"
#include "des.h"
#include "auth.h"
#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>         // UDP library from: bjoern@cs.stanford.edu 12/30/2008

static unsigned char sysUpTime[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};

class snmpMessage // this is a beautiful class. my masterpiece :P
{
  public:
    snmpMessage();
    void parseSNMP(unsigned char* rawData);
    void parseFurther();
    void printSNMP();
    void setVersion(int ver);

    int ver = SNMPV_DEFAULT
    
//#ifndef SNMP_V2C
    /* SNMP v3 Message Format */
    dataBlock msgBody;
      dataBlock msgBodyChildren[4];           // 0 = msgVersion, 1 = msgGlobalData, 2 = msgAuthEngine, 3 = msgData
        dataBlock *msgVersion;
        dataBlock *msgGlobalData;
          dataBlock msgGlobalDataChildren[4];     // 0 = msgID, 1 = msgMaxSize, 2 = msgFlags, 3 = msgSecurityModel
            dataBlock *msgID;
            dataBlock *msgMaxSize;
            dataBlock *msgFlags;
            dataBlock *msgSecurityModel;
        dataBlock *msgAuthEngineContainer;
          dataBlock msgAuthEngineContainerChildren[1]; // 0 =msgAuthEngine
            dataBlock *msgAuthEngine;
              dataBlock msgAuthEngineChildren[6];     // 0 = msgAuthEnID, 1 = msgAuthEnBoots, 2 = msgAuthEnTime, 3 = msgUserName, 4 = msgAuthParam, 5 = msgPrivParam
                dataBlock *msgAuthEngineID;
                dataBlock *msgAuthEnBoots;
                dataBlock *msgAuthEnTime;
                dataBlock *msgUserName;
                dataBlock *msgAuthParam;
                dataBlock *msgPrivParam;
        dataBlock *msgData;
          dataBlock msgDataChildren[3];           // 0 = ctxEngineID, 1 = ctxName, 2 = data (actual content)
            dataBlock *ctxEngineID;
            dataBlock *ctxName;
            dataBlock *data;
              dataBlock dataChildren[4];    // 0 = requestID, 1 = error-status, 2 = error-index, 3 = variableBindings
                dataBlock *requestID;
                dataBlock *errorStatus;
                dataBlock *errorIndex;
                dataBlock *variableBindings;
                  dataBlock variableBindingsChildren[10]; // Variable bindings, 1 in each.
//#else
    /* SNMP v2c Message Format */
//    dataBlock msgBody;
//      dataBlock msgBodyChildren[3];       // 0 = msgVersion, 1 = msgCommunity, 2 = data (to be compatible with v3 code)
//        dataBlock *msgVersion;
        dataBlock *msgCommunity;
//        dataBlock *data;
//          dataBlock dataChildren[4];    // 0 = requestID, 1 = error-status, 2 = error-index, 3 = variableBindings
//            dataBlock *requestID;
//            dataBlock *errorStatus;
//            dataBlock *errorIndex;
//            dataBlock *variableBindings;
//              dataBlock variableBindingsChildren[10]; // Variable bindings, 1 in each.
//#endif
};

int convertToStr(int input, unsigned char* buff); // TODO: Make this an actual function :D This one ought to return BER encoded integer. Returns length.

int compareStrings(unsigned char* ina, unsigned char* inb, int len); // Compares two strings. Returns 1 if they are same; 0 if not.

int des_cbc(unsigned char* input, int length, unsigned char* output, unsigned char* IV, unsigned char* key, short int mode);

class snmpAgent
{
  public:
    snmpAgent(); // Initializer
    void fillOIDList(); // Internal function
    int findOID(unsigned char* oid, int len); // Internal function
    int findUser(unsigned char* userName, int len); // Internal function
    void update(); // call this regularly :) This will handle everything
    void updateUpTime(); // Updates upTime
    void listen(); // Checks whether we have any incoming stuff
    void check(); // Checks whether we need to send a trap
    void sendTrapv2c(char* receiverIP, unsigned char* oid, int len, const char* community);
    void sendTrapv3(char* receiverIP, unsigned char* oid, int len, const char* userName, authType auth, privType priv); // oidNo is the index number of OID in the oidList.
    void addUser(const char* userName, authType auth, privType priv, const char* authPass, const char* privPass);
    void addObject(unsigned char* oid, int oidLength, objectType type, void* content);
    void addPermission(unsigned char* oidName, int oidLength, unsigned char* userName, int userLength, unsigned char permission);
    void setVersion(int ver);
    void init(); // Well, just UDP functions
    int setEngineID(unsigned char* newEngineID, int newEngineIDLength);

    snmpMessage message;
    snmpObject objects[MAX_OBJECTS];
    int numberOfObjects;
    snmpUser users[MAX_USERS];
    int numberOfUsers;
    int localUpTime = 0;
    int prevMillis = 0;
    int notInTimeWindows = 0;
    int unknownUserNames = 0;
    int unknownEngineIDs = 0;
    int unsupportedSecLevels = 0;
    int wrongDigests = 0;
    int decryptionErrors = 0;
    unsigned char authDigest[12];
    char communityString[MAX_COMMUNITY_STRING];

    int ver=SNMPV_DEFAULT;
  
    unsigned char engineID[32] = {0x80,0x00,0x1f,0x88,0x80,0x0c,0xc6,0xd3,0x47,0xde,0x36,0xca,0x57};
    int engineIDLength = 13;
};


/*
class oidContainer
{
  public:
    void returnContent(unsigned char* output);
    int returnOID(unsigned char* output);

    char contentOID[20]; // OID in hex
    int oidLength;
    contentType type;
    char* _string;
    int _length;
};

class oid
{
  void returnOID(unsigned char* output);

  static char buf; // this will be used to construct the output :)
  contentType type;
  void* content;
};

*/

#endif
