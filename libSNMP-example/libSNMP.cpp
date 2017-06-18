#include <Arduino.h>

#include "libSNMP.h"

EthernetUDP Udp;

void snmpMessage::setVersion(int ver)
{
  if (ver==2 || ver==3)
  {
    this->ver = ver;
    if (this->ver == 3)
    {
      this->msgBody.children = this->msgBodyChildren;
      this->msgVersion = this->msgBodyChildren;
      this->msgGlobalData = this->msgBodyChildren+1;
      this->msgAuthEngineContainer = this->msgBodyChildren+2;
      this->msgData = this->msgBodyChildren+3;

      this->msgGlobalData->children = this->msgGlobalDataChildren;
      this->msgID = this->msgGlobalDataChildren;
      this->msgMaxSize = this->msgGlobalDataChildren+1;
      this->msgFlags = this->msgGlobalDataChildren+2;
      this->msgSecurityModel = this->msgGlobalDataChildren+3;

      this->msgAuthEngineContainer->children = this->msgAuthEngineContainerChildren;
      this->msgAuthEngine = this->msgAuthEngineContainerChildren;
  
      this->msgAuthEngine->children = this->msgAuthEngineChildren;
      this->msgAuthEngineID = this->msgAuthEngineChildren;
      this->msgAuthEnBoots = this->msgAuthEngineChildren+1;
      this->msgAuthEnTime = this->msgAuthEngineChildren+2;
      this->msgUserName = this->msgAuthEngineChildren+3;
      this->msgAuthParam = this->msgAuthEngineChildren+4;
      this->msgPrivParam = this->msgAuthEngineChildren+5;
  
      this->msgData->children = this->msgDataChildren;
      this->ctxEngineID = this->msgDataChildren;
      this->ctxName = this->msgDataChildren+1;
      this->data = this->msgDataChildren+2;

      this->data->children = this->dataChildren;
      this->requestID = this->dataChildren;
      this->errorStatus = this->dataChildren+1;
      this->errorIndex = this->dataChildren+2;
      this->variableBindings = this->dataChildren+3;

      this->variableBindings->children = this->variableBindingsChildren;
    }
//#else
    else if (this->ver == 2)
    {
//    dataBlock msgBody;

//          dataBlock dataChildren[4];    // 0 = requestID, 1 = error-status, 2 = error-index, 3 = variableBindings
//            dataBlock *requestID;
//            dataBlock *errorStatus;
//            dataBlock *errorIndex;
//            dataBlock *variableBindings;
//              dataBlock variableBindingsChildren[10]; // Variable bindings, 1 in each.

      this->msgBody.children = this->msgBodyChildren;
      this->msgVersion = this->msgBodyChildren;
      this->msgCommunity = this->msgBodyChildren+1;
      this->data = this->msgBodyChildren+2;
  
      this->data->children = this->dataChildren;
      this->requestID = this->dataChildren;
      this->errorStatus = this->dataChildren+1;
      this->errorIndex = this->dataChildren+2;
      this->variableBindings = this->dataChildren+3;
  
      this->variableBindings->children = this->variableBindingsChildren;
    }
  }
}

snmpMessage::snmpMessage() // Here a standard empty SNMP message template is built. Same template can be used for v1, v2c and v3.
{
  this->setVersion(this->ver);
}

void snmpMessage::parseSNMP(unsigned char* rawData)
{
	if (this->ver == 3)
	{
		this->msgBody.parseSelf(rawData);
		this->msgBody.parseChildren(); // Now we should have msgVersion, msgGlobalData, msgAuthEngine and msgData in their places.
		this->msgGlobalData->parseChildren();
		this->msgAuthEngineContainer->parseChildren();
		this->msgAuthEngine->parseChildren();
  
		if (!((this->msgFlags)->_content[0] & 0b00000010)) // Is encrypted?
		{
			this->parseFurther();
		}
		else
		{
			Serial.println("Encrypted!");
		}
	}
	else if (this->ver == 2)
	{
		this->msgBody.parseSelf(rawData);
		this->msgBody.parseChildren(); // Now we should have msgVersion, msgGlobalData, msgAuthEngine and msgData in their places.
		this->data->parseChildren();
		this->variableBindings->parseChildren();
	}
}

void snmpMessage::parseFurther() // If the incoming message is encrypted, this function should be called after decryption
{ 
  this->msgData->parseChildren();
  this->data->parseChildren();
  this->variableBindings->parseChildren();
}

int convertToStr(int input, unsigned char* buff) // TODO: Make this an actual function :D This one ought to return BER encoded integer. Returns length.
{
  buff[0] = input&0xFF;
  return 1;
}

int compareStrings(unsigned char* ina, unsigned char* inb, int len) // Compares two strings. Returns 1 if they are same; 0 if not.
{
  int x;
  for(x=0; x<len;x++)
  {
    if (ina[x] != inb[x])
      return 0;
  }
  return 1;
}

int des_cbc(unsigned char* input, int length, unsigned char* output, unsigned char* IV, unsigned char* key, short int mode)
{
  int offset = 0;
  int x;
  char tempIV[8];
  char tempMsg[8];

  key_set key_sets[17] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  generate_sub_keys(key, key_sets);

  if (mode == 0) //if decrypt
  {
    if (length%8 != 0)
    {
      printf("Error! Length is not divisible by 8\n");
      return 0;
    }

    process_message(input, output, key_sets, DECRYPTION_MODE);

    for (x=0; x<8; x++)
    {
      output[x] ^= IV[x];
    }

    while (offset < length)
    {
      offset += 8;

      process_message(input+offset, output+offset, key_sets, DECRYPTION_MODE);

      for (x=0; x<8; x++)
      {
        output[x+offset] ^= input[x+offset-8];
      }
    }
    return length;
  }
  else if (mode == 1) // if encrypt
  {
    if (length%8 != 0) // Padding
    {
      for (x=(((length/8)+1)*8)-1; x>=length; x--)
      {
        input[x] = 8-length%8;
      }
    }

    length =((length/8)+1)*8;

    offset = 0;

    while (offset <= length)
    {
      for (x=0; x<8; x++)
      {
        IV[x] ^= input[x+offset];
      }
      
      process_message(IV, output+offset, key_sets, ENCRYPTION_MODE);

      for (x=0; x<8; x++)
      {
        IV[x] = output[offset+x];
      }

      offset += 8;
    }

    return length;
  }
}

snmpAgent::snmpAgent()
{
  this->numberOfObjects = 0;
  this->fillOIDList();
}

void snmpAgent::setVersion(int ver)
{
  if (ver==2 || ver==3)
  {
    this->ver = ver;
    (this->message).setVersion(ver);
  }
}

void snmpAgent::addUser(const char* userName, authType auth, privType priv, const char* authPass, const char* privPass)
{
  int x;
  strcpy(this->users[this->numberOfUsers].userName, userName);
  if (auth != 0)
  {
    if (authPass != NULL)
    {
      if (auth == SHA)
      {
        password_to_key_sha((unsigned char*) authPass, strlen(authPass), this->engineID, this->engineIDLength, (unsigned char*) this->users[this->numberOfUsers].authKey);
        this->users[this->numberOfUsers].auth = SHA;
      }
      else if (auth == MD5)
      {
        password_to_key_md5((unsigned char*) authPass, strlen(authPass), this->engineID, this->engineIDLength, (unsigned char*) this->users[this->numberOfUsers].authKey);
        this->users[this->numberOfUsers].auth = MD5;
      }
    }

    else
    {
      Serial.print("Authentication is enabled for this user, yet no pass given: ");
      Serial.println((char*) userName);
      auth = NOAUTH;
      priv = NOPRIV;
    }
      
    if (priv != 0)
    {
      if (privPass != NULL)  
      {
        if (priv == DES)
        {
          if (auth == MD5)
          {
            password_to_key_md5((unsigned char*) privPass, strlen(privPass), this->engineID, this->engineIDLength, (unsigned char*) this->users[this->numberOfUsers].privKey);
            this->users[this->numberOfUsers].priv = DES;
            Serial.print("privKey is: ");
            for (x=0;x<16; x++)
            {
              Serial.print(this->users[this->numberOfUsers].privKey[x], HEX);
              Serial.print(" ");
            }
            Serial.println();
          }
		  else if (auth == SHA)
		  {
			  password_to_key_sha((unsigned char*)privPass, strlen(privPass), this->engineID, this->engineIDLength, (unsigned char*) this->users[this->numberOfUsers].privKey);
			  this->users[this->numberOfUsers].priv = DES;
			  Serial.print("privKey is: ");
			  for (x = 0; x<16; x++)
			  {
				  Serial.print(this->users[this->numberOfUsers].privKey[x], HEX);
				  Serial.print(" ");
			  }
			  Serial.println();
		  }
        }
      }
      else
      {
        Serial.print("Encryption is enabled for this user, yet no pass given: ");
        Serial.println((char*) userName);
        priv = NOPRIV;
      }
    }

    for (x=0; x<MAX_OBJECTS; x++)
    {
      this->users[this->numberOfUsers].permissions[x] = 0;
    }
  }

  this->numberOfUsers ++;
}

void snmpAgent::addPermission(unsigned char* oidName, int oidLength, unsigned char* userName, int userLength, unsigned char permission) // 00: no access, 01: access, 10: auth access, 11: priv access
{
  int x;
  snmpUser *user;
  x = this->findUser(userName, userLength);
  if (x >= 0) // Check for SNMP user name Match
  {
    user = &users[x];

    x = findOID(oidName, oidLength); // TODO: Do something for graceful "no OID message"
    if (x>=0)
    {
      user->permissions[x] = permission;
    }
    else
      Serial.println("OID can not be found");
  }
  else
    Serial.println("User can not be found");
}

void snmpAgent::addObject(unsigned char* oid, int oidLength, objectType type, void* content)
{
  this->objects[this->numberOfObjects].oid = oid;
  this->objects[this->numberOfObjects].oidLen = oidLength;
  this->objects[this->numberOfObjects].type = type;
  this->objects[this->numberOfObjects].content = content;
  this->numberOfObjects += 1;
}

float illumination = 22.12;

void snmpAgent::fillOIDList()
{  
  static unsigned char usmStatsUnsupportedSecLevels[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x01, 0x00};
  static unsigned char usmStatsNotInTimeWindows[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x02, 0x00};
  static unsigned char usmStatsUnknownUserNames[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x03, 0x00};
  static unsigned char usmStatsUnknownEngineIDs[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00};
  static unsigned char usmStatsWrongDigests[]     = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x05, 0x00};
  static unsigned char usmStatsDecryptionErrors[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x06, 0x00};
  
  static unsigned char sysUpTime[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
  
  this->addObject(usmStatsUnknownEngineIDs, 10, COUNTER, &this->unknownEngineIDs);
  this->addObject(usmStatsUnknownUserNames, 10, COUNTER, &this->unknownUserNames);
  this->addObject(usmStatsWrongDigests, 10, COUNTER, &this->wrongDigests);
  this->addObject(usmStatsDecryptionErrors, 10, COUNTER, &this->decryptionErrors);
  this->addObject(usmStatsUnsupportedSecLevels, 10, COUNTER, &this->unsupportedSecLevels);
  
  this->addObject(sysUpTime, 8, TICK, &this->localUpTime);  
}

int snmpAgent::findUser(unsigned char* userName, int len)
{
  int x,y;
  for (x=0;x<this->numberOfUsers;x++)
  {
    if (len != strlen((const char*) users[x].userName))
      continue;
    for (y=0;y<len;y++)
    {
      if (this->users[x].userName[y] != userName[y])
        break;
      if (y==len-1)
        return x;
    }
  }
  return -1;
}

int snmpAgent::findOID(unsigned char* oid, int len)
{
  int x,y;
  
  for (x=0;x<this->numberOfObjects;x++)
  {
    if (len != this->objects[x].oidLen)
      continue;
    for (y=0;y<len;y++)
    {
      if (this->objects[x].oid[y] != oid[y])
        break;
      if (y==len-1)
        return x;
    }
  }
  return -1;
}

void snmpAgent::update()
{
  this->updateUpTime();
  this->listen();
}

void snmpAgent::updateUpTime() // Updates sysUpTime and its string.
{
  if (millis() - this->prevMillis > 1000)
  {
    // increment previous milliseconds
    this->prevMillis += 1000;

    // increment up-time counter
    this->localUpTime += 100;
   }
}

void snmpAgent::init()
{
  Udp.begin(161); // 161 being SNMP port -This looks odd :P 
}

int snmpAgent::setEngineID(unsigned char* newEngineID, int newEngineIDLength)
{
  int x;
  if (newEngineIDLength < 5 || newEngineIDLength>32)
  {
    Serial.println("EngineID length is not within specifications");
    return 0;
  }
  else
  {
    for (x=0; x<newEngineIDLength; x++)
    {
      this->engineID[x] = newEngineID[x];
    }
    this->engineIDLength = newEngineIDLength;
  }

  this->numberOfUsers = 0; // resets the user count as the old users will not work anymore. keys are changed!
}

int snmpAgent::v3engineIdMatches() // returns 1 if engine ID matches
{
	dataBlock *hede;
	int result = 0;
	if (this->ver == 3)
	{
		hede = this->message.msgAuthEngineID;
		result = (hede->_length == this->engineIDLength && compareStrings(hede->_content, this->engineID, this->engineIDLength));
	}

	return result;
}

int snmpAgent::v3userExists() // returns 1 if user is found
{
	int x;
	int result = 0;
	dataBlock *hede;
	if (this->ver == 3)
	{
		hede = this->message.msgUserName;

		x = this->findUser(hede->_content, hede->_length);

		Serial.println(x);
		Serial.print(strlen(users[x].userName));
		Serial.print(" ");
		Serial.println(hede->_length);
		result = ((x >= 0) && strlen(users[x].userName) == hede->_length);
	}

	return result;
}

snmpUser* snmpAgent::v3getUser() // returns pointer to the user object. should be called only when user exists
{
	int x;
	dataBlock *hede;
	if (this->ver == 3)
	{
		hede = this->message.msgUserName;

		x = this->findUser(hede->_content, hede->_length);
		return &users[x];
	}
	else
	{
		return 0;
	}
}

int snmpAgent::v3securityOK(snmpUser *user) // returns 1 if user's and message's security parameters correspond
{
	int result = 0;
	if (this->ver == 3)
	{
		// In human language: return false if message has auth flag but user has no auth, or message has priv flag but user has no priv
		result = (!((((this->message.msgFlags)->_content[0] & 0b00000001) && user->auth == 0) || (((this->message.msgFlags)->_content[0] & 0b00000010) && user->priv == 0)));
		Serial.print("Reporting from v3securityOK ");
		Serial.println(result);
	}
	return result;
}

int snmpAgent::v3authValid(snmpUser *user) // returns 1 if authentication is enabled and is valid.
{
	unsigned char authDummy[30], dummy[12], outbuffer[1000];
	dataBlock *hede;
	int x;
	int result = 0;

	if (this->ver == 3 && ((this->message.msgFlags)->_content[0] & 0b00000001)) // Check for message integrity (a.k.a. Authentication)
	{
		Serial.println("Auth Enabled");

		for (x = 0; x<12; x++) // Storing incoming authParam into first 12 locations of dummy
		{
			dummy[x] = (this->message.msgAuthParam)->_content[x];
		}

		hede = this->message.msgAuthParam;
		hede->_content = this->authDigest;
		hede->_length = 12;

		this->authDigest[0] = 0x00; // loops? no.
		this->authDigest[1] = 0x00;
		this->authDigest[2] = 0x00;
		this->authDigest[3] = 0x00;
		this->authDigest[4] = 0x00;
		this->authDigest[5] = 0x00;
		this->authDigest[6] = 0x00;
		this->authDigest[7] = 0x00;
		this->authDigest[8] = 0x00;
		this->authDigest[9] = 0x00;
		this->authDigest[10] = 0x00;
		this->authDigest[11] = 0x00;

		x = this->message.msgBody.createOutput(outbuffer); // x holds the length of the message

		if (user->auth == SHA)
		{
			lrad_hmac_sha1((unsigned char*)outbuffer, x, (unsigned char*)user->authKey, 20, authDummy);
		}
		else if (user->auth == MD5)
		{
			hmac_md5((unsigned char*)outbuffer, x, (unsigned char*)user->authKey, 16, authDummy); // Auth dummy exists because MD5 functions somehow corrupt the engineID
		}

	} // Check if we have authentication
	result = ((!((this->message.msgFlags)->_content[0] & 0b00000001)) || ((authDummy[0] == dummy[0]) && (authDummy[1] == dummy[1]) && (authDummy[2] == dummy[2]) && (authDummy[3] == dummy[3]) && (authDummy[4] == dummy[4]) && (authDummy[5] == dummy[5]) && (authDummy[6] == dummy[6]) && (authDummy[7] == dummy[7]) && (authDummy[8] == dummy[8]) && (authDummy[9] == dummy[9]) && (authDummy[10] == dummy[10]) && (authDummy[11] == dummy[11]))); // regular people use loops for this. but I am "special"
	return result;
}

void snmpAgent::v3decrypt(snmpUser *user)
{
	int x;
	unsigned char IV[8];

	if (this->ver == 3 && ((this->message.msgFlags)->_content[0] & 0b00000010)) // That is, the message is encrypted
	{
		Serial.println("Doin' decryption...");
		for (x = 0; x<8; x++) // Calculating IV using salt and pre-IV
		{
			IV[x] = (this->message.msgPrivParam)->_content[x] ^ user->privKey[8 + x];
		}

		des_cbc((this->message.msgData)->_content, (this->message.msgData)->_length, (this->message.msgData)->_content + (this->message.msgData)->_length, IV, (unsigned char*)user->privKey, 0);

		/*for (x=0; x<200; x++)
		{
		if (x== (this->message.msgData)->_length)
		Serial.println();
		Serial.print(((this->message.msgData)->_content[x]), HEX);
		Serial.print(" ");
		}
		Serial.println();*/

		(this->message.msgData)->parseSelf((this->message.msgData)->_content + (this->message.msgData)->_length);

		(this->message.msgData)->printContent();

		this->message.parseFurther();
	}
}

void snmpAgent::v3fillTime()
{
	dataBlock *hede;
	hede = this->message.msgAuthEnTime;
	hede->_content = this->timebuffer;
	this->timebuffer[0] = this->localUpTime / 16777216; // README: I don't know how optimization is done here. But we can use >>24 as well.
	this->timebuffer[1] = (this->localUpTime / 65536) % 256; // similarly, >>16
	this->timebuffer[2] = (this->localUpTime / 256) % 256; // >>8
	this->timebuffer[3] = this->localUpTime % 256;
	hede->_length = 4;
}

void snmpAgent::gracefulNoOID()
{
	dataBlock *hede;

	hede = this->message.variableBindings;
	hede = &(hede->children[0]);

	if (this->ver == 3)
	{
		Serial.println("The requested thing is not found among our OIDs");
		hede->printSelf();
		hede->_content[hede->_length - 2] = 0x80; // FIXME: This doesn't work for v2!
	}
	else if (this->ver == 2)
	{
		hede = this->message.errorStatus;
		hede->_content[0] = (unsigned char)6;
		// FIXME: Using errorindex we can generate more meaningful errors
	}
}

void snmpAgent::v3fillError(int errorIdx) // Fills the required fields for an error message. errorIdx is the index number of the object in the objects array.
{
	dataBlock *hede;
	int x;

	hede = this->message.msgAuthEngineID; // auth engine id part
	hede->_content = this->engineID;
	hede->_length = this->engineIDLength;

	hede = this->message.ctxEngineID; // context engine id part
	hede->_content = this->engineID;
	hede->_length = this->engineIDLength;

	hede = this->message.msgFlags;
	hede->_content[0] = 0;

	hede = this->message.msgData;
	hede->childrenCount = 3;
	hede->_type = SEQ;

	hede = this->message.errorIndex;
	hede->_content[0] = 0;

	hede = this->message.errorStatus;
	hede->_content[0] = 0;

	hede = this->message.data;
	hede->_type = REPORT;

	hede = &(this->message.variableBindings->children[0]);
	hede->_type = SEQ;
	hede->_content = this->jokerbuffer;
	x = this->objects[errorIdx].returnObject(this->jokerbuffer);
	hede->_length = x;
	hede = this->message.variableBindings;
	hede->childrenCount = 1;
}

void snmpAgent::listen()
{
  snmpUser *user;
  dataBlock *hede;
  dataBlock dummyBinding[2]; // yet another dummy data block. Used while responding to snmpset requests
  int x, y;
  unsigned char outbuffer[1000];
  unsigned char inbuffer[1000];
  unsigned char timebuffer[4];
  unsigned char oid[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00};
  //unsigned char kedi[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03};
  unsigned char hebe[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
  unsigned char IV[8];

  unsigned char dummy[100], authDummy[30];

  delay(10);

  if (Udp.parsePacket())
      delay(5);
  else
      return;

  Udp.read(inbuffer, 500);

  for (x=0;x<10;x++)
  {
    objects[0].oid[x] = oid[x];
  }

  Serial.println("Started");
  this->message.parseSNMP(inbuffer);
  
  if (this->ver == 2 || this->v3engineIdMatches()) // Check for SNMP authEngineID match
  {    
    Serial.println("yayy :) engine ID matches");

    if (this->ver == 2 || this->v3userExists()) // Check for SNMP user name Match
    {
	  Serial.println("yayyyyy :D user name also matches");
      user = v3getUser();

      if (this->ver == 2 || this->v3securityOK(user))
      {
        Serial.println("Security level seems OK");
      
		if (this->ver == 2 || this->v3authValid(user))
        {
          Serial.println("Message is properly authenticated");

          if (this->ver == 2 || (!((this->message.msgFlags)->_content[0] & 0b00000010) || (((this->message.msgFlags)->_content[0] & 0b00000010) && ((this->message.msgData)->_length)%8 == 0))) // This is for DES. AES is not implemented.
          {
			this->v3decrypt(user);

            if (this->ver == 3 && (user->auth == SHA || user->auth == MD5)) // FIXME: Use flags instead of users
            {
              hede = this->message.msgFlags; // Set message flags to no report
              hede->_content[0] &= 0b00000011; // 0: no auth no priv; 1: auth no priv; 3: auth priv; 2: shouldn't be used
            }
            else if (this->ver == 3)
            {
              hede = this->message.msgFlags;
              hede->_content[0] = 0;
            }

			this->v3fillTime();

            // TODO: Put a for loop here to span all OIDs requested. Now responses to only one.
            
            hede = this->message.variableBindings;
            hede = &(hede->children[0]);
            x = findOID(&(hede->_content[2]),hede->_content[1]); // TODO: Do something for graceful "no OID message"

			Serial.println("looking for OID...");

            if (x>=0 &&(this->ver == 2 || user->permissions[x] != 0)) // Permissions block. FIXME: Make it simpler!
            { 
              hede->printSelf();
              Serial.print("Found OID:");
              Serial.println(x);

              if (this->ver == 2)
              {
                hede = this->message.msgCommunity;

                if (!((hede->_length == strlen(this->communityString)) && compareStrings((unsigned char*) this->communityString, hede->_content, hede->_length)))
                {
                  Serial.println("Community strings did not match! Dropping");
                  return;
                }
                
                Serial.println(hede->_length);
                Serial.println(strlen(this->communityString));
                for (y=0; y<20; y++)
                {
                  Serial.print(hede->_content[y]);
                  Serial.print(" ");
                }
                Serial.println();
              }

              /*
              hede = this->message.data;
              if (hede->_type == SETREQ)
              {
                Serial.println("Hooraay! We have a set request here");
                // Check for the community string
                hede = this->message.variableBindings;
                hede = &(hede->children[0]);

                hede->children = dummyBinding;
                hede->parseChildren();

                hede = &(hede->children[1]);
                
                Serial.println(hede->_type, HEX);

                if (hede->_type == OCTSTR)
                {
                  Serial.println("ehe =)");
                  hede->printContent();
                  Serial.println((this->objects[x]).type);
                  if ((this->objects[x]).type == OCTSTRING)
                  {
                    for (y=0; y<hede->_length; y++)
                    {
                      ((unsigned char*) objects[x].content)[y] = (unsigned char) hede->_content[y];
                    }
                  }
                  else
                  {
                    hede = this->message.errorStatus;
                    hede->_content[0] = (unsigned char) 7;
                  }
                }
                else
                {
                  hede = this->message.errorStatus;
                  hede->_content[0] = (unsigned char) 17;
                }
              }

              */

              hede = this->message.variableBindings;
              hede = &(hede->children[0]);

              if (this->ver == 2 || ((user->permissions[x] == 1) || ((user->permissions[x] == 2) && ((this->message.msgFlags)->_content[0] & 0b00000001)) || ((user->permissions[x] == 3) && ((this->message.msgFlags)->_content[0] & 0b00000010))))
              {
                x = objects[x].returnObject(dummy); // x holds the length of the object
                hede->_length = x;
                hede->_content = dummy;
                hede->printSelf();
              }

              else if (this->ver == 3)
              {
                hede = this->message.errorStatus;
                hede->_content[0] = (unsigned char) 16; // Authorization Error
              }

            }
            else // This is the graceful noOID message
            {
				this->gracefulNoOID();
            }

            hede = this->message.data;
            hede->_type = GETRES; // Outgoing message type is GET response

            if (this->ver == 3 && ((this->message.msgFlags)->_content[0] & 0b00000010)) // That is, the message needs to be encrypted
            {
				for (x = 0; x<8; x++) // Calculating IV using salt and pre-IV
				{
					IV[x] = (this->message.msgPrivParam)->_content[x] ^ user->privKey[8 + x];
				}
              Serial.println("Doin' encryption...");

              hede = this->message.msgData;

              x = (this->message.msgData)->createOutput(outbuffer); // x holds the length of the message
              (this->message.msgData)->_type = OCTSTR;
              (this->message.msgData)->_length = des_cbc(outbuffer, x, (this->message.msgData)->_content, IV, (unsigned char*) user->privKey, 1);
              (this->message.msgData)->childrenCount = 0;

              Serial.println("Encrypted Content:");
              (this->message.msgData)->printContent();
            }

            x = this->message.msgBody.createOutput(outbuffer); // x holds the length of the message

            if (user->auth == SHA)
            {
              lrad_hmac_sha1((unsigned char*) outbuffer, x, (unsigned char*) user->authKey, 20, this->authDigest);
            }
            else if (user->auth == MD5)
            {
              hmac_md5((unsigned char*) outbuffer, x, (unsigned char*) user->authKey, 16, authDummy); // Auth dummy exists because MD5 functions somehow corrupt the engineID
              for (x=0; x<12; x++)
              {
                this->authDigest[x] = authDummy[x];
              }
//#endif // <-------------------------------------------------------------------------------------------------------------ifndef SNMP_V2C  
            }

          }
          else // this is the case when we have a decryption error
          {
			  // TODO: Check report flag here. If no report, do not report.
            Serial.println("There's something wrong regarding to decryption >:'(");

			this->v3fillTime();
            this->decryptionErrors ++; // Increase the unknown engine id counter by one
			this->v3fillError(3);
          }
        } // Check for authentication validity
        else // Package integrity can not be validated: wrongDigest
        {
			// TODO: Check report flag here. If no report, do not report.
          Serial.println("Wrong digest  :(");

		  this->v3fillTime();
          this->wrongDigests ++; // Increase the unknown engine id counter by one
		  this->v3fillError(2);
        }
      }
      else
      {
		  // TODO: Check report flag here. If no report, do not report.
        Serial.println("Problem regarding security levels :(");
        
		this->v3fillTime();
        this->unsupportedSecLevels ++; // Increase the unknown engine id counter by one
		this->v3fillError(4);
      }
    }
    else
    {
	  // TODO: Check report flag here. If no report, do not report.
      Serial.println("No such user :'(");

	  this->v3fillTime();      
      this->unknownUserNames ++; // Increase the unknown engine id counter by one
	  this->v3fillError(1);
    }
  }
  else
  {
	  // TODO: Check report flag here. If no report, do not report.
      Serial.println(">:(");

	  this->v3fillTime();
      this->unknownEngineIDs ++; // Increase the unknown engine id counter by one
	  this->v3fillError(0);
    }

    this->message.msgBody.createOutput(outbuffer);
    Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
    Udp.write(outbuffer,returnInt(outbuffer+1, &x)+x+1);
    Udp.endPacket();
}

void snmpAgent::sendTrapv3(char* receiverIP, unsigned char* oid, int len, const char* userName, authType auth, privType priv)
{
//#ifndef SNMP_V2C
  if (this->ver != 3)
  {
    Serial.println("Version 3 trap can not be sent as the version switch is set to v2c!");
  }
  else
  {
    unsigned char trapTemplate[] = {
		0x30, 0x81, 0x84, 0x02, 0x01, 0x03, 0x30, 0x11,
		0x02, 0x04, 0x09, 0xd7, 0x25, 0x09, 0x02, 0x03, 
		0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01, 
		0x03, 0x04, 0x21, 0x30, 0x1f, 0x04, 0x0d, 0x80, 
		0x00, 0x1f, 0x88, 0x80, 0xff, 0x61, 0x81, 0x68, 
		0x72, 0xa0, 0xe1, 0x56, 0x02, 0x01, 0x18, 0x02, 
		0x01, 0x00, 0x04, 0x04, 0x6b, 0x65, 0x64, 0x69, 
		0x04, 0x00, 0x04, 0x00, 0x30, 0x49, 0x04, 0x0d, 
		0x80, 0x00, 0x1f, 0x88, 0x80, 0xff, 0x61, 0x81, 
		0x68, 0x72, 0xa0, 0xe1, 0x56, 0x04, 0x00, 0xa7, 
		0x36, 0x02, 0x04, 0x37, 0x84, 0x75, 0x9d, 0x02, 
		0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x28, 0x30, 
		0x0f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 
		0x01, 0x03, 0x00, 0x43, 0x03, 0x10, 0x1a, 0x23, 
		0x30, 0x15, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 
		0x03, 0x01, 0x01, 0x04, 0x01, 0x00, 0x06, 0x07, 
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01
    }; // This is pure laziness. Using an example trap, we just fill in the necessary details in it and send as a new trap.
    dataBlock *dummy;
    snmpUser *user;
    unsigned char outbuffer[1000];
    unsigned char temp[100];
    int oidNo;
    int x;
  
    oidNo = this->findOID(oid, len);
  
    dataBlock children[2];
  
    this->message.parseSNMP(trapTemplate);
    
    dummy = this->message.msgAuthEngineID;
    dummy->_content = this->engineID;
    dummy->_length = engineIDLength;
  
    dummy = this->message.ctxEngineID;
    dummy->_content = this->engineID;
    dummy->_length = engineIDLength;
  
    x = this->findUser((unsigned char*) userName, strlen(userName));
    if (x<0)
    {
      Serial.println("No such user could be found while sending trap!");
      return;
    }
  
    user = &(this->users[x]);
  
    dummy = this->message.msgUserName;
    dummy->_content = (unsigned char*) user->userName;
    dummy->_length = strlen(user->userName);
  
    dummy = this->message.variableBindings;
    dummy = &(dummy->children[0]);
    dummy->printSelf();
    dummy->printContent();
  
    x = objects[oidNo].returnObject(temp);
    dummy->_length = x;
    dummy->_content = temp;
  
    Serial.println("kedikedikedi");
    dummy = this->message.variableBindings;
    dummy = &(dummy->children[1]);
    dummy->printSelf();
    dummy->printContent();
    dummy->children = children;
    dummy->parseChildren();
    Serial.println("yubiloo");
    dummy->printSelf();
    dummy->printContent();
  
    children[1]._content = (unsigned char*) objects[oidNo].oid;
    children[1]._length = objects[oidNo].oidLen;
    
    x = this->message.msgBody.createOutput(outbuffer);
  
    Udp.beginPacket(receiverIP, 162); // Trap address is here!!
    Udp.write(outbuffer,x);
    Udp.endPacket();
  
    Serial.println("");
    for (int x =0; x<200; x++)
    {
      Serial.print(outbuffer[x], HEX);
      Serial.print(" ");
    }
    Serial.println("");
    Serial.println("");
  }
//#else
//#endif
}

void snmpAgent::sendTrapv2c(char* receiverIP, unsigned char* oid, int len, const char* community)
{
  if (this->ver != 2)
  {
    Serial.println("Version of this trap bla bla bla");
    return;
  }
  else
  {
    unsigned char trapTemplate[] = {
      0x30, 0x44, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 
      0x75, 0x62, 0x6c, 0x69, 0x63, 0xa7, 0x37, 0x02, 
      0x04, 0x1c, 0xb0, 0xfb, 0xcb, 0x02, 0x01, 0x00, 
      0x02, 0x01, 0x00, 0x30, 0x29, 0x30, 0x0f, 0x06, 
      0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 
      0x00, 0x43, 0x03, 0x05, 0xca, 0x29, 0x30, 0x16, 
      0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 
      0x01, 0x04, 0x01, 0x00, 0x06, 0x08, 0x2b, 0x06, 
      0x01, 0x02, 0x01, 0x01, 0x03, 0x00
    };
    dataBlock *dummy;
    unsigned char outbuffer[1000];
    unsigned char temp[100];
    int oidNo;
    int x;
  
    oidNo = this->findOID(oid, len);
  
    dataBlock children[2];
  
    this->message.parseSNMP(trapTemplate);
  
    dummy = this->message.variableBindings;
    dummy = &(dummy->children[0]);
    dummy->printSelf();
    dummy->printContent();
  
    x = objects[oidNo].returnObject(temp);
    dummy->_length = x;
    dummy->_content = temp;
  
    Serial.println("kedikedikedi");
    dummy = this->message.variableBindings;
    dummy = &(dummy->children[1]);
    dummy->printSelf();
    dummy->printContent();
    dummy->children = children;
    dummy->parseChildren();
    Serial.println("yubiloo");
    dummy->printSelf();
    dummy->printContent();
  
    children[1]._content = (unsigned char*) objects[oidNo].oid;
    children[1]._length = objects[oidNo].oidLen;
    
    x = this->message.msgBody.createOutput(outbuffer);
  
    Udp.beginPacket(receiverIP, 162); // Trap address is here!!
    Udp.write(outbuffer,x);
    Udp.endPacket();
  
    Serial.println("");
    for (int x =0; x<200; x++)
    {
      Serial.print(outbuffer[x], HEX);
      Serial.print(" ");
    }
    Serial.println("");
    Serial.println("");
  }
}

/*
void oidContainer::returnContent(unsigned char* output)
{
  int x;
  output[0] = this->type;
  output[1] = this->_length;
  for (x=0;x<_length;x++)
  {
    output[x+2] = this->_string[x];
  }
}

int oidContainer::returnOID(unsigned char* output)
{
  int x;
  //output[0] = 0x30;
  //output[1] = this->oidLength + this->_length + 4;
  output[0] = 0x06;
  output[1] = this->oidLength;
  for (x=0; x<this->oidLength; x++)
  {
    output[x+2] = this->contentOID[x];
  }
  this->returnContent(output+2+this->oidLength);
  return this->oidLength + this->_length + 4; // 2 x 2 for headers.
}*/

