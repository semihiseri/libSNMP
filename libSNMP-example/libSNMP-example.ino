/* This file is part of libSNMP.
 *
 * libSNMP is free software : you can redistribute it and / or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * libSNMP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Foobar.If not, see <http://www.gnu.org/licenses/>.
 */


static unsigned char illuminationOID[]     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x01}; // illumination
static unsigned char humidityOID[]         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x02}; // humidity
static unsigned char temperatureOID[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x03}; // temperature
static unsigned char temperatureUnitOID[]  = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x04}; // temperature unit
static unsigned char thermistorTempOID[]   = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x05}; // thermistor temperature
static unsigned char voltageOID[]          = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x06}; // voltage input
static unsigned char contactClosureOID[]   = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x07}; // contact closure input
static unsigned char floodSensorOID[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x08}; // flood sensor

static unsigned char trapReceiverIP1[]     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x02, 0x01, 0x01, 0x03, 0x00}; // trapReceiverIPAddress #1 (13)

#include "libSNMP.h"

#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>         // UDP library from: bjoern@cs.stanford.edu 12/30/2008



// Enter a MAC address and IP address for your controller below.
// The IP address will be dependent on your local network:
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};

float humid = 12.35;

snmpAgent kedi;

static unsigned char usmStatsUnsupportedSecLevels[] = { 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x01, 0x00 }; // These are here for demo. They don't have any other functions here
static unsigned char usmStatsNotInTimeWindows[] = { 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x02, 0x00 };
static unsigned char usmStatsUnknownUserNames[] = { 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x03, 0x00 };
static unsigned char usmStatsUnknownEngineIDs[] = { 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00 };
static unsigned char usmStatsWrongDigests[] = { 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x05, 0x00 };
static unsigned char usmStatsDecryptionErrors[] = { 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x06, 0x00 };

void setup() {
  Serial.begin(9600);
  
  delay(1000);

  Serial.print("Gathering IP vs.");
  Ethernet.begin(mac);

  IPAddress address = Ethernet.localIP();
  for (uint8_t i=0;i<4;i++) {
      Serial.print(address[i]);
      Serial.print(".");
  }
  Serial.println("");

  kedi.init();

  unsigned char randomEngineID[20]; // The snmpEngineID should have a length of 5-32. It can be anything.
  int hede = 1234567890;
  String(hede).toCharArray((char*) randomEngineID, 20);
  Serial.print("Engine id: ");
  for (int i = 0; i < 20; i++)
  {
	  randomEngineID[i] -= 48;
	  Serial.print(randomEngineID[i], HEX);
	  Serial.print(" ");
  }
  Serial.println("done");
  kedi.setEngineID(randomEngineID, String(hede).length()); // This function is to set engineID.

  /*
   * This should be set before users are set. Or, users should be added once again after this function is called.
   * This is because key generation uses snmpEngineID. as engineID changes, authKeys has to change as well.
   * kedi.setEngineID(unsigned char* newEngineID, int engineIDLength);
   */

  //kedi.addUser("kedi", NOAUTH, NOPRIV, NULL, NULL); // Add an user named kedi and with noAuthNoPriv security level
  kedi.addUser("kedi", (authType) 0, (privType) 0, NULL, NULL);
  kedi.addUser("hede", SHA, DES, "kedikedi", "kedikedi"); // Add an user named hede with authPriv security level -both authPass and privPass are kedikedi
  kedi.addUser("hebe", SHA, NOPRIV, "hedebelelele", NULL); // Add an user named hede with authNoPriv security level -auth pass is hedebele

  strcpy(kedi.communityString, "kedikedi"); // This is a simple way to set a community string :)

  kedi.addObject(humidityOID, 10, FLOAT, &humid);
  //kedi.addObject(trapReceiverIP1, 13, OCTSTRING, trapip);

  /* A Note on the following lines
   *  kedi.addPermission(oidName, oidLength, userName, userNameLength, authLevel);
   *  
   *  where authLevel is one of the following
   *  0: no access
   *  1: access always
   *  2: access only when authenticated
   *  3: access only when authenticated and private (privacy implies authentication already)
   */
  
  kedi.addPermission(sysUpTime, 8, (unsigned char*) "hede", 4, 3);
  kedi.addPermission(sysUpTime, 8, (unsigned char*) "hede", 4, 3);
  kedi.addPermission(usmStatsUnsupportedSecLevels, 10, (unsigned char*) "hede", 4, 3); // These better be hidden. I included them for demoing
  kedi.addPermission(usmStatsNotInTimeWindows, 10, (unsigned char*) "hede", 4, 3);
  kedi.addPermission(usmStatsUnknownUserNames, 10, (unsigned char*) "hede", 4, 3);
  kedi.addPermission(usmStatsUnknownEngineIDs, 10, (unsigned char*) "hede", 4, 3);
  kedi.addPermission(usmStatsWrongDigests, 10, (unsigned char*) "hede", 4, 3);
  kedi.addPermission(usmStatsDecryptionErrors, 10, (unsigned char*) "hede", 4, 3);

  kedi.addPermission(sysUpTime, 8, (unsigned char*) "kedi", 4, 1);
  kedi.addPermission(usmStatsUnsupportedSecLevels, 10, (unsigned char*) "kedi", 4, 1); // These better be hidden. I included them for demoing
  kedi.addPermission(usmStatsNotInTimeWindows, 10, (unsigned char*) "kedi", 4, 1);
  kedi.addPermission(usmStatsUnknownUserNames, 10, (unsigned char*) "kedi", 4, 1);
  //kedi.addPermission(usmStatsUnknownEngineIDs, 10, (unsigned char*) "kedi", 4, 1);
  //kedi.addPermission(usmStatsWrongDigests, 10, (unsigned char*) "kedi", 4, 1);
  kedi.addPermission(usmStatsDecryptionErrors, 10, (unsigned char*) "kedi", 4, 1);

}



void loop()
{
  /*
   * How to demo:
   * If you send 2 via arduino serial monitor, it switches to v2c
   * If you send 3 via arduino serial monitor, it switches to v3
   * If you send t via arduino serial monitor, it will send a trap to trapip containing sysUpTime.
   */
   
  int x;
  
  kedi.update(); // This is a mandatory function, and it has to be called frequently -frequency depends on the timeout of snmp manager
  //Serial.println(kedi.localUpTime);

  if (Serial.available())
  {
    x = Serial.read();
    if (x=='2')
    {
      kedi.setVersion(2); // Switch to version 2c. Due to current bug, it will hang if it receives a v3 message (may not hang as well, it is luck)
      Serial.println("Version:2");
    }
    else if (x=='3')
    {  
      kedi.setVersion(3); // Switch to version 3. Due to current bug, it will hang if it receives a v2c message (this will definitely hang)
      Serial.println("Version:3");
    }
    else if (x == 't')
    {
      char trapip[16] = "192.168.1.103"; // This is the ip address of the trap receiver
      
      Serial.println("Trap time!!");
      delay(100);
      kedi.sendTrapv3(trapip, sysUpTime, 8, "kedi", NOAUTH, NOPRIV);
      kedi.sendTrapv2c(trapip, sysUpTime, 8, "public");
      /*
       * An explanation about trap functions
       * When the version is set to v2c, sendTrapv3 will simply print a message and return.
       * When the version is set to v3, sendTrapv2c will simply print a message and return.
       * 
       * So, it is possible to have these two functions this way and ignore the messages. It will always work no matter what is the version :)
       * If you want to send a v3 trap and v2c trap at the same time, you can do the following. It is safe.
       * kedi.setVersion(3);
       * kedi.sendTrapv3(...);
       * kedi.setVersion(2);
       * kedi.sendTrapv2c(...);
       * 
       * kedi.sendtrapv3(receiverIP, oid, oidLength, userName, authSetting, privSetting);
       * kedi.sendtrapv2c(receiverIP, oid, oidLength, communityString);
       * Where;
       * - receiverIP is a char array holding the IP address of the receiver
       * - oid is the unsigned char array that holds the oid values. For example
       *   static unsigned char floodSensorOID[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xb9, 0x26, 0x03, 0x08};
       *   is a oid. It has length of 10.
       * - oidLength is the length of the oid to be sent. For floodSensorOID, it is 10 because array has 10 elements in it.
       * - userName should be one of the users that you have added. Permissions don't matter here. So, a user can send any oid.
       * - authSetting can be one of the following: NOAUTH, SHA, MD5. Note that, this feature is not implemented yet
       * - privSetting can be one of the following: NOPRIV, DES, AES. Note that, this feature is not implemented yet
       * - communityString can be any string.
       */
       
      Serial.println("A trap is sent");
      kedi.localUpTime += 100; // Just to end the loop

      Serial.println(trapip);
    }
  }
  
  delay(100);
}
