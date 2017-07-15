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

#ifndef SNMPOBJECT_H
#define SNMPOBJECT_H

typedef enum
{
        INTEGER     = 0x02,
        STRING  = 0x13, // printable string, to be exact
        OCTSTRING= 0x04,
//        OID     = 0x06,
        COUNTER = 0x41,
        TICK    = 0x43,
        FLOAT   = 0x09, // real
} objectType;

class snmpObject
{
  public:
    int returnObject(unsigned char* output);

    unsigned char* oid;
    int oidLen;
    objectType type;
    void* content;
};

#endif
