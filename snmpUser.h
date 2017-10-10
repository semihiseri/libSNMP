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

#ifndef SNMPUSER_H
#define SNMPUSER_H

typedef enum
{
  NOAUTH = 0,
  SHA    = 1,
  MD5    = 2
} authType;

typedef enum
{
  NOPRIV = 0,
  DES    = 1,
  AES    = 2
} privType;

class snmpUser
{
  public:
    char userName[20];
    authType auth;
    privType priv;
    char authKey[20];
    char privKey[20];
    // add access control here
    unsigned char permissions[MAX_OBJECTS];
};

#endif
