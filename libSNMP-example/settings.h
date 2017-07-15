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

#ifndef SETTINGS_H
#define SETTINGS_H

#define MAX_OBJECTS 40 // Note: We already have 6 error objects, 1 time object. The rest 33 are available to the user!
#define MAX_USERS 10

#define MAX_COMMUNITY_STRING 20 // maximum community string length.

#define SNMPV_DEFAULT 3; // v1 not supported, v2c -> 2, v3 -> 3

//#define SNMP_V2C // Comment this out for V3

#endif
