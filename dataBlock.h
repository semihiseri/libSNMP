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

#ifndef DATABLOCK_H
#define DATABLOCK_H

typedef enum
{
	INT     = 0x02,
	OCTSTR  = 0x04,
	NUL     = 0x05,
	OID     = 0x06,
	SEQ     = 0x30,
	CNTR    = 0x41,
	TTICK   = 0x43,
	GET     = 0xA0,
	GETNEXT = 0xA1,
	GETRES  = 0xA2,
	SETREQ  = 0xA3,
	TRAP    = 0xA7,
	REPORT  = 0xA8
} contentType;

class dataBlock
{
  public:
    void parseSelf(unsigned char* input); // Parses the give input buffer into self.
    void parseChildren(); // Parses self content into children if applicable -can be done on octetstrings and sequences and pdu's and many more.
    void printSelf(); // Prints self; type; length and children count. Children count is 0 by default. Can be modified by parseChildren
    void printContent(); // prints content in HEX.
    void printTree(); // Prints self, then calls children's printTree.
    int createOutput(unsigned char* input);
    int calculateLength();
  //private:
    contentType _type;
    unsigned char* _content;
    int _length;
    dataBlock *children;
    int childrenCount = 0;
};

unsigned int returnInt(unsigned char* input, int* len); // Returns integer out of long integer stuff

#endif
