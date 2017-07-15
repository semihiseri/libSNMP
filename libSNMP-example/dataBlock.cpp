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

#include <Arduino.h>
#include "dataBlock.h"

unsigned int returnInt(unsigned char* input, int* len) // Returns integer out of long integer stuff
{
  int ret = 0;
  if ((*input)&(1<<7))
  {
    *len = 0;
    while((*input)&(1<<7))
    {
      ret *= 128;
      ret += (*input)&0b01111111;
      input++;
      (*len)++;
    }
  }
  else
  {
    *len = 1;
    ret = *input;
  }
  return ret;
}

void dataBlock::printSelf()
{
  Serial.print("Type ");
  switch(this->_type)
  {
    case INT:
      Serial.print("Integer");
      break;
    case OCTSTR:
      Serial.print("Octet Stream");
      break;
    case NUL:
      Serial.print("Null");
      break;
    case OID:
      Serial.print("Object Identifier");
      break;
    case SEQ:
      Serial.print("Sequence");
      break;
    case GET:
      Serial.print("Get Request");
      break;
    case REPORT:
      Serial.print("Report");
      break;
    case TRAP:
      Serial.print("Trap");
      break;
    default:
      Serial.print("Unknown: ");
      Serial.print(this->_type);
  }
  Serial.print(" of length ");
  Serial.print(this->_length);
  Serial.print(" and has ");
  Serial.print(this->childrenCount);
  Serial.println(" children");
}

void dataBlock::printTree()
{
  int x;
  this->printSelf();
  
  for (x=0;x<this->childrenCount;x++)
  {
    Serial.println("Children:");
    this->children[x].printTree();
  }
}

void dataBlock::printContent()
{
  int x;
  for (x=0;x<this->_length;x++)
  {
    Serial.print(this->_content[x], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

void dataBlock::parseSelf(unsigned char* input)
{
  int lenOfLen; // length of length. It can be somewhat long.

  this->childrenCount = 0;
  switch (*input)
  {
    case 0x02:
      this->_type = INT;
      break;
    case 0x04:
      this->_type = OCTSTR;
      break;
    case 0x05:
      this->_type = NUL;
      break;
    case 0x06:
      this->_type = OID;
      break;
    case 0x30:
      this->_type = SEQ;
      break;
    case 0x41:
      this->_type = CNTR;
      break;
    case 0x43:
      this->_type = TTICK;
      break;
    case 0xA0:
      this->_type = GET;
      break;
	case 0xA1:
	  this->_type = GETNEXT;
	  break;
    case 0xA3:
      this->_type = SETREQ;
      break;
    case 0xA7:
      this->_type = TRAP;
      break;
    default:
      Serial.print("An unknown case occured. Please report this to developer: ");
      Serial.println(*input, HEX);
      break;
  }
  this->_length = returnInt(input+1, &lenOfLen);
  this->_content = input+1+lenOfLen;
}

void dataBlock::parseChildren()
{
  unsigned char* temp;
  int totalLength;

  if (this->_length==0)
    return;

  for (totalLength=0;totalLength<(this->_length);)
  {
    temp = (this->_content)+totalLength;
    this->children[this->childrenCount].parseSelf(_content+totalLength);
    totalLength += 2;
    totalLength += this->children[this->childrenCount]._length;
    this->childrenCount++;
  }
}

int dataBlock::calculateLength()
{
  int x; //dummy variable
  int len;
  if (this->childrenCount == 0)
  {
    len = this->_length;
  }
  else
  {
    len = 0;
    for (x=0;x<this->childrenCount;x++)
    {
      len += this->children[x].calculateLength();
    }
  }
  return len+2;
}

int dataBlock::createOutput(unsigned char* output)
{
  int x; //dummy variable
  int pos;
  int totalLength;
  int offset;

  output[0] = this->_type;

  totalLength = this->calculateLength()-2; // calculates total length. This may be problematic

  if (totalLength>127)
  {
    offset = 3;
    output[1] = (totalLength/128) | (0b10000000);
    output[2] = (totalLength%128) | (0b10000000);
  }
  else
  {
    offset = 2;
    output[1] = totalLength;
  }

  pos = offset;

  if (this->childrenCount == 0)
  {
    for (x=0;x<this->_length;x++)
      output[x+pos] = this->_content[x];
  }
  else
  {
    this->_length = 0;
    for (x=0;x<this->childrenCount;x++)
    {
      this->_length += this->children[x].createOutput(output+pos);
      pos = this->_length + offset;
    }
  }

  return this->_length + offset;
}

