#include "snmpObject.h"
#include <string.h>

int snmpObject::returnObject(unsigned char* output)
{
  int x;
  int base;
  
  output[0] = 0x06; //OID;
  output[1] = this->oidLen;
  for(x=0;x<this->oidLen;x++)
  {
    output[x+2] = this->oid[x];
  }

  base = this->oidLen + 2;

  switch (this->type)
  {
    case FLOAT:
      output[base] = INTEGER; // we are expressing floats as integer. It can be expressed as REAL as well but it needs some work.
      break;
    default:
      output[base] = this->type;
      break;
  }

  switch (this->type)
  {
    case STRING:
      output[base+1] = strlen((char*) content);
      break;
    default:
      output[base+1] = 4; // we can express almost anything with 32-bit integers :)
      break;
  }

  switch (this->type) // String and float may require different handling
  {
    case STRING:
      for(x=0; x<strlen((char*) content); x++)
      {
        output[base + 2 + x] = ((char*) content)[x];
      }
      return base + strlen((char*) content) + 1;
      break;
    case FLOAT:
      output[base + 2] = (int)( *((float*) this->content)*100)/16777216; // README: I don't know how does the optimization happens here. But we can use >>24 as well.
      output[base + 3] = ((int)( *((float*) this->content)*100)/65536)%256; // similarly, >>16
      output[base + 4] = ((int)( *((float*) this->content)*100)/256)%256; // >>8
      output[base + 5] = (int)( *((float*) this->content)*100)%256;
      return base+6;
      break;
    case INTEGER:
    case TICK:
    case COUNTER: // These are actually integers
      output[base + 2] = *((int*) this->content)/16777216; // README: I don't know how does the optimization happens here. But we can use >>24 as well.
      output[base + 3] = (*((int*) this->content)/65536)%256; // similarly, >>16
      output[base + 4] = (*((int*) this->content)/256)%256; // >>8
      output[base + 5] = *((int*) this->content)%256;
      return base+6;
      break;
  }
  
}

