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
