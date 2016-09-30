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
