#include<string.h>
typedef unsigned int bool;
typedef char _BYTE ;
typedef char __int8 ;
char * sub_7B83C(char *a1, char *a2, int a3)
{
  bool v3; // zf
  unsigned char *v4; // r2
  _BYTE *v5; // r12
  int v6; // r4
  int v7; // t1
  unsigned int v8; // r6
  int v9; // r3
  bool v10; // cc
  bool v11; // zf
  bool v12; // zf
  bool v13; // zf
  bool v14; // zf
  bool v15; // zf
  bool v16; // zf
  bool v17; // zf
  bool v18; // zf
  bool v19; // zf

  v3 = a1 == 0;
  if ( a1 )
    v3 = a2 == 0;
  if ( v3 )
    return 0;
  v4 = &a1[a3];
  v5 = a2;
  while ( a1 < v4 )
  {
    v7 = *a1++;
    v6 = v7;
    v8 = (char)(v7 - 32);
    v9 = (char)v7;
    v10 = (unsigned int)(char)v7 > 0x26;
    if ( (char)v7 != 38 )
      v10 = v8 > 4;
    if ( !v10 )
      goto LABEL_44;
    v11 = v9 == 39;
    if ( v9 != 39 )
      v11 = v9 == 40;
    if ( v11 )
      goto LABEL_44;
    v12 = v9 == 41;
    if ( v9 != 41 )
      v12 = v9 == 42;
    if ( v12 )
      goto LABEL_44;
    v13 = v9 == 44;
    if ( v9 != 44 )
      v13 = v9 == 59;
    if ( v13 )
      goto LABEL_44;
    v14 = v9 == 60;
    if ( v9 != 60 )
      v14 = v9 == 62;
    if ( v14 )
      goto LABEL_44;
    v15 = v9 == 63;
    if ( v9 != 63 )
      v15 = v9 == 91;
    if ( v15 )
      goto LABEL_44;
    v16 = v9 == '\\';
    if ( v9 != '\\' )
      v16 = v9 == 93;
    if ( v16 )
      goto LABEL_44;
    v17 = v9 == 94;
    if ( v9 != 94 )
      v17 = v9 == 96;
    if ( v17 )
      goto LABEL_44;
    v18 = v9 == 123;
    if ( v9 != 123 )
      v18 = v9 == 124;
    if ( v18 )
      goto LABEL_44;
    v19 = v6 == 125;
    if ( v6 != 125 )
      v19 = v6 == 126;
    if ( v19 )
    {
LABEL_44:
      *v5 = '\\';
      v5[1] = v6;
      v5 += 2;
    }
    else
    {
      *v5++ = v6;
    }
  }
  *v5 = 0;
  return a2;
}
int main(){
  char v1[0x400]="cpegg";
  char s[0x400]={0};
  int v2=strlen(v1);
  sub_7B83C(v1,s,v2);
  return 0;
}
