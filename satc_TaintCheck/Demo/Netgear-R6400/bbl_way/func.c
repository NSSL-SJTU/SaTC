#include<string.h>
#include <stdio.h>

void sanitizer(char* buf,char* out,int len){
  for (i=0, i<len, i++){
    if (buf[i] != '`' && buf[i] != '>' && buf[i] != ';' && buf[i] != '&'){
      out[i] = buf[i];
    }
    else{
      return 1;
    }
  }
  return 0;
}
int main(){
  char buf[0x20]={0};
  char out[0x20]={0};
  if(!sanitizer(buf,out,0x20)){
    sprintf(cmd,"echo %s",out);
    system(cmd);
  }
  return 0;
}
