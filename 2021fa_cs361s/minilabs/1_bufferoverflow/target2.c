#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/t2pipe"
static char *cmdbuf;

void badfmt(void)
{
  char buf[127];
  snprintf(buf, sizeof(buf), cmdbuf);
}

int main(void)
{
  cmdbuf = allocate_rwx();
  readcmd(PIPEPATH, cmdbuf, RWX_REGION_SIZE);
  badfmt();
  
  return 0;
}
