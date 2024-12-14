# macOS Dyld Process

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

The real **entrypoint** of a Mach-o binary is the dynamic linked, defined in `LC_LOAD_DYLINKER` usually is `/usr/lib/dyld`.

This linker will need to locate all the executables libraries, map them in memory and link all the non-lazy libraries. Only after this process, the entry-point of the binary will be executed.

Of course, **`dyld`** doesn't have any dependencies (it uses syscalls and libSystem excerpts).

{% hint style="danger" %}
If this linker contains any vulnerability, as it's being executed before executing any binary (even highly privileged ones), it would be possible to **escalate privileges**.
{% endhint %}

### Flow

Dyld will be loaded by **`dyldboostrap::start`**, which will also load things such as the **stack canary**. This is because this function will receive in its **`apple`** argument vector this and other **sensitive** **values**.

**`dyls::_main()`** is the entry point of dyld and it's first task is to run `configureProcessRestrictions()`, which usually restricts **`DYLD_*`** environment variables explained in:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Then, it maps the dyld shared cache which prelinks all the important system libraries and then it maps the libraries the binary depends on and continues recursively until all the needed libraries are loaded. Therefore:

1. it start loading inserted libraries with `DYLD_INSERT_LIBRARIES` (if allowed)
2. Then the shared cached ones
3. Then the imported ones
   1. &#x20;Then continue importing libraries recursively

Once all are loaded the **initialisers** of these libraries are run. These are coded using **`__attribute__((constructor))`** defined in the `LC_ROUTINES[_64]` (now deprecated) or by pointer in a section flagged with `S_MOD_INIT_FUNC_POINTERS` (usually: **`__DATA.__MOD_INIT_FUNC`**).

Terminators are coded with **`__attribute__((destructor))`** and are located in a section flagged with `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

All binaries sin macOS are dynamically linked. Therefore, they contain some stubs sections that helps the binary to jump to the correct code in different machines and context. It's dyld when the binary is executed the brain that needs to resolve these addresses (at least the non-lazy ones).

Som stub sections in the binary:

* **`__TEXT.__[auth_]stubs`**: Pointers from `__DATA` sections
* **`__TEXT.__stub_helper`**: Small code invoking dynamic linking with info on the function to call
* **`__DATA.__[auth_]got`**: Global Offset Table (addresses to imported functions, when resolved, (bound during load time as it's marked with flag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers (bound during load time as it's marked with flag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers (bound on first access)

{% hint style="warning" %}
Note that the pointers with the prefix "auth\_" are using one in-process encryption key to protect it (PAC). Moreover, It's possible to use the arm64 instruction `BLRA[A/B]` to verify the pointer before following it. And the RETA\[A/B] can be used instead of a RET address.\
Actually, the code in **`__TEXT.__auth_stubs`** will use **`braa`** instead of **`bl`** to call the requested function to authenticate the pointer.

Also note that current dyld versions load **everything as non-lazy**.
{% endhint %}

### Finding lazy symbols

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Interesting disassembly part:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

It's possible to see that the jump to call printf is going to **`__TEXT.__stubs`**:

```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
  0 __text        00000038 0000000100003f60 TEXT
  1 __stubs       0000000c 0000000100003f98 TEXT
  2 __cstring     00000004 0000000100003fa4 DATA
  3 __unwind_info 00000058 0000000100003fa8 DATA
  4 __got         00000008 0000000100004000 DATA
```

In the disassemble of the **`__stubs`** section:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

you can see that we are **jumping to the address of the GOT**, which in this case is resolved non-lazy and will contain the address of the printf function.

In other situations instead of directly jumping to the GOT, it could jump to **`__DATA.__la_symbol_ptr`** which will load a value that represents the function that it's trying to load, then jump to **`__TEXT.__stub_helper`** which jumps the **`__DATA.__nl_symbol_ptr`** which contains the address of **`dyld_stub_binder`** which takes as parameters the number of the function and an address.\
This last function, after finding the address of the searched function writes it in the corresponding location in **`__TEXT.__stub_helper`** to avoid doing lookups in the future.

{% hint style="success" %}
However notice taht current dyld versions load everything as non-lazy.
{% endhint %}

#### Dyld opcodes

Finally, **`dyld_stub_binder`** needs to find the indicated function and write it in the proper address to not search for it again. To do so it uses opcodes (a finite state machine) within dyld.

## apple\[] argument vector

In macOS the main function receives actually 4 arguments instead of 3. The fourth is called apple and each entry is in the form `key=value`. For example:

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

Result:

```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```

{% hint style="success" %}
By the time these values reaches the main function, sensitive information has already been removed from them or it would have been a data leak.
{% endhint %}

it's possible to see all these interesting values debugging before getting into main with:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

This is a structure exported by dyld with information about the dyld state which can be found in the [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) with information like the version, pointer to dyld\_image\_info array, to dyld\_image\_notifier, if proc is detached from shared cache, if libSystem initializer was called, pointer to dyls's own Mach header, pointer to dyld version string...

## dyld env variables

### debug dyld

Interesting env variables that helps to understand what is dyld doing:

* **DYLD\_PRINT\_LIBRARIES**

Check each library that is loaded:

```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```

* **DYLD\_PRINT\_SEGMENTS**

Check how is each library loaded:

```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```

* **DYLD\_PRINT\_INITIALIZERS**

Print when each library initializer is running:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### Others

* `DYLD_BIND_AT_LAUNCH`: Lazy bindings are resolved with non lazy ones
* `DYLD_DISABLE_PREFETCH`: DIsable pre-fetching of \_\_DATA and \_\_LINKEDIT content
* `DYLD_FORCE_FLAT_NAMESPACE`: Single-level bindings
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Resolution paths
* `DYLD_INSERT_LIBRARIES`: Load an specifc library
* `DYLD_PRINT_TO_FILE`: Write dyld debug in a file
* `DYLD_PRINT_APIS`: Print libdyld API calls
* `DYLD_PRINT_APIS_APP`: Print libdyld API calls made by main
* `DYLD_PRINT_BINDINGS`: Print symbols when bound
* `DYLD_WEAK_BINDINGS`: Only print weak symbols when bound
* `DYLD_PRINT_CODE_SIGNATURES`: Print code signature registration operations
* `DYLD_PRINT_DOFS`: Print D-Trace object format sections as loaded
* `DYLD_PRINT_ENV`: Print env seen by dyld
* `DYLD_PRINT_INTERPOSTING`: Print interposting operations
* `DYLD_PRINT_LIBRARIES`: Print librearies loaded
* `DYLD_PRINT_OPTS`: Print load options
* `DYLD_REBASING`: Print symbol rebasing operations
* `DYLD_RPATHS`: Print expansions of @rpath
* `DYLD_PRINT_SEGMENTS`: Print mappings of Mach-O segments
* `DYLD_PRINT_STATISTICS`: Print timing statistics
* `DYLD_PRINT_STATISTICS_DETAILS`: Print detailed timing statistics
* `DYLD_PRINT_WARNINGS`: Print warning messages
* `DYLD_SHARED_CACHE_DIR`: Path to use for shared library cache
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Enable closures

It's possible to find more with someting like:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Or downloading the dyld project from [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) and running inside the folder:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```

## References

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>

