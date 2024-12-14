# macOS Universal binaries & Mach-O Format

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

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

* Header
* Load Commands
* Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Fat Header

Search for the file with: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
	cpu_type_t	cputype;	/* cpu specifier (int) */
	cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
	uint32_t	offset;		/* file offset to this object file */
	uint32_t	size;		/* size of this object file */
	uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

The header has the **magic** bytes followed by the **number** of **archs** the file **contains** (`nfat_arch`) and each arch will have a `fat_arch` struct.

Check it with:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
    cpusubtype CPU_SUBTYPE_X86_64_ALL
    capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
    cpusubtype CPU_SUBTYPE_ARM64E
    capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

As you may be thinking usually a universal binary compiled for 2 architectures **doubles the size** of one compiled for just 1 arch.

## **Mach-O Header**

The header contains basic information about the file, such as magic bytes to identify it as a Mach-O file and information about the target architecture. You can find it in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file (usage and alignment for the file) */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
	uint32_t	magic;		/* mach magic number identifier */
	int32_t		cputype;	/* cpu specifier */
	int32_t		cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
	uint32_t	reserved;	/* reserved */
};
```

### Mach-O File Types

There are different file types, you can find them defined in the [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). The most important ones are:

* `MH_OBJECT`: Relocatable object file (intermediate products of compilation, not executables yet).
* `MH_EXECUTE`: Executable files.
* `MH_FVMLIB`: Fixed VM library file.
* `MH_CORE`: Code Dumps
* `MH_PRELOAD`: Preloaded executable file (no longer supported in XNU)
* `MH_DYLIB`: Dynamic Libraries
* `MH_DYLINKER`: Dynamic Linker
* `MH_BUNDLE`: "Plugin files". Generated using -bundle in gcc and explicitly loaded by `NSBundle` or `dlopen`.
* `MH_DYSM`: Companion `.dSym` file (file with symbols for debugging).
* `MH_KEXT_BUNDLE`: Kernel Extensions.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

The source code also defines several flags useful for loading libraries:

* `MH_NOUNDEFS`: No undefined references (fully linked)
* `MH_DYLDLINK`: Dyld linking
* `MH_PREBOUND`: Dynamic references prebound.
* `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
* `MH_WEAK_DEFINES`: Binary has weak defined symbols
* `MH_BINDS_TO_WEAK`: Binary uses weak symbols
* `MH_ALLOW_STACK_EXECUTION`: Make the stack executable
* `MH_NO_REEXPORTED_DYLIBS`: Library not LC\_REEXPORT commands
* `MH_PIE`: Position Independent Executable
* `MH_HAS_TLV_DESCRIPTORS`: There is a section with thread local variables
* `MH_NO_HEAP_EXECUTION`: No execution for heap/data pages
* `MH_HAS_OBJC`: Binary has oBject-C sections
* `MH_SIM_SUPPORT`: Simulator support
* `MH_DYLIB_IN_CACHE`: Used on dylibs/frameworks in shared library cache.

## **Mach-O Load commands**

The **file's layout in memory** is specified here, detailing the **symbol table's location**, the context of the main thread at execution start, and the required **shared libraries**. Instructions are provided to the dynamic loader **(dyld)** on the binary's loading process into memory.

The uses the **load\_command** structure, defined in the mentioned **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Basically, this type of Load Command define **how to load the \_\_TEXT** (executable code) **and \_\_DATA** (data for the process) **segments** according to the **offsets indicated in the Data section** when the binary is executed.
{% endhint %}

These commands **define segments** that are **mapped** into the **virtual memory space** of a process when it is executed.

There are **different types** of segments, such as the **\_\_TEXT** segment, which holds the executable code of a program, and the **\_\_DATA** segment, which contains data used by the process. These **segments are located in the data section** of the Mach-O file.

**Each segment** can be further **divided** into multiple **sections**. The **load command structure** contains **information** about **these sections** within the respective segment.

In the header first you find the **segment header**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* includes sizeof section_64 structs */
	char		segname[16];	/* segment name */
	uint64_t	vmaddr;		/* memory address of this segment */
	uint64_t	vmsize;		/* memory size of this segment */
	uint64_t	fileoff;	/* file offset of this segment */
	uint64_t	filesize;	/* amount to map from the file */
	int32_t		maxprot;	/* maximum VM protection */
	int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Example of segment header:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

This header defines the **number of sections whose headers appear after** it:

```c
struct section_64 { /* for 64-bit architectures */
	char		sectname[16];	/* name of this section */
	char		segname[16];	/* segment this section goes in */
	uint64_t	addr;		/* memory address of this section */
	uint64_t	size;		/* size in bytes of this section */
	uint32_t	offset;		/* file offset of this section */
	uint32_t	align;		/* section alignment (power of 2) */
	uint32_t	reloff;		/* file offset of relocation entries */
	uint32_t	nreloc;		/* number of relocation entries */
	uint32_t	flags;		/* flags (section type and attributes)*/
	uint32_t	reserved1;	/* reserved (for offset or index) */
	uint32_t	reserved2;	/* reserved (for count or sizeof) */
	uint32_t	reserved3;	/* reserved */
};
```

Example of **section header**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

If you **add** the **section offset** (0x37DC) + the **offset** where the **arch starts**, in this case `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

It's also possible to get **headers information** from the **command line** with:

```bash
otool -lv /bin/ls
```

Common segments loaded by this cmd:

* **`__PAGEZERO`:** It instructs the kernel to **map** the **address zero** so it **cannot be read from, written to, or executed**. The maxprot and minprot variables in the structure are set to zero to indicate there are **no read-write-execute rights on this page**.
  * This allocation is important to **mitigate NULL pointer dereference vulnerabilities**. This is because XNU enforces a hard page zero that ensures the first page (only the first) of memory is innaccesible (except in i386). A binary could fulfil this requirements by crafting a small \_\_PAGEZERO (using the `-pagezero_size`) to cover the first 4k and having the rest of 32bit memory accessible in both user and kernel mode.
* **`__TEXT`**: Contains **executable** **code** with **read** and **execute** permissions (no writable)**.** Common sections of this segment:
  * `__text`: Compiled binary code
  * `__const`: Constant data (read only)
  * `__[c/u/os_log]string`: C, Unicode or os logs string constants
  * `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
  * `__unwind_info`: Stack unwind data.
  * Note that all this content is signed but also marked as executable (creating more options for exploitation of sections that doesn't necessarily need this privilege, like string dedicated sections).
* **`__DATA`**: Contains data that is **readable** and **writable** (no executable)**.**
  * `__got:` Global Offset Table
  * `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
  * `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
  * `__const`: Should be read-only data (not really)
  * `__cfstring`: CoreFoundation strings
  * `__data`: Global variables (that have been initialized)
  * `__bss`: Static variables (that have not been initialized)
  * `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Information used by the Objective-C runtime
* **`__DATA_CONST`**: \_\_DATA.\_\_const is not guaranteed to be constant (write permissions), nor are other pointers and the GOT. This section makes `__const`, some initializers and the GOT table (once resolved) **read only** using `mprotect`.
* **`__LINKEDIT`**: Contains information for the linker (dyld) such as, symbol, string, and relocation table entries. It' a generic container for contents that are neither in `__TEXT` or `__DATA` and its content is decribed in other load commands.
  * dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
  * Functions starts: Table of start addresses of functions
  * Data In Code: Data islands in \_\_text
  * SYmbol Table: Symbols in binary
  * Indirect Symbol Table: Pointer/stub symbols
  * String Table
  * Code Signature
* **`__OBJC`**: Contains information used by the Objective-C runtime. Though this information might also be found in the \_\_DATA segment, within various in \_\_objc\_\* sections.
* **`__RESTRICT`**: A segment without content with a single section called **`__restrict`** (also empty) that ensures that when running the binary, it will ignore DYLD environmental variables.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

* `SG_HIGHVM`: Core only (not used)
* `SG_FVMLIB`: Not used
* `SG_NORELOC`: Segment has no relocation
* `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contains the entrypoint in the **entryoff attribute.** At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to start execution of the binary’s code.

**`LC_UNIXTHREAD`** contains the values the register must have when starting the main thread. This was already deprecated but **`dyld`** still uses it. It's possible to see the vlaues of the registers set by this with:

```bash
otool -l /usr/lib/dyld
[...]
Load command 13
        cmd LC_UNIXTHREAD
    cmdsize 288
     flavor ARM_THREAD_STATE64
      count ARM_THREAD_STATE64_COUNT
	    x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
	    x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
	    x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
	    x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
	    x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
	    x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
	    x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
	    x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
	    x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
	    x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
	     lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
	   cpsr 0x00000000

[...]
```

### **`LC_CODE_SIGNATURE`**

Contains information about the **code signature of the Macho-O file**. It only contains an **offset** that **points** to the **signature blob**. This is typically at the very end of the file.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Support for binary encryption. However, of course, if an attacker manages to compromise the process, he will be able to dump the memory unencrypted.

### **`LC_LOAD_DYLINKER`**

Contains the **path to the dynamic linker executable** that maps shared libraries into the process address space. The **value is always set to `/usr/lib/dyld`**. It’s important to note that in macOS, dylib mapping happens in **user mode**, not in kernel mode.

### **`LC_IDENT`**

Obsolete but when configured to geenrate dumps on panic, a Mach-O core dump is created and the kernel version is set in the `LC_IDENT` command.

### **`LC_UUID`**

Random UUID. It's useful for anything directly but XNU caches it with the rest of the process info. It can be used in crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Allows to indicate environment variables to the dyld beforenthe process is executed. This can be vary dangerous as it can allow to execute arbitrary code inside the process so this load command is only used in dyld build with `#define SUPPORT_LC_DYLD_ENVIRONMENT` and further restricts processing only to variables of the form `DYLD_..._PATH` specifying load paths.

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a `LC_LOAD_DYLIB` load command **for each library** that the Mach-O binary requires.

* This load command is a structure of type **`dylib_command`** (which contains a struct dylib, describing the actual dependent dynamic library):

```objectivec
struct dylib_command {
        uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
        uint32_t        cmdsize;        /* includes pathname string */
        struct dylib    dylib;          /* the library identification */ 
};

struct dylib {
    union lc_str  name;                 /* library's path name */
    uint32_t timestamp;                 /* library's build time stamp */
    uint32_t current_version;           /* library's current version number */
    uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```

![](<../../../.gitbook/assets/image (486).png>)

You could also get this info from the cli with:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Some potential malware related libraries are:

* **DiskArbitration**: Monitoring USB drives
* **AVFoundation:** Capture audio and video
* **CoreWLAN**: Wifi scans.

{% hint style="info" %}
A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC\_MAIN**.\
The offsets of any constructors are held in the **\_\_mod\_init\_func** section of the **\_\_DATA\_CONST** segment.
{% endhint %}

## **Mach-O Data**

At the core of the file lies the data region, which is composed of several segments as defined in the load-commands region. **A variety of data sections can be housed within each segment**, with each section **holding code or data** specific to a type.

{% hint style="success" %}
The data is basically the part containing all the **information** that is loaded by the load commands **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

This includes:

* **Function table:** Which holds information about the program functions.
* **Symbol table**: Which contains information about the external function used by the binary
* It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:

```bash
size -m /bin/ls
```

## Objetive-C Common Sections

In `__TEXT` segment (r-x):

* `__objc_classname`: Class names (strings)
* `__objc_methname`: Method names (strings)
* `__objc_methtype`: Method types (strings)

In `__DATA` segment (rw-):

* `__objc_classlist`: Pointers to all Objetive-C classes
* `__objc_nlclslist`: Pointers to Non-Lazy Objective-C classes
* `__objc_catlist`: Pointer to Categories
* `__objc_nlcatlist`: Pointer to Non-Lazy Categories
* `__objc_protolist`: Protocols list
* `__objc_const`: Constant data
* `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

* `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

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

