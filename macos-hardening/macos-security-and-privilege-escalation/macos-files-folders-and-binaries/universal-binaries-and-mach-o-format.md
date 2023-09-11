# macOS Universal binaries & Mach-O Format

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

* Header
* Load Commands
* Data

![](<../../../.gitbook/assets/image (559).png>)

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

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

As you may be thinking usually a universal binary compiled for 2 architectures **doubles the size** of one compiled for just 1 arch.

## **Mach-O  Header**

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

**Filetypes**:

* MH\_EXECUTE (0x2): Standard Mach-O executable
* MH\_DYLIB (0x6): A Mach-O dynamic linked library (i.e. .dylib)
* MH\_BUNDLE (0x8): A Mach-O bundle (i.e. .bundle)

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O  Load commands**

This specifies the **layout of the file in memory**. It contains the **location of the symbol table**, the main thread context at the beginning of execution, and which **shared libraries** are required.\
The commands basically instruct the dynamic loader **(dyld) how to load the binary in memory.**

Load commands all begin with a **load\_command** structure, defined in the previously mentioned **`loader.h`**:

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

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

If you **add** the **section offset** (0x37DC) + the **offset** where the **arch starts**, in this case `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

It's also possible to get **headers information** from the **command line** with:

```bash
otool -lv /bin/ls
```

Common segments loaded by this cmd:

* **`__PAGEZERO`:** It instructs the kernel to **map** the **address zero** so it **cannot be read from, written to, or executed**. The maxprot and minprot variables in the structure are set to zero to indicate there are **no read-write-execute rights on this page**.&#x20;
  * This allocation is important to **mitigate NULL pointer dereference vulnerabilities**.
* **`__TEXT`**: Contains **executable** **code** with **read** and **execute** permissions (no writable)**.** Common sections of this segment:
  * `__text`: Compiled binary code
  * `__const`: Constant data
  * `__cstring`: String constants
  * `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
* **`__DATA`**: Contains data that is **readable** and **writable** (no executable)**.**
  * `__data`: Global variables (that have been initialized)
  * `__bss`: Static variables (that have not been initialized)
  * `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Information used by the Objective-C runtime
* **`__LINKEDIT`**: Contains information for the linker (dyld) such as, "symbol, string, and relocation table entries."
* **`__OBJC`**: Contains information used by the Objective-C runtime. Though this information might also be found in the \_\_DATA segment, within various in \_\_objc\_\* sections.

### **`LC_MAIN`**

Contains the entrypoint in the **entryoff attribute.** At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to start execution of the binary’s code.

### **LC\_CODE\_SIGNATURE**

Contains information about the **code signature of the Macho-O file**. It only contains an **offset** that **points** to the **signature blob**. This is typically at the very end of the file.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Contains the **path to the dynamic linker executable** that maps shared libraries into the process address space. The **value is always set to `/usr/lib/dyld`**. It’s important to note that in macOS, dylib mapping happens in **user mode**, not in kernel mode.

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a LC\_LOAD\_DYLIB load command **for each library** that the Mach-O binary requires.

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

![](<../../../.gitbook/assets/image (558).png>)

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

The heart of the file is the final region, the data, which consists of a number of segments as laid out in the load-commands region. **Each segment can contain a number of data sections**. Each of these sections **contains code or data** of one particular type.

{% hint style="success" %}
The data is basically the part containing all the **information** that is loaded by the load commands **LC\_SEGMENTS\_64**
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

This includes:&#x20;

* **Function table:** Which holds information about the program functions.
* **Symbol table**: Which contains information about the external function used by the binary
* It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Or from the cli:

```bash
size -m /bin/ls
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
