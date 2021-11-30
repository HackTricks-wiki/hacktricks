# Mac OS Architecture

## Kernel

### XNU

The heart of Mac OS X is the **XNU kernel**. XNU is basically composed of a **Mach core** (covered in the next section) with supplementary features provided by Berkeley Software Distribution (**BSD**). Additionally, **XNU** is responsible for providing an **environment for kernel drivers called the I/O Kit**. **XNU is a Darwin package**, so all of the source **code** is **freely available**.

From a security researcher’s perspective, **Mac OS X feels just like a FreeBSD box with a pretty windowing system** and a large number of custom applications. For the most part, applications written for BSD will compile and run without modification on Mac OS X. All the tools you are accustomed to using in BSD are available in Mac OS X. Nevertheless, the fact that the **XNU kernel contains all the Mach code** means that some day, when you have to dig deeper, you’ll find many differences that may cause you problems and some you may be able to leverage for your own purposes.

### Mach

Mach was originated as a UNIX-compatible** operating system **back in 1984. One of its primary design **goals** was to be a **microkernel**; that is, to **minimize** the amount of code running in the **kernel** and allow many typical kernel functions, such as file system, networking, and I/O, to **run as user-level** Mach tasks.

**In XNU, Mach is responsible for many of the low-level operations** you expect from a kernel, such as processor scheduling and multitasking and virtual- memory management.

### BSD

The **kernel** also involves a large chunk of **code derived from the FreeBSD** code base. This code runs as part of the kernel along with Mach and uses the same address space. The F**reeBSD code within XNU may differ significantly from the original FreeBSD code**, as changes had to be made for it to coexist with Mach. FreeBSD provides many of the remaining operations the kernel needs, including:

* Processes
* Signals
* Basic security, such as users and groups
* System call infrastructure
* TCP/IP stack and sockets
* Firewall and packet filtering

To get an idea of just how complicated the interaction between these two sets of code can be, consider the idea of the fundamental executing unit. **In BSD the fundamental unit is the process. In Mach it is a Mach thread**. The disparity is settled by each BSD-style process being associated with a Mach task consisting of exactly one Mach thread. When the BSD fork() system call is made, the BSD code in the kernel uses Mach calls to create a task and thread structure. Also, it is important to note that both the Mach and BSD layers have different security models. The **Mach security** model is **based** **on** **port** **rights**, and the **BSD** model is based on **process** **ownership**. Disparities between these two models have resulted in a **number of local privilege-escalation vulnerabilities**. Additionally, besides typical system cells, there are Mach traps that allow user-space programs to communicate with the kernel.

### I/O Kit - Drivers

I/O Kit is the open-source, object-oriented, **device-driver framework **in the XNU kernel and is responsible for the addition and management of **dynamically loaded device drivers**. These drivers allow for modular code to be added to the kernel dynamically for use with different hardware, for example. They are located in:

* `/System/Library/Extensions`
  * KEXT files built into the OS X operating system.
* `/Library/Extensions`
  * KEXT files installed by 3rd party software

```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
   10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```

Until the number 9 the listed drivers are **loaded in the address 0**. This means that those aren't real drivers but **part of the kernel and they cannot be unloaded**.

In order to find specific extensions you can use:

```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```

To load and unload kernel extensions do:

```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```

## Applications

A kernel without applications isn’t very useful. **Darwin** is the non-Aqua, **open-source core of Mac OS X**. Basically it is all the parts of Mac OS X for which the **source code is available**. The code is made available in the form of a **package that is easy to install**. There are hundreds of **available Darwin packages**, such as X11, GCC, and other GNU tools. Darwin provides many of the applications you may already use in BSD or Linux for Mac OS X. Apple has spent significant time **integrating these packages into their operating system** so that everything behaves nicely and has a consistent look and feel when possible.

On the **other** hand, many familiar pieces of Mac OS X are **not open source**. The main missing piece to someone running just the Darwin code will be **Aqua**, the **Mac OS X windowing and graphical-interface environment**. Additionally, most of the common **high-level applications**, such as Safari, Mail, QuickTime, iChat, etc., are not open source (although some of their components are open source). Interestingly, these closed-source applications often **rely on open- source software**, for example, Safari relies on the WebKit project for HTML and JavaScript rendering. **For perhaps this reason, you also typically have many more symbols in these applications when debugging than you would in a Windows environment.**

### **Universal binaries**

Mac OS binaries usually are compiled as universal binaries.** **A **universal binary** can **support multiple architectures in the same file**.

```bash
file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e
```

In the following example, a universal binary for the **x86** **and** **PowerPC** architectures is created:

```bash
gcc -arch ppc -arch i386 -o test-universal test.c
```

As you may be thinking usually a universal binary compiled for 2 architectures **doubles the size** of one compiled for just 1 arch.

### Mach-o Format

![](<../../.gitbook/assets/image (559).png>)

#### **Header**

The header contains basic information about the file, such as magic bytes to identify it as a Mach-O file and information about the target architecture. You can find it in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

```c
struct mach_header {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file (usage and alignment for the file) */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
};
```

Filetypes:

* MH\_EXECUTE (0x2): Standard Mach-O executable            &#x20;
* MH\_DYLIB (0x6): A Mach-O dynamic linked library (i.e. .dylib)
* MH\_BUNDLE (0x8): A Mach-O bundle (i.e. .bundle)

#### ****

#### **Load commands**

This specifies the **layout of the file in memory**. It contains the **location of the symbol table**, the main thread context at the beginning of execution, and which **shared libraries** are required.\
The commands basically instruct the dynamic loader **(dyld) how to load the binary in memory.**

Load commands all begin with a **load\_command** structure, defined in mach-o/loader.h:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

A **common** type of load command is **LC\_SEGMENT/LC\_SEGMENT\_64**, which **describes** a **segment:** \
_A segment defines a **range of bytes **in a Mach-O file and the **addresses** and **memory** **protection** **attributes** at which those bytes are **mapped into **virtual memory when the dynamic linker loads the application._

![](<../../.gitbook/assets/image (557).png>)

Common segments:

* **`__TEXT`**: Contains **executable** **code** and **data** that is **read-only. **Common sections of this segment:
  * `__text`:** **Compiled binary code
  * `__const`: Constant data
  * `__cstring`: String constants
* **`__DATA`**: Contains data that is **writable.**
  * `__data`: Global variables (that have been initialized)
  * `__bss`: Static variables (that have not been initialized)
  * `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Information used by the Objective-C runtime&#x20;
* **`__LINKEDIT`**: Contains information for the linker (dyld) such as, "symbol, string, and relocation table entries."
* **`__OBJC`**: Contains information used by the Objective-C runtime. Though this information might also be found in the \_\_DATA segment, within various in \_\_objc\_\* sections.
* **`LC_MAIN`**: Contains the entrypoint in the **entryoff attribute. **At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to kickoff execution of the binary’s code.
*   **`LC_LOAD_DYLIB`**:** **This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to l**oad and link said library**. There is a LC\_LOAD\_DYLIB load command **for each library **that the Mach-O binary requires.

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

![](<../../.gitbook/assets/image (558).png>)

Some potential malware related libraries are:

* **DiskArbitration**: Monitoring USB drives
* **AVFoundation:** Capture audio and video
* **CoreWLAN**: Wifi scans.

{% hint style="info" %}
A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC\_MAIN**. \
The offsets of any constructors are held in the **\_\_mod\_init\_func** section of the **\_\_DATA\_CONST** segment.
{% endhint %}

#### ****

#### **Data**

The heart of the file is the final region, the data, which consists of a number of segments as laid out in the load-commands region. **Each segment can contain a number of data sections**. Each of these sections **contains code or data** of one particular type.

![](<../../.gitbook/assets/image (555).png>)

#### Get the info

```bash
otool -f /bin/ls #Get universal headers info
otool -hv /bin/ls #Get the Mach header
otool -l /bin/ls #Get Load commands
otool -L /bin/ls #Get libraries used by the binary
```

Or you can use the GUI tool [**machoview**](https://sourceforge.net/projects/machoview/).

### Bundles

Basically, a bundle is a **directory structure** within the file system. Interestingly, by default this directory **looks like a single object in Finder**. The types of resources contained within a bundle may consist of applications, libraries, images, documentation, header files, etc. All these files are inside `<application>.app/Contents/`

```bash
ls -lR /Applications/Safari.app/Contents
```

*   `Contents/_CodeSignature`

    Contains **code-signing information** about the application (i.e., hashes, etc.).
*   `Contents/MacOS`

    Contains the **application’s binary** (which is executed when the user double-clicks the application icon in the UI).&#x20;
*   `Contents/Resources`

    Contains **UI elements of the application**, such as images, documents, and nib/xib files (that describe various user interfaces).&#x20;
* `Contents/Info.plist`\
  ****The application’s main “**configuration file.**” Apple notes that “the system relies on the presence of this file to identify relevant information about \[the] application and any related files”.
  * **Plist** **files** contains configuration information. You can find find information about the meaning of they plist keys in [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
  *   Pairs that may be of interest when analyzing an application include:\


      * **CFBundleExecutable**

      Contains the **name of the application’s binary** (found in Contents/MacOS).

      * **CFBundleIdentifier**

      Contains the application’s bundle identifier (often used by the system to **globally** **identify** the application).

      * **LSMinimumSystemVersion**

      Contains the **oldest** **version** of **macOS** that the application is compatible with.

### Objective-C

Programs written in Objective-C **retain** their class declarations **when** **compiled** into (Mach-O) binaries. Such class declarations **include** the name and type of:

* The class
* The class methods
* The class instance variables

You can get this information using [**class-dump**](https://github.com/nygard/class-dump):

```bash
class-dump Kindle.app
```

Note that this names can be obfuscated to make the reversing of the binary more difficult.

### Native Packages

There are some projects that allow to generate a binary executable by MacOS containing script code which will be executed. Some examples are:

* **Platypus**: Generate MacOS binary executing** **shell scripts, Python, Perl, Ruby, PHP, Swift, Expect, Tcl, AWK, JavaScript, AppleScript or any other user-specified interpreter.
  * **It saves the script in `Contents/Resources/script`. So finding this script is a good indicator that Platypus was used.**
* **PyInstaller: **Python
  * Ways to detect this is the use of the embedded** **string** “Py\_SetPythonHome” **or a a **call** into a function named **`pyi_main`.**
* **Electron: **JavaScript, HTML, and CSS.
  * These binaries will use **Electron Framework.framework**. Moreover, the non-binary components (e.g. JavaScript files) maybe found in the application’s **`Contents/Resources/`** directory, achieved in `.asar` files. These binaries will use Electron Framework.framework. Moreover, the non-binary components (e.g. JavaScript files) maybe found in the application’s **`Contents/Resources/`** directory, achieved in **`.asar` files**. It's possible **unpack** such archives via the **asar** node module, or the **npx** **utility: **`npx asar extract StrongBox.app/Contents/Resources/app.asar appUnpacked`\


## References

* ****[**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)****
* ****[**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)****
