# Mac OS Architecture

## Kernel

### XNU

The heart of Mac OS X is the **XNU kernel**. XNU is basically composed of a **Mach core** \(covered in the next section\) with supplementary features provided by Berkeley Software Distribution \(**BSD**\). Additionally, **XNU** is responsible for providing an **environment for kernel drivers called the I/O Kit**. **XNU is a Darwin package**, so all of the source **code** is **freely available**.

From a security researcher’s perspective, **Mac OS X feels just like a FreeBSD box with a pretty windowing system** and a large number of custom applications. For the most part, applications written for BSD will compile and run without modification on Mac OS X. All the tools you are accustomed to using in BSD are available in Mac OS X. Nevertheless, the fact that the **XNU kernel contains all the Mach code** means that some day, when you have to dig deeper, you’ll find many differences that may cause you problems and some you may be able to leverage for your own purposes.

### Mach

Mach was originated as a UNIX-compatible **operating system** back in 1984. One of its primary design **goals** was to be a **microkernel**; that is, to **minimize** the amount of code running in the **kernel** and allow many typical kernel functions, such as file system, networking, and I/O, to **run as user-level** Mach tasks.

**In XNU, Mach is responsible for many of the low-level operations** you expect from a kernel, such as processor scheduling and multitasking and virtual- memory management.

### BSD

The **kernel** also involves a large chunk of **code derived from the FreeBSD** code base. This code runs as part of the kernel along with Mach and uses the same address space. The F**reeBSD code within XNU may differ significantly from the original FreeBSD code**, as changes had to be made for it to coexist with Mach. FreeBSD provides many of the remaining operations the kernel needs, including:

* Processes
* Signals
* Basic security, such as users and groups
* System call infrastructure
* TCP/IP stack and sockets
* Firewall and packet filtering

To get an idea of just how complicated the interaction between these two sets of code can be, consider the idea of the fundamental executing unit. **In BSD the fundamental unit is the process. In Mach it is a Mach thread**. The disparity is settled by each BSD-style process being associated with a Mach task consisting of exactly one Mach thread. When the BSD fork\(\) system call is made, the BSD code in the kernel uses Mach calls to create a task and thread structure. Also, it is important to note that both the Mach and BSD layers have different security models. The **Mach security** model is **based** **on** **port** **rights**, and the **BSD** model is based on **process** **ownership**. Disparities between these two models have resulted in a **number of local privilege-escalation vulnerabilities**. Additionally, besides typical system cells, there are Mach traps that allow user-space programs to communicate with the kernel.

### I/O Kit - Drivers

I/O Kit is the open-source, object-oriented, **device-driver framework** in the XNU kernel and is responsible for the addition and management of **dynamically loaded device drivers**. These drivers allow for modular code to be added to the kernel dynamically for use with different hardware, for example. They are located in:

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

On the **other** hand, many familiar pieces of Mac OS X are **not open source**. The main missing piece to someone running just the Darwin code will be **Aqua**, the **Mac OS X windowing and graphical-interface environment**. Additionally, most of the common **high-level applications**, such as Safari, Mail, QuickTime, iChat, etc., are not open source \(although some of their components are open source\). Interestingly, these closed-source applications often **rely on open- source software**, for example, Safari relies on the WebKit project for HTML and JavaScript rendering. **For perhaps this reason, you also typically have many more symbols in these applications when debugging than you would in a Windows environment.**

### **Universal binaries**

Mac OS binaries usually are compiled as universal binaries. ****A **universal binary** can **support multiple architectures in the same file**.

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

* **Header**

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

* **load-commands region**

This specifies the **layout of the file in memory**. It contains the **location of the symbol table**, the main thread context at the beginning of execution, and which shared libraries are required.

* **data region**

The heart of the file is the final region, the data, which consists of a number of segments as laid out in the load-commands region. **Each segment can contain a number of data sections**. Each of these sections **contains code or data** of one particular type.

![](../../.gitbook/assets/image%20%28507%29.png)

#### Get the info

```bash
otool -f /bin/ls #Get universal headers info
otool -h /bin/ls #get the Mach header
otool -l /bin/ls #Get Load commands
```

### Bundles

Basically, a bundle is a **directory structure** within the file system. Interestingly, by default this directory **looks like a single object in Finder**. The types of resources contained within a bundle may consist of applications, libraries, images, documentation, header files, etc. All these files are inside `<application>.app/Contents/`

```bash
ls -lR /Applications/Safari.app/Contents
```

* The **MacOS** **folder** contains the executable of the application
* The **Resources** **folder** contains the resources of the app \(icons, images...\)
* **Plist** **files** contains configuration information. You can find find information about the meaning of they plist keys in [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

## References

* \*\*\*\*[**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)\*\*\*\*

