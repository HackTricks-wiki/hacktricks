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

### I/O Kit

I/O Kit is the open-source, object-oriented, device-driver framework in the XNU kernel and is responsible for the addition and management of dynamically loaded device drivers. These drivers allow for modular code to be added to the kernel dynamically for use with different hardware, for example. They are located in:

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

