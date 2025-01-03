# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

The **core of macOS is XNU**, which stands for "X is Not Unix". This kernel is fundamentally composed of the **Mach microkerne**l (to be discussed later), **and** elements from Berkeley Software Distribution (**BSD**). XNU also provides a platform for **kernel drivers via a system called the I/O Kit**. The XNU kernel is part of the Darwin open source project, which means **its source code is freely accessible**.

From a perspective of a security researcher or a Unix developer, **macOS** can feel quite **similar** to a **FreeBSD** system with an elegant GUI and a host of custom applications. Most applications developed for BSD will compile and run on macOS without needing modifications, as the command-line tools familiar to Unix users are all present in macOS. However, because the XNU kernel incorporates Mach, there are some significant differences between a traditional Unix-like system and macOS, and these differences might cause potential issues or provide unique advantages.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is a **microkernel** designed to be **UNIX-compatible**. One of its key design principles was to **minimize** the amount of **code** running in the **kernel** space and instead allow many typical kernel functions, such as file system, networking, and I/O, to **run as user-level tasks**.

In XNU, Mach is **responsible for many of the critical low-level operations** a kernel typically handles, such as processor scheduling, multitasking, and virtual memory management.

### BSD

The XNU **kernel** also **incorporates** a significant amount of code derived from the **FreeBSD** project. This code **runs as part of the kernel along with Mach**, in the same address space. However, the FreeBSD code within XNU may differ substantially from the original FreeBSD code because modifications were required to ensure its compatibility with Mach. FreeBSD contributes to many kernel operations including:

- Process management
- Signal handling
- Basic security mechanisms, including user and group management
- System call infrastructure
- TCP/IP stack and sockets
- Firewall and packet filtering

Understanding the interaction between BSD and Mach can be complex, due to their different conceptual frameworks. For instance, BSD uses processes as its fundamental executing unit, while Mach operates based on threads. This discrepancy is reconciled in XNU by **associating each BSD process with a Mach task** that contains exactly one Mach thread. When BSD's fork() system call is used, the BSD code within the kernel uses Mach functions to create a task and a thread structure.

Moreover, **Mach and BSD each maintain different security models**: **Mach's** security model is based on **port rights**, whereas BSD's security model operates based on **process ownership**. Disparities between these two models have occasionally resulted in local privilege-escalation vulnerabilities. Apart from typical system calls, there are also **Mach traps that allow user-space programs to interact with the kernel**. These different elements together form the multifaceted, hybrid architecture of the macOS kernel.

### I/O Kit - Drivers

The I/O Kit is an open-source, object-oriented **device-driver framework** in the XNU kernel, handles **dynamically loaded device drivers**. It allows modular code to be added to the kernel on-the-fly, supporting diverse hardware.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS is **super restrictive to load Kernel Extensions** (.kext) because of the high privileges that code will run with. Actually, by default is virtually impossible (unless a bypass is found).

In the following page you can also see how to recover the `.kext` that macOS loads inside its **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Instead of using Kernel Extensions macOS created the System Extensions, which offers in user level APIs to interact with the kernel. This way, developers can avoid to use kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}



