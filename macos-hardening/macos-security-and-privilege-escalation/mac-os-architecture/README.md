# macOS Architecture

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel

### XNU

The heart of Mac OS X is the **XNU kernel**. XNU is basically composed of a **Mach core** (covered in the next section) with supplementary features provided by Berkeley Software Distribution (**BSD**). Additionally, **XNU** is responsible for providing an **environment for kernel drivers called the I/O Kit**. **XNU is a Darwin package**, so all of the source **code** is **freely available**.

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

To get an idea of just how complicated the interaction between these two sets of code can be, consider the idea of the fundamental executing unit. **In BSD the fundamental unit is the process. In Mach it is a Mach thread**. The disparity is settled by each BSD-style process being associated with a Mach task consisting of exactly one Mach thread. When the BSD fork() system call is made, the BSD code in the kernel uses Mach calls to create a task and thread structure. Also, it is important to note that both the Mach and BSD layers have different security models. The **Mach security** model is **based** **on** **port** **rights**, and the **BSD** model is based on **process** **ownership**. Disparities between these two models have resulted in a **number of local privilege-escalation vulnerabilities**. Additionally, besides typical system cells, there are Mach traps that allow user-space programs to communicate with the kernel.

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

### IPC - Inter Process Communication

{% content-ref url="macos-ipc-inter-process-communication.md" %}
[macos-ipc-inter-process-communication.md](macos-ipc-inter-process-communication.md)
{% endcontent-ref %}

## Apple Propietary File System (APFS)

APFS, or Apple File System, is a modern file system developed by Apple Inc. that was designed to replace the older Hierarchical File System Plus (HFS+) with an emphasis on **improved performance, security, and efficiency**.

Some notable features of APFS include:

1. **Space Sharing**: APFS allows multiple volumes to **share the same underlying free storage** on a single physical device. This enables more efficient space utilization as the volumes can dynamically grow and shrink without the need for manual resizing or repartitioning.
   1. This means, compared with traditional partitions in file disks, t**hat in APFS different partitions (volumes) shares all the disk space**, while a regular partition usually had a fixed size.
2. **Snapshots**: APFS supports **creating snapshots**, which are **read-only**, point-in-time instances of the file system. Snapshots enable efficient backups and easy system rollbacks, as they consume minimal additional storage and can be quickly created or reverted.
3. **Clones**: APFS can **create file or directory clones that share the same storage** as the original until either the clone or the original file is modified. This feature provides an efficient way to create copies of files or directories without duplicating the storage space.
4. **Encryption**: APFS **natively supports full-disk encryption** as well as per-file and per-directory encryption, enhancing data security across different use cases.
5. **Crash Protection**: APFS uses a **copy-on-write metadata scheme that ensures file system consistency** even in cases of sudden power loss or system crashes, reducing the risk of data corruption.

Overall, APFS offers a more modern, flexible, and efficient file system for Apple devices, with a focus on improved performance, reliability, and security.

```bash
diskutil list # Get overview of the APFS volumes
```

## Applications

A kernel without applications isn’t very useful. **Darwin** is the non-Aqua, **open-source core of Mac OS X**. Basically it is all the parts of Mac OS X for which the **source code is available**. The code is made available in the form of a **package that is easy to install**. There are hundreds of **available Darwin packages**, such as X11, GCC, and other GNU tools. Darwin provides many of the applications you may already use in BSD or Linux for Mac OS X. Apple has spent significant time **integrating these packages into their operating system** so that everything behaves nicely and has a consistent look and feel when possible.

On the **other** hand, many familiar pieces of Mac OS X are **not open source**. The main missing piece to someone running just the Darwin code will be **Aqua**, the **Mac OS X windowing and graphical-interface environment**. Additionally, most of the common **high-level applications**, such as Safari, Mail, QuickTime, iChat, etc., are not open source (although some of their components are open source). Interestingly, these closed-source applications often **rely on open- source software**, for example, Safari relies on the WebKit project for HTML and JavaScript rendering. **For perhaps this reason, you also typically have many more symbols in these applications when debugging than you would in a Windows environment.**

### **Universal binaries &** Mach-o Format

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

### Bundles

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

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

* **Platypus**: Generate MacOS binary executing shell scripts, Python, Perl, Ruby, PHP, Swift, Expect, Tcl, AWK, JavaScript, AppleScript or any other user-specified interpreter.
  * **It saves the script in `Contents/Resources/script`. So finding this script is a good indicator that Platypus was used.**
* **PyInstaller:** Python
  * Ways to detect this is the use of the embedded string **“Py\_SetPythonHome”** or a a **call** into a function named **`pyi_main`.**
* **Electron:** JavaScript, HTML, and CSS.
  * These binaries will use **Electron Framework.framework**. Moreover, the non-binary components (e.g. JavaScript files) maybe found in the application’s **`Contents/Resources/`** directory, achieved in `.asar` files. These binaries will use Electron Framework.framework. Moreover, the non-binary components (e.g. JavaScript files) maybe found in the application’s **`Contents/Resources/`** directory, achieved in **`.asar` files**. It's possible **unpack** such archives via the **asar** node module, or the **npx** **utility:** `npx asar extract StrongBox.app/Contents/Resources/app.asar appUnpacked`\\

## References

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
