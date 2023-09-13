# macOS Apps - Inspecting, debugging and Fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Static Analysis

### otool

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}

### jtool2

The tool can be used as a **replacement** for **codesign**, **otool**, and **objdump**, and provides a few additional features. [**Download it here**](http://www.newosxbook.com/tools/jtool.html) or install it with `brew`.

```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator
```

### Codesign

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) is a tool useful to inspect **.pkg** files (installers) and see what is inside before installing it.\
These installers have `preinstall` and `postinstall` bash scripts that malware authors usually abuse to **persist** **the** **malware**.

### hdiutil

This tool allows to **mount** Apple disk images (**.dmg**) files to inspect them before running anything:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

It will be mounted in `/Volumes`

### Objective-C

#### Metadata

{% hint style="danger" %}
Note that programs written in Objective-C **retain** their class declarations **when** **compiled** into [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Such class declarations **include** the name and type of:
{% endhint %}

* The class
* The class methods
* The class instance variables

You can get this information using [**class-dump**](https://github.com/nygard/class-dump):

```bash
class-dump Kindle.app
```

Note that this names could be obfuscated to make the reversing of the binary more difficult.

#### Function calling

When a function is called in a binary that uses objective-C, the compiled code instead of calling that function, it will call **`objc_msgSend`**. Which will be calling the final function:

![](<../../../.gitbook/assets/image (560).png>)

The params this function expects are:

* The first parameter (**self**) is "a pointer that points to the **instance of the class that is to receive the message**". Or more simply put, it’s the object that the method is being invoked upon. If the method is a class method, this will be an instance of the class object (as a whole), whereas for an instance method, self will point to an instantiated instance of the class as an object.
* The second parameter, (**op**), is "the selector of the method that handles the message". Again, more simply put, this is just the **name of the method.**
* The remaining parameters are any **values that are required by the method** (op).

| **Argument**      | **Register**                                                    | **(for) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: object that the method is being invoked upon** |
| **2nd argument**  | **rsi**                                                         | **op: name of the method**                             |
| **3rd argument**  | **rdx**                                                         | **1st argument to the method**                         |
| **4th argument**  | **rcx**                                                         | **2nd argument to the method**                         |
| **5th argument**  | **r8**                                                          | **3rd argument to the method**                         |
| **6th argument**  | **r9**                                                          | **4th argument to the method**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **5th+ argument to the method**                        |

### Swift

With Swift binaries, since there is Objective-C compatibility, sometimes you can extract declarations using [class-dump](https://github.com/nygard/class-dump/) but not always.

With the **`jtool -l`** or **`otool -l`** command lines it's possible ti find several sections that start with **`__swift5`** prefix:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

You can find further information about the [**information stored in these section in this blog post**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

### Packed binaries

* Check for high entropy
* Check the strings (is there is almost no understandable string, packed)
* The UPX packer for MacOS generates a section called "\_\_XHDR"

## Dynamic Analysis

{% hint style="warning" %}
Note that in order to debug binaries, **SIP needs to be disabled** (`csrutil disable` or `csrutil enable --without debug`) or to copy the binaries to a temporary folder and **remove the signature** with `codesign --remove-signature <binary-path>` or allow the debugging of the binary (you can use [this script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Note that in order to **instrument system binaries**, (such as `cloudconfigurationd`) on macOS, **SIP must be disabled** (just removing the signature won't work).
{% endhint %}

### Unified Logs

MacOS generates a lot of logs that can be very useful when running an application trying to understand **what is it doing**.

Moreover, the are some logs that will contain the tag `<private>` to **hide** some **user** or **computer** **identifiable** information. However, it's possible to **install a certificate to disclose this information**. Follow the explanations from [**here**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Left panel

In the left panel of hopper it's possible to see the symbols (**Labels**) of the binary, the list of procedures and functions (**Proc**) and the strings (**Str**). Those aren't all the strings but the ones defined in several parts of the Mac-O file (like _cstring or_ `objc_methname`).

#### Middle panel

In the middle panel you can see the **dissasembled code**. And you can see it a **raw** disassemble, as **graph**, as **decompiled** and as **binary** by clicking on the respective icon:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Right clicking in a code object you can see **references to/from that object** or even change its name (this doesn't work in decompiled pseudocode):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Moreover, in the **middle down you can write python commands**.

#### Right panel

In the right panel you can see interesting information such as the **navigation history** (so you know how you arrived at the current situation), the **call grap**h where you can see all the **functions that call this function** and all the functions that **this function calls**, and **local variables** information.

### dtrace

It allows users access to applications at an extremely **low level** and provides a way for users to **trace** **programs** and even change their execution flow. Dtrace uses **probes** which are **placed throughout the kernel** and are at locations such as the beginning and end of system calls.

DTrace uses the **`dtrace_probe_create`** function to create a probe for each system call. These probes can be fired in the **entry and exit point of each system call**. The interaction with DTrace occur through /dev/dtrace which is only available for the root user.

{% hint style="success" %}
To enable Dtrace without fully disabling SIP protection you could execute on recovery mode: `csrutil enable --without dtrace`

You can also **`dtrace`** or **`dtruss`** binaries that **you have compiled**.
{% endhint %}

The available probes of dtrace can be obtained with:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

The probe name consists of four parts: the provider, module, function, and name (`fbt:mach_kernel:ptrace:entry`). If you not specifies some part of the name, Dtrace will apply that part as a wildcard.

To configure DTrace to activate probes and to specify what actions to perform when they fire, we will need to use the D language.

A more detailed explanation and more examples can be found in [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Examples

Run `man -k dtrace` to list the **DTrace scripts available**. Example: `sudo dtruss -n binary`

* In line

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

* script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234 
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### ktrace

You can use this one even with **SIP activated**

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is a very useful tool to check the process related actions a process is performing (for example, monitor which new processes a process is creating).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) allows to monitor file events (such as creation, modifications, and deletions) providing detailed information about such events.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) is a GUI tool with the look and feel Windows users may know from Microsoft Sysinternal’s _Procmon_. It lets you start and stop recording events of all types, filter them by categories (file, process, network, etc) and save the recorded events as json file.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) are part of Xcode’s Developer tools – used for monitoring application performance, identifying memory leaks and tracking filesystem activity.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Allows to follow actions performed by processes:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) is useful to see the **libraries** used by a binary, the **files** it's using and the **network** connections.\
It also checks the binary processes against **virustotal** and show information about the binary.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

In [**this blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) you can find an example about how to **debug a running daemon** that used **`PT_DENY_ATTACH`** to prevent debugging even if SIP was disabled.

### lldb

**lldb** is the de **facto tool** for **macOS** binary **debugging**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

You can set intel flavour when using lldb creating a file called **`.lldbinit`** in your home folder with the following line:

```bash
settings set target.x86-disassembly-flavor intel
```

{% hint style="warning" %}
Inside lldb, dump a process with `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Starting execution, which will continue unabated until a breakpoint is hit or the process terminates.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continue execution of the debugged process.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Execute the next instruction. This command will skip over function calls.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Execute the next instruction. Unlike the nexti command, this command will step into function calls.</td></tr><tr><td><strong>finish (f)</strong></td><td>Execute the rest of the instructions in the current function (“frame”) return and halt.</td></tr><tr><td><strong>control + c</strong></td><td>Pause execution. If the process has been run (r) or continued (c), this will cause the process to halt ...wherever it is currently executing.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Any func called main</p><p>b &#x3C;binname>`main #Main func of the bin</p><p>b set -n main --shlib &#x3C;lib_name> #Main func of the indicated bin</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Breakpoint list</p><p>br e/dis &#x3C;num> #Enable/Disable breakpoint</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Display the memory as a null-terminated string.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Display the memory as assembly instruction.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Display the memory as byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>This will print the object referenced by the param</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Note that most of Apple’s Objective-C APIs or methods return objects, and thus should be displayed via the “print object” (po) command. If po doesn't produce a meaningful output use <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n &#x3C;funcname> #Disas func</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr></tbody></table>

{% hint style="info" %}
When calling the **`objc_sendMsg`** function, the **rsi** register holds the **name of the method** as a null-terminated (“C”) string. To print the name via lldb do:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dynamic Analysis

#### VM detection

* The command **`sysctl hw.model`** returns "Mac" when the **host is a MacOS** but something different when it's a VM.
* Playing with the values of **`hw.logicalcpu`** and **`hw.physicalcpu`** some malwares try to detect if it's a VM.
* Some malwares can also **detect** if the machine is **VMware** based on the MAC address (00:50:56).
* It's also possible to find **if a process is being debugged** with a simple code such us:
  * `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* It can also invoke the **`ptrace`** system call with the **`PT_DENY_ATTACH`** flag. This **prevents** a deb**u**gger from attaching and tracing.
  * You can check if the **`sysctl`** or **`ptrace`** function is being **imported** (but the malware could import it dynamically)
  * As noted in this writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
    “_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT\_DENY\_ATTACH**_”

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analyzes crashing processes and saves a crash report to disk**. A crash report contains information that can **help a developer diagnose** the cause of a crash.\
For applications and other processes **running in the per-user launchd context**, ReportCrash runs as a LaunchAgent and saves crash reports in the user's `~/Library/Logs/DiagnosticReports/`\
For daemons, other processes **running in the system launchd context** and other privileged processes, ReportCrash runs as a LaunchDaemon and saves crash reports in the system's `/Library/Logs/DiagnosticReports`

If you are worried about crash reports **being sent to Apple** you can disable them. If not, crash reports can be useful to **figure out how a server crashed**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Sleep

While fuzzing in a MacOS it's important to not allow the Mac to sleep:

* systemsetup -setsleep Never
* pmset, System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Disconnect

If you are fuzzing via a SSH connection it's important to make sure the session isn't going to day. So change the sshd\_config file with:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Internal Handlers

**Checkout the following page** to find out how you can find which app is responsible of **handling the specified scheme or protocol:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerating Network Processes

This interesting to find processes that are managing network data:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Or use `netstat` or `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Works for CLI tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

It "**just works"** with macOS GUI tools. Note some some macOS apps have some specific requirements like unique filenames, the right extension, need to read the files from the sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Some examples:

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### More Fuzzing MacOS Info

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
