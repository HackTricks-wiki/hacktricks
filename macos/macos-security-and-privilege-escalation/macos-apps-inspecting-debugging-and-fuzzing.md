# MacOS Apps - Inspecting, debugging and Fuzzing

## Static Analysis

### otool

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

### SuspiciousPackage

****[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) is a tool useful to inspect **.pkg** files (installers) and see what is inside before installing it.\
These installers have `preinstall` and `postinstall` bash scripts that malware authors usually abuse to **persist** **the** **malware**.

### hdiutil

This tool allows to **mount** Apple disk images (**.dmg**) files to inspect them before running anything:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

It will be mounted in `/Volumes`

### Objective-C

When a function is called in a binary that uses objective-C, the compiled code instead of calling that function, it will call **`objc_msgSend`**. Which will be calling the final function:

![](<../../.gitbook/assets/image (560).png>)

The params this function expects are:

* The first parameter (**self**) is "a pointer that points to the **instance of the class that is to receive the message**". Or more simply put, it’s the object that the method is being invoked upon. If the method is a class method, this will be an instance of the class object (as a whole), whereas for an instance method, self  will point to an instantiated instance of the class as an object. 
* The second parameter, (**op**), is "the selector of the method that handles the message". Again, more simply put, this is just the **name of the method.** 
* The remaining parameters are any** values that are required by the method** (op).

| **Argument  **    | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument ** | **rdi**                                                         | **self: object that the method is being invoked upon** |
| **2nd argument ** | **rsi**                                                         | **op: name of the method**                             |
| **3rd argument**  | **rdx**                                                         | **1st argument to the method**                         |
| **4th argument**  | **rcx**                                                         | **2nd argument to the method**                         |
| **5th argument**  | **r8**                                                          | **3rd argument to the method**                         |
| **6th argument**  | **r9**                                                          | **4th argument to the method**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **5th+ argument to the method**                        |

### Packed binaries

* Check for high entropy
* Check the strings (is there is almost no understandable string, packed)
* The UPX packer for MacOS generates a section called "\__XHDR"

## Dynamic Analysis

{% hint style="warning" %}
Note that in order to debug binaries, **SIP needs to be disabled **(`csrutil disable` or `csrutil enable --without debug`) or to copy the binaries to a temporary folder and **remove the signature **with `codesign --remove-signature <binary-path> `or allow the debugging of the binary (you can use [this script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Note that in order to **instrument system binarie**s, (such as `cloudconfigurationd`) on macOS, **SIP must be disabled** (just removing the signature won't work).
{% endhint %}

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

### dtrace

It allows users access to applications at an extremely **low level **and provides a way for users to **trace** **programs** and even change their execution flow. Dtrace uses **probes** which are **placed throughout the kernel** and are at locations such as the beginning and end of system calls.

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

A more detailed explanation and more examples can be found in [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Examples

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

### ProcessMonitor

****[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is a very useful tool to check the process related actions a process is performing (for example, monitor which new processes a process is creating).

### FileMonitor

****[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) allows to monitor file events (such as creation, modifications, and deletions) providing detailed information about such events.

### fs_usage

Allows to follow actions performed by processes:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

****[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) is useful to see the **libraries** used by a binary, the **files** it's using and the **network** connections.\
It also checks the binary processes against **virustotal** and show information about the binary.

### lldb

**lldb** is the de **facto tool **for **macOS** binary **debugging**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

| **(lldb) Command**            | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **run (r)**                   | Starting execution, which will continue unabated until a breakpoint is hit or the process terminates.                                                                                                                                                                                                                                                                                                                                 |
| **continue (c)**              | Continue execution of the debugged process.                                                                                                                                                                                                                                                                                                                                                                                           |
| **nexti (n)**                 | Execute the next instruction. This command will skip over function calls.                                                                                                                                                                                                                                                                                                                                                             |
| **stepi (s)**                 | Execute the next instruction. Unlike the nexti command, this command will step into function calls.                                                                                                                                                                                                                                                                                                                                   |
| **finish (f)**                | Execute the rest of the instructions in the current function (“frame”) return and halt.                                                                                                                                                                                                                                                                                                                                               |
| **control + c**               | Pause execution. If the process has been run (r) or continued (c), this will cause the process to halt ...wherever it is currently executing.                                                                                                                                                                                                                                                                                         |
| **breakpoint (b)**            | <p>b main</p><p>b -[NSDictionary objectForKey:]</p><p>b 0x0000000100004bd9</p><p>br l #Breakpoint list</p><p>br e/dis &#x3C;num> #Enable/Disable breakpoint</p><p>breakpoint delete &#x3C;num></p>                                                                                                                                                                                                                                    |
| **help**                      | <p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p>                                                                                                                                                                                                                                                                                                                     |
| **reg**                       | <p>reg read $rax</p><p>reg write $rip 0x100035cc0</p>                                                                                                                                                                                                                                                                                                                                                                                 |
| **x/s \<reg/memory address>** | Display the memory as a null-terminated string.                                                                                                                                                                                                                                                                                                                                                                                       |
| **x/i \<reg/memory address>** | Display the memory as assembly instruction.                                                                                                                                                                                                                                                                                                                                                                                           |
| **x/b \<reg/memory address>** | Display the memory as byte.                                                                                                                                                                                                                                                                                                                                                                                                           |
| **print object (po)**         | <p>This will print the object referenced by the param</p><p>po $raw</p><p><code>{</code></p><p><code> dnsChanger =  {</code></p><p><code>   "affiliate" = "";</code></p><p><code>   "blacklist_dns" = ();</code></p><p>Note that most of Apple’s Objective-C APIs or methods return objects, and thus should be displayed via the “print object” (po) command. If po doesn't produce a meaningful output use <code>x/b</code><br></p> |
| **memory write**              | memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address                                                                                                                                                                                                                                                                                                                                                                  |

{% hint style="info" %}
When calling the **`objc_sendMsg`** function, the **rsi** register holds the **name of the method **as a null-terminated (“C”) string. To print the name via lldb do:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576  "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dynamic Analysis

#### VM detection

* The command **`sysctl hw.model`** returns "Mac" when the **host is a MacOS** but something different when it's a VM.
* Playing with the values of **`hw.logicalcpu`** and **`hw.physicalcpu`** some malwares try to detect if it's a VM.
* Some malwares can also **detect** if the machine is **VMware** based on the MAC address (00:50:56).
* It's also possible to find **if a process is being debugged** with a simple code such us:
  * `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* It can also invoke the **`ptrace`** system call with the **`PT_DENY_ATTACH`** flag. This **prevents** a deb**u**gger from attaching and tracing.
  * You can check if the **`sysctl` **or**`ptrace`** function is being **imported** (but the malware could import it dynamically)
  * As noted in this writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
    “_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT_DENY_ATTACH**_”

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html#:\~:text=ReportCrash%20analyzes%20crashing%20processes%20and%20saves%20a%20crash%20report%20to%20disk.\&text=ReportCrash%20also%20records%20the%20identity,when%20a%20crash%20is%20detected.)

ReportCrash **analyzes crashing processes and saves a crash report to disk**. A crash report contains information that can **help a developer diagnose** the cause of a crash.\
For applications and other processes** running in the per-user launchd context**, ReportCrash runs as a LaunchAgent and saves crash reports in the user's `~/Library/Logs/DiagnosticReports/`\
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

If you are fuzzing via a SSH connection it's important to make sure the session isn't going to day. So change the sshd_config file with:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Internal Handlers

[**Checkout this section**](./#file-extensions-apps)** **to find out how you can find which app is responsible of **handling the specified scheme or protocol**.

### Enumerating Network Processes

This interesting to find processes that are managing network data:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Or use `netstat` or `lsof`

### More Fuzzing MacOS Info

* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)****
* ****[**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)****
* ****[**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)****
