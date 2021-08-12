# Inspecting, debugging and Fuzzing Mac OS Software

## Static Analysis

### otool

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

### SuspiciousPackage

\*\*\*\*[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) is a tool useful to inspect **.pkg** files \(installers\) and see what is inside before installing it.  
These installers have `preinstall` and `postinstall` bash scripts that malware authors usually abuse to **persist** **the** **malware**.

### hdiutil

This tool allows to **mount** Apple disk images \(**.dmg**\) files to inspect them before running anything:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

It will be mounted in `/Volumes`

### Objective-C

When a function is called in a binary that uses objective-C, the compiled code instead of calling that function, it will call **`objc_msgSend`**. Which will be calling the final function:

![](../../.gitbook/assets/image%20%28559%29.png)

The params this function expects are:

* The first parameter \(**self**\) is "a pointer that points to the **instance of the class that is to receive the message**". Or more simply put, it’s the object that the method is being invoked upon. If the method is a class method, this will be an instance of the class object \(as a whole\), whereas for an instance method, self  will point to an instantiated instance of the class as an object. 
* The second parameter, \(**op**\), is "the selector of the method that handles the message". Again, more simply put, this is just the **name of the method.** 
* The remaining parameters are any **values that are required by the method** \(op\).

| **Argument**   | **Register** | **\(for\) objc\_msgSend** |
| :--- | :--- | :--- |
| **1st argument**  | **rdi** | **self: object that the method is being invoked upon** |
| **2nd argument**  | **rsi** | **op: name of the method** |
| **3rd argument** | **rdx** | **1st argument to the method** |
| **4th argument** | **rcx** | **2nd argument to the method** |
| **5th argument** | **r8** | **3rd argument to the method** |
| **6th argument** | **r9** | **4th argument to the method** |
| **7th+ argument** | **rsp+ \(on the stack\)** | **5th+ argument to the method** |

## Dynamic Analysis

{% hint style="warning" %}
Note that in order to debug binaries, **SIP needs to be disabled** \(`csrutil disable` or `csrutil enable --without debug`\) or to copy the binaries to a temporary folder and **remove the signature** with `codesign --remove-signature <binary-path>` or allow the debugging of the binary \(you can use [this script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)\)
{% endhint %}

{% hint style="warning" %}
Note that in order to **instrument system binarie**s, \(such as `cloudconfigurationd`\) on macOS, **SIP must be disabled** \(just removing the signature won't work\).
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

It allows users access to applications at an extremely **low level** and provides a way for users to **trace** **programs** and even change their execution flow. Dtrace uses **probes** which are **placed throughout the kernel** and are at locations such as the beginning and end of system calls.

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

The probe name consists of four parts: the provider, module, function, and name \(`fbt:mach_kernel:ptrace:entry`\). If you not specifies some part of the name, Dtrace will apply that part as a wildcard.

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

\*\*\*\*[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is a very useful tool to check the process related actions a process is performing \(for example, monitor which new processes a process is creating\).

### FileMonitor

\*\*\*\*[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) allows to monitor file events \(such as creation, modifications, and deletions\) providing detailed information about such events.

### fs\_usage

Allows to follow actions performed by processes:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### lldb

**lldb** is the de **facto tool** for **macOS** binary **debugging**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

<table>
  <thead>
    <tr>
      <th style="text-align:left"><b>(lldb) Command</b>
      </th>
      <th style="text-align:left"><b>Description</b>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><b>run (r)</b>
      </td>
      <td style="text-align:left">Starting execution, which will continue unabated until a breakpoint is
        hit or the process terminates.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>continue (c)</b>
      </td>
      <td style="text-align:left">Continue execution of the debugged process.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>nexti (n)</b>
      </td>
      <td style="text-align:left">Execute the next instruction. This command will skip over function calls.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>stepi (s)</b>
      </td>
      <td style="text-align:left">Execute the next instruction. Unlike the nexti command, this command will
        step into function calls.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>finish (f)</b>
      </td>
      <td style="text-align:left">Execute the rest of the instructions in the current function (&#x201C;frame&#x201D;)
        return and halt.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>control + c</b>
      </td>
      <td style="text-align:left">Pause execution. If the process has been run (r) or continued (c), this
        will cause the process to halt ...wherever it is currently executing.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>breakpoint (b)</b>
      </td>
      <td style="text-align:left">
        <p>b main</p>
        <p>b -[NSDictionary objectForKey:]</p>
        <p>b 0x0000000100004bd9</p>
        <p>br l #Breakpoint list</p>
        <p>br e/dis &lt;num&gt; #Enable/Disable breakpoint</p>
        <p>breakpoint delete &lt;num&gt;</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><b>help</b>
      </td>
      <td style="text-align:left">
        <p>help breakpoint #Get help of breakpoint command</p>
        <p>help memory write #Get help to write into the memory</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><b>reg</b>
      </td>
      <td style="text-align:left">
        <p>reg read $rax</p>
        <p>reg write $rip 0x100035cc0</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><b>x/s &lt;reg/memory address&gt;</b>
      </td>
      <td style="text-align:left">Display the memory as a null-terminated string.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>x/i &lt;reg/memory address&gt;</b>
      </td>
      <td style="text-align:left">Display the memory as assembly instruction.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>x/b &lt;reg/memory address&gt;</b>
      </td>
      <td style="text-align:left">Display the memory as byte.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>print object (po)</b>
      </td>
      <td style="text-align:left">
        <p>This will print the object referenced by the param</p>
        <p>po $raw</p>
        <p><code>{</code>
        </p>
        <p><code> dnsChanger =  {</code>
        </p>
        <p><code>   &quot;affiliate&quot; = &quot;&quot;;</code>
        </p>
        <p><code>   &quot;blacklist_dns&quot; = ();</code>
        </p>
        <p>Note that most of Apple&#x2019;s Objective-C APIs or methods return objects,
          and thus should be displayed via the &#x201C;print object&#x201D; (po)
          command. If po doesn&apos;t produce a meaningful output use <code>x/b</code>
          <br
          />
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><b>memory write</b>
      </td>
      <td style="text-align:left">memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address</td>
    </tr>
  </tbody>
</table>

{% hint style="info" %}
When calling the **`objc_sendMsg`** function, the **rsi** register holds the **name of the method** as a null-terminated \(“C”\) string. To print the name via lldb do:

\(lldb\) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"

\(lldb\) print \(char\*\)$rsi:  
\(char \*\) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"

\(lldb\) reg read $rsi: rsi = 0x00000001000f1576  "startMiningWithPort:password:coreCount:slowMemory:currency:"
{% endhint %}

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html#:~:text=ReportCrash%20analyzes%20crashing%20processes%20and%20saves%20a%20crash%20report%20to%20disk.&text=ReportCrash%20also%20records%20the%20identity,when%20a%20crash%20is%20detected.)

ReportCrash **analyzes crashing processes and saves a crash report to disk**. A crash report contains information that can **help a developer diagnose** the cause of a crash.  
For applications and other processes **running in the per-user launchd context**, ReportCrash runs as a LaunchAgent and saves crash reports in the user's `~/Library/Logs/DiagnosticReports/`  
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

[**Checkout this section**](./#file-extensions-apps) ****to find out how you can find which app is responsible of **handling the specified scheme or protocol**.

### Enumerating Network Processes

This interesting to find processes that are managing network data:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Or use `netstat` or `lsof`

## References

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://taomm.org/vol1/analysis.html](https://taomm.org/vol1/analysis.html)

