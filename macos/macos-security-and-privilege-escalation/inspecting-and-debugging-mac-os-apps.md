# Inspecting and debugging Mac OS Sotware

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

## Dynamic Analysis

{% hint style="warning" %}
These tools require **SIP to be disabled** or to copy the binaries to a temporary folder and **remove the signature** with `codesign --remove-signature <binary-path>`
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

