# Inspecting and debugging Mac OS Apps

## Static Analysis

### otool

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

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

```bash
sudo dtrace -n 'syscall:::entry {@[execname] = count()}' #Count the number of syscalls of each running process
```

