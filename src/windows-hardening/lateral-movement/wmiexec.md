# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理解释

可以在已知用户名和密码或哈希的主机上通过使用 WMI 打开进程。通过 Wmiexec 使用 WMI 执行命令，提供半交互式的 shell 体验。

**dcomexec.py:** 利用不同的 DCOM 端点，该脚本提供类似于 wmiexec.py 的半交互式 shell，特别利用 ShellBrowserWindow DCOM 对象。它目前支持 MMC20。应用程序、Shell Windows 和 Shell Browser Window 对象。（来源：[Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)）

## WMI 基础知识

### 命名空间

WMI 的顶级容器是 \root，按照目录式层次结构组织，下面有称为命名空间 的其他目录。
列出命名空间的命令：
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
在命名空间内可以使用以下方式列出类：
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **类**

知道 WMI 类名，例如 win32_process，以及它所在的命名空间，对于任何 WMI 操作都是至关重要的。
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

方法是一个或多个可执行的 WMI 类函数，可以被执行。
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

验证 WMI 服务是否正常运行的命令：
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
对于攻击者来说，WMI 是一个强大的工具，用于枚举有关系统或域的敏感数据。
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
通过仔细构造命令，可以远程查询 WMI 以获取特定信息，例如本地管理员或登录用户。

### **手动远程 WMI 查询**

可以通过特定的 WMI 查询隐秘地识别远程机器上的本地管理员和登录用户。`wmic` 还支持从文本文件读取，以便同时在多个节点上执行命令。

要通过 WMI 远程执行一个进程，例如部署 Empire 代理，使用以下命令结构，成功执行的返回值为 "0"：
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
这个过程展示了WMI远程执行和系统枚举的能力，突显了它在系统管理和渗透测试中的实用性。

## 参考文献

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## 自动化工具

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
