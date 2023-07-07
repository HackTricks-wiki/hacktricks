# WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## 動作原理

Wmiは、ユーザー名/（パスワード/ハッシュ）がわかるホストでプロセスを開くことができます。その後、Wmiexecは、実行する各コマンドを実行するためにwmiを使用します（これがWmicexecが半対話型シェルを提供する理由です）。

**dcomexec.py:** このスクリプトは、異なるDCOMエンドポイント（ShellBrowserWindow DCOMオブジェクト）を使用して、wmiexec.pyと似た半対話型シェルを提供します。現在、MMC20.アプリケーション、Shell Windows、およびShell Browser Windowオブジェクトをサポートしています（[ここから](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)）。

## WMIの基礎

### 名前空間

WMIは、\rootコンテナと呼ばれるディレクトリスタイルの階層で分割されており、\rootの下に他のディレクトリがあります。これらの「ディレクトリパス」は名前空間と呼ばれます。\
名前空間の一覧：
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
以下のコマンドを使用して、名前空間のクラスをリストします:

```plaintext
wmic /namespace:\\root\cimv2 CLASS __NAMESPACE
```

このコマンドは、指定した名前空間内のクラスを表示します。
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **クラス**

WMIクラス名（例：win32\_process）は、WMIアクションの出発点です。常にクラス名とその場所である名前空間を知る必要があります。\
`win32`で始まるクラスの一覧を表示します。
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
クラスを呼び出す：
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### メソッド

WMIクラスには、実行できる1つ以上の関数があります。これらの関数はメソッドと呼ばれます。
```bash
#Load a class using [wmiclass], leist methods and call one
$c = [wmiclass]"win32_share"
$c.methods
#Find information about the class in https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
$c.Create("c:\share\path","name",0,$null,"My Description")
#If returned value is "0", then it was successfully executed
```

```bash
#List methods
Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' | Where-Object { $_.PSBase.Methods } | Select-Object Name, Methods
#Call create method from win32_share class
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI列挙

### WMIサービスの確認

WMIサービスが実行されているかどうかを確認する方法は次の通りです：
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### システム情報

To obtain system information using WMIC, you can use the following command:

```plaintext
wmic os get Caption, Version, OSArchitecture, Manufacturer, BuildNumber
```

This command will retrieve the following information:

- Caption: The name of the operating system.
- Version: The version number of the operating system.
- OSArchitecture: The architecture of the operating system (32-bit or 64-bit).
- Manufacturer: The manufacturer of the operating system.
- BuildNumber: The build number of the operating system.

By running this command, you will be able to gather important system information that can be useful for various purposes, such as troubleshooting or system analysis.
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### プロセス情報

To obtain information about running processes on a Windows system, you can use the `wmic` command. This command allows you to query various attributes of processes, such as their process ID (PID), parent process ID (PPID), command line arguments, and more.

To list all running processes, you can run the following command:

```plaintext
wmic process get Caption,ProcessId,CommandLine
```

This will display the name of the process (`Caption`), its process ID (`ProcessId`), and the command line arguments used to launch the process (`CommandLine`).

You can also filter the results based on specific criteria. For example, to find all processes with a specific name, you can use the `where` clause:

```plaintext
wmic process where "Name='process_name'" get Caption,ProcessId,CommandLine
```

Replace `process_name` with the name of the process you want to find.

Additionally, you can sort the results based on a specific attribute. For example, to sort the processes by their process ID in ascending order, you can use the `order by` clause:

```plaintext
wmic process get Caption,ProcessId,CommandLine /order by ProcessId
```

This will display the processes sorted by their process ID in ascending order.

By using the `wmic` command, you can gather valuable information about running processes on a Windows system, which can be useful for troubleshooting, monitoring, or security purposes.
```bash
Get-WmiObject win32_process | Select Name, Processid
```
攻撃者の視点から見ると、WMIはシステムやドメインに関する機密情報を列挙するために非常に価値があります。
```
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

```bash
Get-WmiObject Win32_Processor -ComputerName 10.0.0.182 -Credential $cred
```
## **手動リモートWMIクエリ**

たとえば、リモートマシン上でローカル管理者を発見する非常にステルスな方法があります（ドメインはコンピュータ名であることに注意してください）：
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")
```
もう一つ便利なワンライナーは、マシンにログインしているユーザーを確認することです（管理者を追跡する場合に使用します）:
```
wmic /node:ordws01 path win32_loggedonuser get antecedent
```
`wmic`は、テキストファイルからノードを読み取り、それら全てにコマンドを実行することもできます。もしワークステーションのテキストファイルがある場合は、以下のように実行できます。
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent
```
**WMIを介してリモートでプロセスを作成し、Empireエージェントを実行します。**
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"
```
実行が成功しました（ReturnValue = 0）。そして、1秒後にEmpireリスナーがそれをキャッチします。プロセスIDがWMIが返したものと同じであることに注意してください。

この情報はここから抽出されました：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
