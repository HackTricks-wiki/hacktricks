# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## はじめに

**System Path フォルダーに write できる**ことが判明した場合（**User Path フォルダーに write できる**場合は機能しない点に注意してください）、システム上で**権限昇格**できる可能性があります。

これを行うには、**Dll Hijacking**を悪用します。これは、自分よりも**高い権限**で動作している service または process が**ロードしている library を hijack**する手法です。その service が、おそらくシステム全体のどこにも存在しない Dll をロードしているため、write 可能な System Path からロードしようとします。

**Dll Hijack とは何か**についての詳細は、以下を確認してください:


{{#ref}}
./
{{#endref}}

## Dll Hijacking による Privesc

### 不足している Dll の発見

最初に必要なのは、自分よりも**高い権限**で動作し、write 可能な System Path から Dll を**ロードしようとしている process**を特定することです。

この手法は、**User PATH**だけでなく、**Machine/System PATH**エントリに依存することを覚えておいてください。そのため、Procmon に時間をかける前に、**Machine PATH**エントリを列挙し、どれが write 可能かを確認する価値があります:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
このケースでの問題は、おそらくこれらのプロセスがすでに実行中であることです。サービスに必要な Dlls のうち、不足しているものを特定するには、procmon をできるだけ早く（プロセスがロードされる前に）起動する必要があります。不足している .dlls を特定するには、次の手順を実行します。

- **`C:\privesc_hijacking`** フォルダーを作成し、パス **`C:\privesc_hijacking`** を **System Path env variable** に追加します。これは **手動** または **PS** で実行できます。
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- **`procmon`** を起動し、**`Options`** --> **`Enable boot logging`** に移動して、プロンプトで **`OK`** を押します。
- 次に、**再起動**します。コンピューターが再起動されると、**`procmon`** がすぐにイベントの**記録**を開始します。
- **Windows** が**起動したら `procmon` を再度実行**します。実行中だったことが通知され、イベントをファイルに**保存するかどうかを尋ねられます**。**yes** を選択し、**イベントをファイルに保存**します。
- **ファイル**が**生成されたら**、開いている **`procmon`** ウィンドウを閉じ、**イベントファイルを開きます**。
- 以下の**フィルター**を追加すると、書き込み可能な System Path フォルダーから、何らかの**プロセスがロードしようとした**すべての DLL を確認できます。

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging は、通常の方法では観察できないほど早く起動するサービス**に対してのみ必要です。**対象のサービスやプログラムをオンデマンドでトリガーできる場合**（たとえば、COM インターフェースとの対話、サービスの再起動、スケジュールされたタスクの再実行など）は、通常の Procmon キャプチャを、**`Path contains .dll`**、**`Result is NAME NOT FOUND`**、**`Path begins with <writable_machine_path>`** などのフィルターとともに使用する方が、一般的に高速です。

### 見逃された DLL

無償の **仮想 VMware Windows 11 マシン**でこれを実行したところ、次の結果が得られました。

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、.exe は役に立たないため無視してください。見逃された DLL は次のとおりです。

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを発見した後、[**privesc のために WptsExtensions.dll を abuse する方法を説明した**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)興味深いブログ記事を見つけました。これを**これから実行します**。<sup>[[3]](#references)</sup>

### トリアージする価値のあるその他の候補

`WptsExtensions.dll` は良い例ですが、特権サービスに現れる **phantom DLL** はこれだけではありません。最新のハンティングルールや公開されている hijack カタログでは、次のような名前も引き続き追跡されています。<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | クライアントシステムにおける典型的な **SYSTEM** 候補です。書き込み可能なディレクトリが **Machine PATH** に含まれており、サービスが起動時に DLL を検索する場合に有効です。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | サービスが **SYSTEM** として実行され、一部の build では通常のユーザーが**オンデマンドでトリガーできる**ため、**server editions** では興味深い候補です。再起動のみに依存するケースよりも優れています。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常、最初に **`NT AUTHORITY\LOCAL SERVICE`** が得られます。これは多くの場合、トークンが **`SeImpersonatePrivilege`** を持っているため、[RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) と chain するには十分です。 |

これらの名前は、成功を保証するものではなく、**トリアージのヒント**として扱ってください。これらは **SKU/build に依存**しており、Microsoft は release 間で動作を変更する可能性があります。重要なのは、**Machine PATH をたどる特権サービス内の missing DLL**、特に**再起動せずに再度トリガーできるサービス**を探すことです。

### Exploitation

したがって、**privileges を escalate**するために、ライブラリ **WptsExtensions.dll** を hijack します。**path** と**名前**が分かっているので、あとは**malicious dll を生成**するだけです。

[**これらの例のいずれかを使用してみることができます**](#creating-and-compiling-dlls)。get a rev shell、ユーザーの追加、beacon の実行などの payload を実行できます。

> [!WARNING]
> **すべてのサービスが** **`NT AUTHORITY\SYSTEM`** として実行されるわけではない点に注意してください。一部は **`NT AUTHORITY\LOCAL SERVICE`** として実行されます。これは**権限が少ない**ため、ユーザーを作成できず、その権限を abuse することもできません。\
> ただし、このユーザーには **`seImpersonate`** privilege があるため、[ **potato suite で privileges を escalate できます**](../roguepotato-and-printspoofer.md)。したがって、この場合はユーザーの作成を試みるよりも、rev shell の方が適しています。

執筆時点では、**Task Scheduler** サービスは **Nt AUTHORITY\SYSTEM** として実行されています。

**malicious Dll を生成**したら（_私の場合は x64 rev shell を使用して shell を取得しましたが、msfvenom 由来だったため defender に kill されました_）、書き込み可能な System Path に **WptsExtensions.dll** という名前で保存し、コンピューターを**再起動**します（またはサービスを再起動するか、対象のサービスやプログラムを再実行するために必要な操作を行います）。

サービスが再起動されると、**dll がロードされて実行される**はずです（**ライブラリが期待どおりにロードされたか**を確認するために、**procmon** の手法を再利用できます）。

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
