# Writable Sys Path +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**システム全体の `PATH`**（単にユーザーの `PATH` ではない）のディレクトリに**書き込み可能**であれば、システム上で**権限昇格**できる可能性があります。

これは、より高い権限を持つ service または process が、以前の検索場所に存在しない DLL を load し、最終的に書き込み可能なシステム `PATH` ディレクトリを検索する場合に、**DLL hijacking** を通じて悪用できます。

**DLL hijacking** の詳細については、以下を参照してください。


{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

まず、**書き込み可能なシステム `PATH` ディレクトリから DLL を load** しようとする、**より高い権限で実行されている process** を特定します。

この technique は、**User PATH** だけでなく、**Machine/System PATH** エントリに依存することに注意してください。そのため、Procmon に時間を費やす前に、**Machine PATH** エントリを列挙し、どのエントリが書き込み可能かを確認する価値があります:<sup>[[1]](#references)</sup>
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
このようなケースで問題となるのは、それらのプロセスがすでに実行中である可能性が高いことです。サービスが読み込みを試みて失敗する DLL を特定するには、Procmon をできるだけ早く（プロセスが開始する前に）起動し、次の操作を行います。

- **Create** フォルダー `C:\privesc_hijacking` を作成し、パス `C:\privesc_hijacking` を **System Path env variable** に追加します。これは**手動**または **PS** で実行できます。
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
- その後、**reboot** します。コンピューターが再起動すると、**`procmon`** はすぐにイベントの**記録**を開始します。
- **Windows** が**起動したら `procmon` を実行**し、実行中だったことを通知して、イベントをファイルに**保存するかどうか尋ねてきます**。**yes** を選択し、**イベントをファイルに保存**します。
- **ファイル**が**生成されたら**、開いている **`procmon`** ウィンドウを閉じ、**イベントファイルを開きます**。
- **writable System Path** フォルダーから**プロセスがロードを試みた**すべての DLL を見つけるため、次の**フィルター**を追加します。

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** が必要なのは、通常の方法では観察できないほど早い段階で起動するサービスだけです。**対象のサービス/プログラムをオンデマンドでトリガーできる**場合（COM interface とのやり取り、サービスの再起動、scheduled task の再起動など）は、通常の Procmon capture を使用し、**`Path contains .dll`**、**`Result is NAME NOT FOUND`**、**`Path begins with <writable_machine_path>`** などのフィルターを設定する方が、通常は高速です。

### 見逃された DLL

無料の**仮想（vmware）Windows 11 マシン**でこれを実行したところ、次の結果が得られました。

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、`.exe` の結果は無視します。missing-DLL probe は次のものから発生していました。

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

次の例では、この記事で説明されている [**`WptsExtensions.dll` を悪用した privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) の technique を使用します。<sup>[[3]](#references)</sup>

### トリアージする価値のあるその他の候補

`WptsExtensions.dll` は良い例ですが、特権サービスに繰り返し登場する **phantom DLL** はこれだけではありません。Modern hunting rules と public hijack catalogs では、現在も次のような名前が追跡されています。<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | client systems における典型的な **SYSTEM** candidate です。writable directory が **Machine PATH** に含まれ、サービスが startup 中に DLL を probe する場合に有効です。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** では興味深い候補です。サービスが **SYSTEM** として実行され、一部の build では **normal user がオンデマンドでトリガーできる**ため、reboot-only cases より優れています。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常、最初に **`NT AUTHORITY\LOCAL SERVICE`** が得られます。これは多くの場合、token に **`SeImpersonatePrivilege`** があるため十分です。そのため、[RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) と chain できます。 |

これらの名前は**トリアージのヒント**として扱い、確実に成功するものとは考えないでください。**SKU/build に依存**しており、Microsoft は release 間で動作を変更する可能性があります。重要なのは、**Machine PATH をたどる privileged services** における **missing DLL** を探すことです。特に、**reboot なしで再トリガーできる**サービスが対象となります。

### Exploitation

**privileges を escalate** するには、**`WptsExtensions.dll`** を hijack します。**path** と **name** が判明したら、malicious DLL を生成します。

[**これらの例のいずれかを使用してみることができます**](#creating-and-compiling-dlls)。次のような payload を実行できます: rev shell の取得、user の追加、beacon の実行など。

> [!WARNING]
> すべてのサービスが **`NT AUTHORITY\SYSTEM`** として**実行されるわけではない**ことに注意してください。一部は **`NT AUTHORITY\LOCAL SERVICE`** として実行されます。この account は**権限が少ない**ため、これらのサービスのいずれかを abuse しても、新しい user を作成できない場合があります。\
> ただし、この account には **`SeImpersonatePrivilege`** user right があるため、[**Potato suite で privileges を escalate**](../roguepotato-and-printspoofer.md) できます。この場合、user の作成を試みるより reverse shell の方が適しています。

執筆時点では、**Task Scheduler** service は **Nt AUTHORITY\SYSTEM** で実行されています。

**malicious Dll を生成したら**（_私の場合は x64 rev shell を使用し、shell を取得できましたが、msfvenom 由来だったため defender に kill されました_）、writable System Path に **WptsExtensions.dll** という名前で保存し、コンピューターを**再起動**します（または service を restart するか、影響を受けた service/program を再実行するために必要な操作を行います）。

service が再起動されると、**dll がロードされて実行されるはずです**（**library が想定どおりロードされたか**確認するため、**procmon** の technique を**再利用**できます）。

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
