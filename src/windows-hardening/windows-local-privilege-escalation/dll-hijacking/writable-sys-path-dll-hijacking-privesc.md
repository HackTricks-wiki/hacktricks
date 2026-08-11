# Writable Sys Path + DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**system-wide `PATH`**（単にユーザーの `PATH` ではない）のディレクトリに**書き込み可能**な場合、システム上で**privileges を escalate**できる可能性があります。

これは、より高い権限で動作する service または process が、以前の検索場所に存在しない DLL を load し、最終的に書き込み可能な system `PATH` ディレクトリを検索する場合に、**DLL hijacking** を通じて悪用できます。

**DLL hijacking** の詳細については、以下を参照してください。


{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Missing DLL の特定

まず、**書き込み可能な system `PATH` ディレクトリから DLL を load しようとする、より高い privileges で実行中の process**を**特定**します。

この technique は、**User PATH**だけでなく、**Machine/System PATH**の entry に依存することに注意してください。そのため、Procmon に時間をかける前に、**Machine PATH**の entry を列挙し、どれが書き込み可能かを確認する価値があります。<sup>[[1]](#references)</sup>
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
このようなケースでの問題は、これらのプロセスがすでに実行中である可能性が高いことです。サービスがロードを試みて失敗する DLL を特定するには、Procmon をできるだけ早く（プロセスが開始する前に）起動し、次の操作を行います。

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
- その後、**reboot** します。コンピューターが再起動すると、**`procmon`** はできるだけ早くイベントの**記録**を開始します。
- **Windows** が**起動したら `procmon` を実行**します。実行中だったことが通知され、イベントをファイルに**保存するかどうかを尋ねられます**。**yes** を選択し、**イベントをファイルに保存**します。
- **ファイル**が**生成されたら**、開いている **`procmon`** ウィンドウを閉じ、**イベントファイルを開きます**。
- **writable System Path** フォルダーから**プロセスがロードしようとした** DLL をすべて見つけるため、以下の**filters**を追加します。

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging は、他の方法では観察できないほど早く起動するサービスにのみ必要**です。**対象のサービス/program をオンデマンドでトリガーできる場合**（例えば、その COM interface とやり取りする、サービスを再起動する、scheduled task を再起動するなど）は、通常の Procmon capture を使用し、**`Path contains .dll`**、**`Result is NAME NOT FOUND`**、**`Path begins with <writable_machine_path>`** などの filters を設定する方が速くなります。

### 見逃された DLL

無料の **virtual (vmware) Windows 11 machine** でこれを実行したところ、以下の結果になりました。

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、`.exe` の結果は無視します。missing-DLL probes は以下から発生していました。

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

以下の例では、この記事で説明されている **privilege escalation のために `WptsExtensions.dll` を abuse する手法**を使用します。[**`WptsExtensions.dll` を privilege escalation のために abuse する**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)<sup>[[3]](#references)</sup>

### さらに triage する価値のある候補

`WptsExtensions.dll` は良い例ですが、privileged services に繰り返し現れる **phantom DLL** はこれだけではありません。Modern hunting rules と public hijack catalogs では、現在も次のような名前が追跡されています。<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | client systems における典型的な **SYSTEM** candidate です。writable directory が **Machine PATH** に含まれており、service が startup 中に DLL を probe する場合に有効です。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** では興味深い候補です。この service は **SYSTEM** として実行され、一部の builds では**通常の user がオンデマンドで trigger できる**ため、reboot-only cases より優れています。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常、最初に **`NT AUTHORITY\LOCAL SERVICE`** が得られます。これは多くの場合、token に **`SeImpersonatePrivilege`** があるため十分です。そのため、[RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) と chain できます。 |

これらの名前は、確実な成功を保証するものではなく、**triage hints** として扱ってください。**SKU/build に依存**しており、Microsoft は release 間で動作を変更する可能性があります。重要なのは、特に**reboot せずに再度 trigger できる service** で、**Machine PATH を走査する privileged services における missing DLL** を探すことです。

### Exploitation

**privileges を escalate** するには、**`WptsExtensions.dll`** を hijack します。**path** と**name**が判明したら、malicious DLL を生成します。

[**これらの例を使用してみる**](#creating-and-compiling-dlls)ことができます。次のような payloads を実行できます。rev shell の取得、user の追加、beacon の実行などです。

> [!WARNING]
> すべての services が **`NT AUTHORITY\SYSTEM`** として**実行されるわけではない**ことに注意してください。一部は **`NT AUTHORITY\LOCAL SERVICE`** として実行されます。この account は**権限が少ない**ため、これらの services を abuse しても新しい user を作成できない場合があります。\
> ただし、この account には **`SeImpersonatePrivilege`** user right があるため、[**Potato suite で privileges を escalate できます**](../roguepotato-and-printspoofer.md)。この場合、user の作成を試みるよりも reverse shell の方が適しています。

執筆時点では、**Task Scheduler** service は **Nt AUTHORITY\SYSTEM** で実行されています。

**malicious Dll を生成したら**（_私の場合は x64 rev shell を使用し、shell を取得できましたが、msfvenom 由来だったため defender に kill されました_）、writable System Path に **WptsExtensions.dll** という name で保存し、コンピューターを**restart**します（または service を restart するか、影響を受けた service/program を再実行するために必要な操作を行います）。

service が再起動されると、**dll がロードされて実行されるはずです**（**procmon** の trick を再利用して、**library が想定どおりロードされたか**を確認できます）。

## References

- [1] [Windows DLL Hijacking（明確化を目指して）](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Persistence または Privilege Escalation のためにロードされた疑わしい DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
