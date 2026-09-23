# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**system-wide `PATH`**（単なるユーザーの `PATH` ではない）のディレクトリに**書き込み可能**である場合、システム上で**privilege escalation**を実行できる可能性があります。

これは、より高い権限で動作する service または process が、先行する検索場所に存在しない DLL を load し、最終的に書き込み可能な system `PATH` ディレクトリを検索する場合に、**DLL hijacking**を通じて悪用できます。

書き込み可能な Machine `PATH` エントリは、**primitive**に過ぎず、code execution の証明ではありません。標準の検索順序を使用する unpackaged application では、`PATH` に到達する前に、redirection、API sets、SxS、loaded-module list、KnownDLLs、application directory、Windows directory、current directory が検索されます。full path または `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` policy によって、`PATH` が完全に除外される場合もあります。<sup>[[4]](#references)</sup>

**DLL hijacking**の詳細については、以下を参照してください。

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

まず、**より高い権限**で動作し、**書き込み可能な system `PATH` ディレクトリから DLL を load**しようとする **process**を特定します。

この technique は、**User PATH**だけではなく、**Machine/System PATH**エントリに依存することに注意してください。そのため、Procmon に時間をかける前に、**Machine PATH**エントリを列挙し、どのエントリが書き込み可能かを確認する価値があります。<sup>[[1]](#references)</sup>
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
ACL text can be misleading because group membership, deny ACEs, and inherited permissions affect the result. In an authorized test, a create/delete probe checks the **effective access of the current token** (it is intrusive and may generate alerts):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### 対象の実効 `PATH` を確認する

レジストリから読み取った Machine `PATH` は設定データです。loader は **対象プロセス** の環境ブロックを使用します。すべてのプロセスは環境ブロックを所有しており、子プロセスは通常、親プロセスの環境をコピーして継承します。そのため、長時間実行されているサービスには古い値が残っている場合があり、custom environment で起動されたサービスは、shell で確認できる値と異なることがあります。対象 PID による該当ディレクトリへの Procmon probe の観測結果を ground truth として扱ってください。lab で `PATH` を変更した後は、lookup が発生しないと判断する前に、関連する process tree を restart するか reboot してください。<sup>[[5]](#references)</sup>

このようなケースで問題となるのは、対象のプロセスがすでに実行中である可能性が高いことです。services が load を試みて失敗する DLLs を特定するには、Procmon をできるだけ早く（プロセスの起動前に）launch してから、次の操作を行います。

> [!WARNING]
> user-writable directory を Machine `PATH` に追加すると、**vulnerable condition が作成されます**。これは、どの privileged process が `PATH` に到達するかを確認するため、隔離された research VM でのみ実行してください。assessment 対象の host では、system configuration を変更せず、既存の writable entry を monitor してください。<sup>[[1]](#references)</sup>

- `C:\privesc_hijacking` folder を **作成** し、path `C:\privesc_hijacking` を **System Path env variable** に追加します。これは **手動** または **PS** で実行できます。
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
- **Windows** の**起動後に `procmon` を再度実行**すると、実行中だったことを通知し、イベントをファイルに**保存するかどうか尋ねられます**。**yes** を選択し、**イベントをファイルに保存**します。
- **ファイル**の**生成後**、開いている **`procmon`** ウィンドウを閉じ、**イベントファイルを開きます**。
- **writable System Path** フォルダーから**プロセスが load を試みた**すべての DLL を見つけるため、次の**filters**を追加します。

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** が必要なのは、通常の方法では観察できないほど**早い段階で起動するサービス**だけです。**対象のサービスやプログラムをオンデマンドで trigger できる場合**（たとえば、COM interface とのやり取り、サービスの再起動、scheduled task の再起動など）は、通常の Procmon capture を維持し、**`Path contains .dll`**、**`Result is NAME NOT FOUND`**、**`Path begins with <writable_machine_path>`** などの filters を使用する方が、一般的に高速です。

### 見逃された DLL

無料の**virtual (vmware) Windows 11 machine** でこれを実行したところ、次の結果が得られました。

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、`.exe` の結果は無視します。不足している DLL の probe は次のサービスから発生していました。

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

次の例では、この記事で説明されている、[**特権昇格のために `WptsExtensions.dll` を abuse する手法**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) を使用します。<sup>[[3]](#references)</sup>

### 追加で triage する価値のある候補

`WptsExtensions.dll` は良い例ですが、特権サービスに繰り返し現れる **phantom DLL** はこれだけではありません。Modern hunting rules と public hijack catalogs では、今でも次のような名前が追跡されています。<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client systems における典型的な **SYSTEM** candidate です。writable directory が **Machine PATH** に含まれ、サービスが startup 中に DLL を probe する場合に有効です。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** では興味深い候補です。サービスが **SYSTEM** として実行され、一部の build では通常の user が**オンデマンドで trigger できる**ため、reboot-only case よりも有利です。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常、最初に **`NT AUTHORITY\LOCAL SERVICE`** が得られます。token には **`SeImpersonatePrivilege`** があるため、多くの場合これで十分です。そのため、[RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) と chain できます。 |

これらの名前は**triage のヒント**として扱い、確実な成功例とは考えないでください。これらは **SKU/build に依存**しており、Microsoft が release 間で挙動を変更する可能性があります。重要なのは、**Machine PATH を通過する特権サービス内の missing DLL** を探すことです。特に、**reboot なしで再度 trigger できる**サービスが対象となります。

### weaponize する前に candidate を検証する

`NAME NOT FOUND` event だけでは不十分です。payload を配置する前に、完全な chain を検証してください。<sup>[[1]](#references)[[4]](#references)</sup>

1. event が想定された **PID、command line、service account、integrity level** に属しており、missing path が正確な writable Machine `PATH` directory であること。
2. 同じ DLL basename について、それより前の directory が `SUCCESS` を返していないこと。また、module が loaded-module list、KnownDLLs、redirection、SxS manifest によって解決されていないこと。
3. low-privileged user が意図した trigger を実行した際に probe が繰り返されること。boot-only lookup でも利用できますが、オンデマンドのものより operational に大幅に劣ります。
4. payload の architecture が process と一致していること。アプリケーションが後で exports を resolve する場合は、legitimate DLL を proxy するか、想定される symbols を export します。[Creating and compiling DLLs](README.md#creating-and-compiling-dlls) を参照してください。
5. 最初は、PID、identity、timestamp を記録する無害な canary DLL を使用します。Procmon では、直前の file probe が execution を引き起こしたと推測するのではなく、配置した path からの **`Load Image`** の成功を要求します。

### Exploitation

**privileges を escalate** するには、**`WptsExtensions.dll`** を hijack します。**path** と **name** が判明したら、malicious DLL を生成します。

[**これらの例のいずれかを使用してみることができます**](README.md#creating-and-compiling-dlls)。次のような payload を実行できます。reverse shell の取得、user の追加、beacon の実行などです。

> [!WARNING]
> **すべてのサービスが** **`NT AUTHORITY\SYSTEM`** として実行されるわけではないことに注意してください。一部は **`NT AUTHORITY\LOCAL SERVICE`** として実行されます。この account は**権限が少ない**ため、これらのサービスを abuse しても新しい user を作成できない場合があります。\
> ただし、この account には **`SeImpersonatePrivilege`** user right があるため、[**Potato suite で privileges を escalate**](../roguepotato-and-printspoofer.md) できます。この場合、user の作成を試みるより reverse shell の方が適しています。

**Task Scheduler** サービスは通常 **`NT AUTHORITY\SYSTEM`** として実行されますが、実際の deployment を確認し、service name だけから execution identity を推測しないでください。<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
**malicious Dllを生成した**後（_私の場合は x64 rev shellを使用し、shellを取得できましたが、msfvenom由来だったため Defender に強制終了されました_）、それを writable System Path に **WptsExtensions.dll** という名前で保存し、コンピューターを**再起動**します（または serviceを再起動するなど、影響を受ける service/programを再実行するために必要な操作を行います）。

serviceが再起動されると、**DLLがロードされ実行されるはずです**（**Procmon**の手法を再利用して、**libraryが想定どおりロードされたか**を確認できます）。

> [!NOTE]
> 実行前にcleanupの計画を立ててください。serviceがDLLをメモリにマッピングしたまま、serviceが停止するまでファイルをlockする場合があります。`WptsExtensions.dll`の場合、Task Schedulerの停止には昇格された権限が必要です。意図したcontextを取得したら、targetを安全に停止し、payloadを削除して、lab専用の`PATH`変更を元に戻してください。<sup>[[1]](#references)</sup>

### Remediation / detection

すべてのMachine `PATH`ディレクトリから弱いwrite grantを削除し、古いentryを削除します。Developerは、trusted libraryをfull pathでloadするか、`SetDefaultDllDirectories` / `LoadLibraryEx`のsearch flagsを使用してresolutionを制限する必要があります。Defenderは、Machine `PATH`への変更と、privileged processがnon-systemかつuser-writableなdirectoryからDLLをloadしたことを関連付けて検出できます。<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking（Hopefully）Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [PersistenceまたはPrivilege EscalationのためにロードされたSuspicious DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
