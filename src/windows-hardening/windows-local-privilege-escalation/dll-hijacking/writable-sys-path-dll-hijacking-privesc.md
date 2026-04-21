# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

もし **System Path フォルダに書き込みできる** ことが分かった場合（※ **User Path フォルダ** に書き込めるだけではこれは機能しません）、システム内で **権限昇格** できる可能性があります。

そのためには、**Dll Hijacking** を悪用します。これは、あなたより **より高い権限** で動作するサービスやプロセスが **読み込もうとしているライブラリを hijack** し、そのサービスが、おそらくシステム全体に存在しない Dll を読み込もうとするため、あなたが書き込める System Path からそれを読み込もうとする、というものです。

**Dll Hijackig** とは何かについての詳細は、こちらを確認してください:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

最初に必要なのは、あなたより **高い権限** で動作していて、あなたが書き込める **System Path から Dll を読み込もうとしている** **プロセスを特定する** ことです。

この手法は、あなたの **User PATH** だけでなく、**Machine/System PATH** のエントリに依存することを忘れないでください。したがって、Procmon に時間をかける前に、**Machine PATH** のエントリを列挙し、どれが書き込み可能かを確認する価値があります:
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
この場合の問題は、おそらくそれらのプロセスがすでに実行されていることです。どの Dlls が不足しているかを見つけるには、プロセスが読み込まれる前、できるだけ早く procmon を起動する必要があります。したがって、不足している .dlls を見つけるには、次を行います:

- **作成** フォルダ `C:\privesc_hijacking` を作成し、`C:\privesc_hijacking` のパスを **System Path env variable** に追加します。これは **手動** でも **PS** でも行えます:
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
- 次に、**再起動**します。コンピュータが再起動すると、**`procmon`** はできるだけ早くイベントの**記録**を開始します。
- **Windows** が起動したら、もう一度 **`procmon`** を**実行**します。すると、しばらく実行されていたことが表示され、イベントをファイルに**保存したいか**と**尋ねられます**。**yes** を選び、イベントをファイルに**保存**します。
- **ファイル**が生成されたら、開いている **`procmon`** ウィンドウを**閉じ**、イベントファイルを**開きます**。
- 次の**フィルタ**を追加すると、書き込み可能な System Path フォルダからいくつかの **proccess** が読み込もうとしたすべての Dll を見つけられます:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** が必要なのは、そうでなければ観測できないほど早く起動するサービスだけです。対象の service/program を**オンデマンドでトリガー**できるなら（たとえば、COM interface を操作する、service を再起動する、scheduled task を再実行するなど）、通常は **`Path contains .dll`**、**`Result is NAME NOT FOUND`**、**`Path begins with <writable_machine_path>`** のようなフィルタを使った通常の Procmon capture を取るほうが速いです。

### Missed Dlls

free の **virtual (vmware) Windows 11 machine** でこれを実行すると、次の結果になりました:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、.exe は役に立たないので無視してください。見つからなかった DLL は次のものでした:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを見つけたあと、[**WptsExtensions.dll を privesc に悪用する方法**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) も説明している興味深い blog post を見つけました。これが、これから**行うこと**です。

### Other candidates worth triaging

`WptsExtensions.dll` は良い例ですが、権限の高い services に現れる recurring な **phantom DLL** はそれだけではありません。最近の hunting rules や公開されている hijack catalog でも、次のような名前が追跡されています:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | client systems での古典的な **SYSTEM** 候補。書き込み可能なディレクトリが **Machine PATH** にあり、service が起動時に DLL を探索する場合に有効です。 |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **server editions** では興味深いです。service が **SYSTEM** として実行され、一部の build では**通常ユーザーがオンデマンドでトリガーできる**ため、再起動必須のケースより有利です。 |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | 通常はまず **`NT AUTHORITY\LOCAL SERVICE`** になります。それでも token には **`SeImpersonatePrivilege`** があることが多いため、[RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) と組み合わせられます。 |

これらの名前は**確実な成功**ではなく、**triage のヒント**として扱ってください。**SKU/build に依存**し、Microsoft は release 間で動作を変更することがあります。重要なのは、**Machine PATH をたどる権限の高い services の missing DLL** を探すことです。特に、その service を**再起動なしで再トリガーできる**場合は重要です。

### Exploitation

したがって、権限を**昇格**するために、library **WptsExtensions.dll** を hijack します。**path** と **name** が分かったので、あとは**悪意のある dll を生成**するだけです。

[**これらの例のいずれかを使ってみる**](#creating-and-compiling-dlls) ことができます。たとえば、rev shell を取得する、user を追加する、beacon を実行する、などが可能です...

> [!WARNING]
> すべての service が **`NT AUTHORITY\SYSTEM`** で実行されるわけではなく、**`NT AUTHORITY\LOCAL SERVICE`** で実行されるものもあります。こちらは**権限が低く**、user を新規作成して権限を悪用することは**できません**。\
> ただし、その user には **`seImpersonate`** privilege があるため、[**potato suite を使って権限を昇格**](../roguepotato-and-printspoofer.md) できます。したがって、この場合は user を作成しようとするより rev shell のほうが適しています。

執筆時点では **Task Scheduler** service は **Nt AUTHORITY\SYSTEM** で実行されています。

**悪意のある Dll** を生成したら（私の場合は x64 rev shell を使い、shell は返ってきましたが msfvenom 由来だったため defender に殺されました）、それを writable System Path に **WptsExtensions.dll** という名前で保存し、コンピュータを**再起動**します（または service を再起動するか、影響を受ける service/program を再実行するのに必要なことを行います）。

service が再起動されると、**dll が読み込まれて実行**されるはずです（**procmon** の手法を再利用して、**library が期待どおりに読み込まれたか**確認できます）。

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
