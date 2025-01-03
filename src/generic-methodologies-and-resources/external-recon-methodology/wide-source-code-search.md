# ワイドソースコード検索

{{#include ../../banners/hacktricks-training.md}}

このページの目的は、**コードを検索できるプラットフォーム**（リテラルまたは正規表現）を列挙することです。これは、1つまたは複数のプラットフォームで数千または数百万のリポジトリにわたります。

これは、**漏洩情報**や**脆弱性**パターンを検索する際に役立ちます。

- [**SourceGraph**](https://sourcegraph.com/search): 数百万のリポジトリを検索します。無料版とエンタープライズ版（15日間無料）があります。正規表現をサポートしています。
- [**Github Search**](https://github.com/search): Github全体を検索します。正規表現をサポートしています。
- もしかしたら、[**Github Code Search**](https://cs.github.com/)も確認するのが有用かもしれません。
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Gitlabプロジェクト全体を検索します。正規表現をサポートしています。
- [**SearchCode**](https://searchcode.com/): 数百万のプロジェクトのコードを検索します。

> [!WARNING]
> リポジトリ内で漏洩を探していて、`git log -p`のようなコマンドを実行する際は、**秘密を含む他のコミットがある他のブランチ**が存在するかもしれないことを忘れないでください！

{{#include ../../banners/hacktricks-training.md}}
