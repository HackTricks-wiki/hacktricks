# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

このセクションでは、cryptography challenge に登場するものの、他のカテゴリにはうまく分類できない手法をまとめています。

## 難解言語

### 手法

難解言語のプログラムを実行し、その出力を decode する必要がある challenge では、次のワークフローを使用します。

challenge で標準的な言語に見えない code が与えられた場合:

- 特徴的な token や instruction sequence を検索して、言語を特定します。
- オンライン interpreter または Docker image を使用します。
- 出力が奇妙な場合は、実行後に layered encoding/compression がないか確認します。

便利な言語一覧として、Esolang wiki があります。<sup>[[1]](#references)</sup>

## References

- [1] [Esolang、難解プログラミング言語の wiki](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
