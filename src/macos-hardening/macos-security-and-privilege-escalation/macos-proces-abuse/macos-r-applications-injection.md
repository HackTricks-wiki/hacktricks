# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

起動時に、RはRコードを含むsiteおよびuser profileファイルを読み込みます。`R_PROFILE`はsite profileを選択し、`R_PROFILE_USER`はuser profileを選択するため、継承された環境変数によって、いずれかの検索先を攻撃者が読み取り可能なファイルへリダイレクトできます。<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` はユーザープロファイルをスキップし、`--no-site-file` はサイトプロファイルをスキップします。`--vanilla` には両方の保護が含まれます。R はまず、`R_ENVIRON` と `R_ENVIRON_USER` によって選択された環境ファイルを処理しますが、これらのファイルは変数を設定するだけです。プロファイル変数が、任意コード実行の直接的なプリミティブになります。

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` とライブラリパス

R は起動時に、`R_DEFAULT_PACKAGES` に含まれるカンマ区切りのパッケージを attach します。`Rscript` では `R_SCRIPT_DEFAULT_PACKAGES` が優先されます。いずれかの変数を `R_LIBS`、`R_LIBS_USER`、または `R_LIBS_SITE` と組み合わせると、R に攻撃者が管理するインストール済みパッケージを検索・ロードさせることができます。その `.onLoad` または `.onAttach` hook は自動的に実行されます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
これは、単なる独立した `.R` ファイルではなく、構造的に有効なインストール済み R package を必要とします。`--vanilla` は直接継承された変数をクリアしないため、信頼できる wrapper では、profile ファイルを無効化するだけでなく、default-package と library-path の変数も unset または置換する必要があります。

## References

- [1] [R セッション開始時の初期化](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R のインストールと管理: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
