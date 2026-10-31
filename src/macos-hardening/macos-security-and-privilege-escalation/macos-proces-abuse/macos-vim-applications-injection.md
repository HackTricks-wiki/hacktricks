# macOS Vim/Neovim アプリケーションへのインジェクション

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Vim 独自のスクリプト言語（Vimscript）は、起動時に環境変数から**任意の Ex コマンドやシェルコマンドを実行**できます。より高い権限を持つプロセス（メンテナンス/root のワークフロー、`sudo vim …`、別のツールが起動したエディタ、`crontab -e`、`visudo`、エディタを呼び出す `git`/`less` など）が、攻撃者の影響を受けた環境変数を使って Vim/Neovim を起動すると、攻撃者はその実行コンテキストでコード実行できます。

## `VIMINIT`

初期化時に Vim は **`VIMINIT`** 内の Ex コマンドを読み込んで実行します。Ex コマンドには `:!cmd`（シェルコマンドを実行）や `:call system(...)` が含まれるため、この変数ひとつで、ファイルを編集する前に任意のコードを実行できます。<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

最初の例で stdin から渡された `:qa!` は、payload の実行後にエディタを閉じるだけです。実際のシナリオでは、被害者は通常どおり Vim を開くことができます。

`VIMINIT` は**1つの Ex コマンドライン**として解析されます。コマンドを連結するには `|`（または改行文字）を使います。ユーザーの vimrc と `EXINIT` より優先されるため、payload に悪意のある設定ファイルは不要で、通常のユーザー設定より前に実行されます。<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

`VIMINIT` が設定されていない場合、Vim（および `vi`/`ex` 互換バイナリ）は**`EXINIT`**にフォールバックし、同じ方法で実行します。これは、同じプリミティブの vi 時代からある古典的なバリアントです。<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Vimの`exrc`を使ったプロジェクトローカルのrc

これは`VIMINIT`に代わる、ファイルベースの方法です。被害者がユーザー設定で`set exrc`を有効にしている場合、Vimは編集対象ファイルのディレクトリだけでなく、**作業ディレクトリ**からも`.vimrc`（続いて`_vimrc`または`.exrc`）を読み込みます。プロジェクトにローカルの`.vimrc`を配置し、被害者にそのプロジェクトからVimを起動させます。Unixでは、Vimは他人が所有するローカルrcに`secure`制限を適用しますが、被害者が展開したアーカイブ内のファイルは通常、被害者の所有となるため、このチェックを回避できます。<sup>[[1]](#references)</sup>

この独立したマーカーは、実際のユーザー設定を変更せずに起動トリガーを示します。<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim は異なります。現在のビルドでは、プロジェクト内の `.nvim.lua`、`.nvimrc`、または `.exrc` を実行する前に信頼する必要があります。信頼状態はファイルのコンテンツハッシュに基づくため、信頼済みファイルを変更すると、再度信頼するかどうかの判断が求められます。リポジトリにファイルを置けるだけの攻撃者は、`exrc` によって確認なしに実行されるとは想定できません。このオプトインが必要な、信頼によって制御される経路と、後述するカレントディレクトリからの Lua `require()` 経路を区別してください。<sup>[[4]](#references)[[5]](#references)</sup>

プロジェクト内のファイルではなく、書き込み可能な**ユーザー**の vimrc については、[macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration) を参照してください。

## 起動抑止と悪用可能性

このプリミティブは**通常の起動**に依存します。`vim -u NONE` / `nvim -u NONE` は環境設定とユーザー初期化（およびプラグイン）をスキップし、`-u <file>` は代わりにそのファイルを使います。Vim の `-es`/`-Es` と Neovim の `-es`、`-Es`、または `-l` も、これらの初期化手順をスキップします。`--headless` を安全なモードと誤解しないでください。通常の Neovim の headless 起動では、`VIMINIT` が引き続き処理されます。<sup>[[1]](#references)[[2]](#references)</sup>

したがって、起動チェーン全体を検証してください。変数がラッパー、`sudo` ポリシー、ジョブランナー、エディターの選択を通過して保持され、最終的なコマンドが `-u NONE`/`NORC` やバッチモードを強制しないことを確認します。信頼性の高いペイロードは `|qall!` で自身を終了できるため、TTY を提供しないラッパーのテストも容易になります。<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim のカレントディレクトリ Lua モジュールハイジャック

別の Neovim インジェクションプリミティブは、Lua の `package.path`/`package.cpath` に `./?.lua` や `./?.so` などのカレントディレクトリ用テンプレートが残っているビルドに影響します。Neovim を起動するだけでは不十分です。設定またはプラグインが `require("name")` を呼び出し、それ以前のローダーがその名前を解決していない必要があります。よくあるトリガーは `pcall(require, "optional_dep")` のような**オプション依存関係の確認**です。攻撃者が制御する作業ディレクトリに `optional_dep.lua` を置くと、別機能である `'exrc'` のローカル設定を有効にせずに、そのファイルを実行できます。コアの `vim.*` モジュールや、`'runtimepath'` 上ですでに見つかるモジュールは、一般にシャドウできません。そのため、名前を推測するのではなく、実際に欠落している／オプション扱いの `require()` 呼び出しを列挙してください。<sup>[[3]](#references)</sup>

以下では、無害なマーカーを使ってローダーのプリミティブを再現します。<sup>[[3]](#references)</sup>

```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```

実行中のビルドを確認し、バージョン文字列だけに頼らないでください:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstreamでは、通常のエディター起動時にカレントディレクトリーへのフォールバックを削除しつつ、Luaスクリプト（`nvim -l`）の動作は維持する変更が進められています。インストール済みビルドでこの機能が公開されなくなるまでは、これを`init.lua`の**先頭**に配置してください（相対パスのカレントディレクトリーにあるLua/Cモジュールのテンプレートを意図的に削除するため、それらを必要とするワークフローには適用しないでください）：<sup>[[3]](#references)</sup>

```lua
local function drop_cwd(path)
  local keep = {}
  for entry in path:gmatch("[^;]+") do
    if not entry:match("^%./") then keep[#keep + 1] = entry end
  end
  return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```

## Notes and caveats

- **Neovim** は `VIMINIT` と `EXINIT` のフォールバックの両方を尊重しますが、通常のユーザー設定ファイルは `init.vim` または `init.lua` です。<sup>[[2]](#references)</sup>
- 環境変数を使う方法では、書き込み可能なファイルは不要です。ローカル rc とカレントディレクトリの module hijacking は、それぞれ別のファイルベースの手法です。<sup>[[1]](#references)[[3]](#references)</sup>
- プロジェクトローカルの rc ファイルは、modelines や前述の `require()` のカレントディレクトリフォールバックとは異なります。Vim と Neovim ではチェック方法が異なるため、前述のプロジェクトローカル `exrc` の手順を参照してください。<sup>[[1]](#references)[[4]](#references)</sup>
- エディター選択用の変数は、起動するプログラムを選ぶだけであり、`VIMINIT` が最終プロセスに引き継がれることを保証しません。Vim/Neovim の exec 境界で、実際の環境変数と引数を確認してください。<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- 特権付きのエディター起動や自動化されたエディター起動の前に、変数を明示的に削除してください: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`。呼び出し元がすべてのユーザー起動元を無視する必要がある場合は、`-u NONE` が重要です。<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL` には信頼できる絶対パスを設定し、ユーザー環境を引き継いだ状態で root として対話型エディターを実行することを避け、サニタイズ後にラッパーが `VIMINIT`/`EXINIT` を復元できないようにしてください。<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim では、エディターモード中にカレントディレクトリの Lua/C 検索テンプレートを削除するビルドに更新するか、プラグインを読み込む前にそれらを取り除いてください。信頼できないリポジトリを開く際は、省略可能な `pcall(require, ...)` 呼び出しがないかプラグインのコードを監査してください。<sup>[[3]](#references)</sup>
- 対象のエディター環境、作業ディレクトリ、または起動設定を制御できる場合、エディターのセキュリティコンテキストでの code execution 手段となる可能性があるものとして扱ってください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim ドキュメント — `starting.txt` (初期化、`VIMINIT`、`EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim ドキュメント — 起動と初期化](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` のカレントディレクトリフォールバック](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim オプション — プロジェクトローカルの `exrc` と信頼要件](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim 編集 — 信頼済みファイルと `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
