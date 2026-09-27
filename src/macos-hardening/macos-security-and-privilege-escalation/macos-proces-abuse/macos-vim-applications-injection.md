# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Vim独自のスクリプト言語（Vimscript）は、環境変数から起動時に**任意のExコマンドおよびシェルコマンドを実行**できます。より高い権限を持つプロセス（メンテナンス/rootワークフロー、`sudo vim …`、別のツールによって起動されたエディタ、`crontab -e`、`visudo`、エディタを呼び出す`git`/`less`など）が、攻撃者の影響を受けた環境でVim/Neovimを起動すると、攻撃者はそのコンテキストでコード実行を行えます。

## `VIMINIT`

初期化中、Vimは**`VIMINIT`**内のExコマンドを読み込み、実行します。Exコマンドには`:!cmd`（シェルコマンドを実行）や`:call system(...)`が含まれるため、ファイルが編集される前に、1つの変数だけで任意の実行が可能になります。<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
最初の例で stdin に渡された `:qa!` は、payload の実行後に editor を閉じるだけです。実際のシナリオでは、victim は通常どおり Vim を開けます。

`VIMINIT` は **1 行の Ex command line** として解析されます。`|`（またはリテラルの改行）でチェーンを区切ります。これはユーザーの vimrc と `EXINIT` よりも優先されるため、payload の実行に悪意のある configuration file は必要なく、通常の user configuration より前に実行されます。<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

`VIMINIT` が設定されていない場合、Vim（および `vi`/`ex` compatibility binaries）は **`EXINIT`** にフォールバックし、同じ方法で実行します。これは、同じ primitive の古典的な vi-era variant です。<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Startup suppression and exploitability

この primitive は **normal startup** に依存します。`vim -u NONE` / `nvim -u NONE` は環境およびユーザーの初期化処理（および plugins）をスキップし、`-u <file>` は代わりにそのファイルを使用します。Vim の `-es` / `-Es` と Neovim の `-es`、`-Es`、`-l` も、これらの初期化手順をスキップします。`--headless` を safe mode と取り違えないでください。通常の Neovim headless startup では、依然として `VIMINIT` が処理されます。<sup>[[1]](#references)[[2]](#references)</sup>

したがって、完全な launch chain を検証してください。変数は wrapper、`sudo` policy、job runner、editor selection を通過して保持される必要があり、最終 command では `-u NONE` / `NORC` や batch mode を強制してはなりません。信頼性のある payload は `|qall!` で自身を終了させることができるため、TTY を提供しない wrappers のテストも容易になります。<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

別の Neovim injection primitive は、Lua の `package.path` / `package.cpath` に `./?.lua` や `./?.so` のような current-directory templates が依然として含まれている build に影響します。Neovim を起動するだけでは不十分です。config または plugin が `require("name")` を呼び出す必要があり、さらに、それより前の loader がその name を解決していない必要があります。一般的な trigger は **optional dependency check** である `pcall(require, "optional_dep")` です。攻撃者が制御する working directory に `optional_dep.lua` を配置すると、独立した `'exrc'` local-configuration feature を有効にせずに、そのファイルが実行されます。core の `vim.*` modules や `'runtimepath'` 上ですでに見つかる modules は、一般に shadowing できません。そのため、名前を推測するのではなく、実際に不足している、または optional な `require()` calls を列挙してください。<sup>[[3]](#references)</sup>

以下では、無害な marker を使用して loader primitive を再現します。<sup>[[3]](#references)</sup>
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
バージョン文字列だけに依存せず、実行中のビルドを確認します:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream は、通常の editor startup 時における current-directory fallback の削除を追跡していますが、Lua-script（`nvim -l`）の動作は維持しています。インストール済みの build がこの動作を公開しなくなるまで、これを `init.lua` の**先頭**に配置してください（これは相対的な current-directory Lua/C module templates を意図的に削除するため、それらを必要とする workflow には適用しないでください）：<sup>[[3]](#references)</sup>
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
## 注意事項と留意点

- **Neovim** は `VIMINIT` とフォールバックの `EXINIT` の両方を使用しますが、通常のユーザー設定ファイルは `init.vim` または `init.lua` です。<sup>[[2]](#references)</sup>
- 環境変数を使用する方法では、書き込み可能なファイルは不要です。ローカル rc とカレントディレクトリのモジュール hijacking は、別個のファイルベースのプリミティブです。<sup>[[1]](#references)[[3]](#references)</sup>
- プロジェクトローカル設定は modeline とは異なる攻撃対象です。Vim で `'exrc'` が有効な場合、別のユーザーが所有するローカル vimrc/exrc は `'secure'` による制限下で実行されます。ただし、通常どおり archive を展開すると、仕込まれたファイルは被害者の所有となり、この所有者ベースの保護を回避できます。Neovim も `'exrc'` が有効な場合は `.nvim.lua`、`.nvimrc`、または `.exrc` を検索します。これを、前述した `require()` のカレントディレクトリフォールバックと混同しないでください。前者は明示的な opt-in メカニズムです。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- エディター選択用の変数は、起動するプログラムを選択するだけであり、`VIMINIT` が最終プロセスに到達することを保証しません。Vim/Neovim の exec 境界で、正確な環境変数と引数を確認してください。<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- 特権付きまたは自動化されたエディター起動の前に、変数を明示的に削除します: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`。呼び出し元がすべてのユーザー startup source を無視する必要がある場合、`-u NONE` は重要です。<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL` には信頼できる絶対パスを設定し、継承されたユーザー環境で root として interactive editor を実行しないようにし、sanitization 後に wrapper が `VIMINIT`/`EXINIT` を復元できないようにします。<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim では、editor mode 中にカレントディレクトリの Lua/C search template を削除する build に更新するか、plugin のロード前にそれらを除去します。信頼できない repository を開く際は、optional な `pcall(require, ...)` 呼び出しについて plugin code を監査してください。<sup>[[3]](#references)</sup>
- 対象の editor environment、working directory、または startup configuration を制御できることは、editor の security context における code-execution primitive となる可能性があるものとして扱ってください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim ドキュメント — `starting.txt`（初期化、`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim ドキュメント — startup と初期化](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` におけるカレントディレクトリフォールバック](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
