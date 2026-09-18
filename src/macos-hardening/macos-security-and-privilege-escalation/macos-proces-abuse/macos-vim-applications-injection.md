# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Vim 自体の scripting language（Vimscript）は、環境変数から起動時に **任意の Ex commands と shell commands** を実行できます。より高い権限を持つプロセス（maintenance/root workflow、`sudo vim …`、別のツールによって起動された editor、`crontab -e`、`visudo`、editor を呼び出す `git`/`less` など）が attacker の影響を受けた environment で Vim/Neovim を起動すると、attacker はその context で code execution を実行できます。

## `VIMINIT`

初期化中、Vim は **`VIMINIT`** 内の Ex commands を読み込み、実行します。Ex commands には `:!cmd`（shell command の実行）や `:call system(...)` が含まれるため、1 つの変数だけで、ファイルが編集される前に任意の実行が可能になります。<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
標準入力から渡された `:qa!` は、payload の実行後にエディタを閉じるだけです。実際のシナリオでは、victim は単に Vim を通常どおり開きます。

## `EXINIT`

`VIMINIT` が設定されていない場合、Vim（および `vi`/`ex` 互換バイナリ）は **`EXINIT`** にフォールバックし、同じ方法で実行します。これは、同じ primitive の古典的な vi 時代のバリエーションです。<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notes and caveats

- **Neovim** も `VIMINIT` を尊重します（ユーザーの `init.vim`/`init.lua` より前に確認されます）。
- Batch/Ex mode（`vim -es` / `vim -Es`）では **`VIMINIT`/`EXINIT` は source されません**。これらの変数は通常の（interactive な）startup で実行されます。これは一般的な被害シナリオです。
- 関連する file-based vector には、ディレクトリごとの `exrc`/`.nvimrc` の "modeline"/local-rc 機能や `-u <vimrc>` があります。上記の environment-variable path では writable な file は一切必要ありません。

## Hardening

- privileged または automated な context から editor を起動する前に environment を sanitize し（`VIMINIT`/`EXINIT` を削除）、environment を reset する `sudo -i`/`env -i` wrapper を優先してください。
- `EDITOR`/`VISUAL` には trusted な absolute path を設定し、inherited user environment を使って editor を root として実行することを避けてください。
- target の environment を control できることは、その target が spawn する Vim/Neovim に対する code execution と同等に扱ってください。

## References

- [1] [Vim documentation — `starting.txt`（initialization、`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
