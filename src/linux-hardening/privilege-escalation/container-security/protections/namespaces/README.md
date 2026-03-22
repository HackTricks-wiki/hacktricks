# 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces は、コンテナが「まるで独立したマシンであるかのように」振る舞う原因となるカーネル機能です。実際には単なるホスト上のプロセスツリーに過ぎず、新しいカーネルを作成したりすべてを仮想化したりするわけではありませんが、カーネルが選択したリソースの異なるビューを異なるプロセス群に提示できるようにします。これがコンテナの錯覚の核心です：ワークロードはローカルに見えるファイルシステム、プロセステーブル、ネットワークスタック、ホスト名、IPC リソース、ユーザ／グループのアイデンティティモデルを目にしますが、背後では基盤となるシステムが共有されています。

だからこそ、namespaces はコンテナの仕組みを学ぶ際に最初に出会う概念の一つです。しかし同時に、「namespaces がある＝安全に隔離されている」と読者が誤解しがちなため、最も誤解されやすい概念の一つでもあります。実際には、namespace は当該リソースクラスのみを分離します。プロセスが private な PID namespace を持っていても、書き込み可能なホストの bind mount を持っていれば危険になり得ます。private な network namespace を持っていても、`CAP_SYS_ADMIN` を保持し seccomp なしで動いていれば依然危険です。namespaces は基礎的な要素ですが、最終的な境界の一層に過ぎません。

## Namespace Types

Linux コンテナは通常、複数の namespace 種類を同時に利用します。**mount namespace** はプロセスに別個のマウントテーブルを与え、制御されたファイルシステムビューを提供します。**PID namespace** はプロセスの可視性と番号付けを変更し、ワークロードが自分自身のプロセスツリーを見られるようにします。**network namespace** はインターフェース、ルート、ソケット、ファイアウォール状態を分離します。**IPC namespace** は SysV IPC と POSIX メッセージキューを分離します。**UTS namespace** はホスト名と NIS ドメイン名を分離します。**user namespace** はユーザ／グループ ID をリマップし、コンテナ内の root がホスト上の root を意味しないようにします。**cgroup namespace** は可視 cgroup 階層を仮想化し、**time namespace** は新しいカーネルで選択されたクロックを仮想化します。

これら各 namespace は別々の問題を解決します。だからこそ、実務的なコンテナセキュリティ分析では多くの場合「どの namespace が隔離されているか」「どの namespace が意図的にホストと共有されているか」を確認することに帰着します。

## Host Namespace Sharing

多くのコンテナブレイクアウトはカーネル脆弱性から始まるわけではありません。オペレータが意図的に隔離モデルを弱めることから始まります。例として `--pid=host`、`--network=host`、`--userns=host` はホスト namespace を共有する具体例として使われる、Docker/Podman-style CLI flags です。その他の runtime では同じ考えが別の形で表現されます。Kubernetes では同等の設定が通常 Pod 設定として `hostPID: true`、`hostNetwork: true`、`hostIPC: true` のように現れます。containerd や CRI-O のような低レベルの runtime スタックでは、同じ動作がユーザ向けフラグではなく生成された OCI runtime 設定を通して実現されることが多いです。これらすべての場合において、結果は似ています：ワークロードはもはやデフォルトの隔離された namespace ビューを受け取りません。

だからこそ、namespace のレビューは「プロセスが何らかの namespace にいる」というところで終わるべきではありません。重要な問いは、その namespace がコンテナに対してプライベートか、同居する他のコンテナと共有されているか、あるいは直接ホストに結合されているか、ということです。Kubernetes でも同じ考えが `hostPID`、`hostNetwork`、`hostIPC` のようなフラグで現れます。名前はプラットフォーム間で変わりますが、リスクパターンは同じです：ホストと共有された namespace は、コンテナの残りの権限や到達可能なホスト状態をはるかに意味のあるものにします。

## Inspection

最も簡単な概要は：
```bash
ls -l /proc/self/ns
```
各エントリは inode のような識別子を持つシンボリックリンクです。もし 2 つのプロセスが同じ名前空間識別子を指している場合、それらはそのタイプの同じ名前空間にあります。これにより、`/proc` は現在のプロセスをマシン上の他の興味深いプロセスと比較するのに非常に便利な場所になります。

これらの簡単なコマンドで、まずは十分なことが多い:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
そこからの次のステップは、コンテナプロセスをホストや隣接するプロセスと比較し、その名前空間が実際にプライベートかどうかを判断することです。

### ホスト上で名前空間インスタンスを列挙する

すでにホストにアクセスでき、ある種の名前空間がいくつ存在するかを把握したい場合、`/proc` で簡単に確認できます:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
特定の namespace identifier に属するプロセスを調べたい場合は、`readlink` の代わりに `ls -l` を使い、対象の namespace 番号で grep してください:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
これらのコマンドは、ホストが単一の隔離されたワークロードを実行しているのか、複数の隔離されたワークロードを実行しているのか、あるいは共有とプライベートなnamespaceインスタンスが混在しているのかを判断するのに便利です。

### ターゲットnamespaceに入る

呼び出し元に十分な権限がある場合、`nsenter`は他のプロセスのnamespaceに参加する標準的な方法です:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
これらの形式をまとめて並べているのは、すべての評価がそれらすべてを必要とするという意味ではなく、オペレータが正確なエントリ構文を知っていれば、all-namespaces form のみを覚えている場合に比べて、namespace-specific post-exploitation がしばしばずっと容易になるためです。

## Pages

The following pages explain each namespace in more detail:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

As you read them, keep two ideas in mind. First, each namespace isolates only one kind of view. Second, a private namespace is useful only if the rest of the privilege model still makes that isolation meaningful.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | デフォルトで新しい mount、PID、network、IPC、UTS 名前空間が作成されます。user namespaces は利用可能ですが、標準の rootful セットアップではデフォルトで有効になっていません。 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | デフォルトで新しい名前空間を作成します。rootless Podman は自動的に user namespace を使用します。cgroup namespace のデフォルトは cgroup バージョンに依存します。 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods はデフォルトでホストの PID、network、IPC を共有しません。Pod のネットワーキングは各コンテナ個別ではなく Pod 単位でプライベートです。user namespaces は対応するクラスターで `spec.hostUsers: false` によるオプトインです。 | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | 通常は Kubernetes Pod のデフォルトに従います。 | Kubernetes 行と同様；直接の CRI/OCI spec でもホスト namespace への参加を要求できます。 |

主要な移植性ルールは簡単です: ホスト名前空間共有の**概念**はランタイム間で共通ですが、**構文**はランタイム固有です。
{{#include ../../../../../banners/hacktricks-training.md}}
