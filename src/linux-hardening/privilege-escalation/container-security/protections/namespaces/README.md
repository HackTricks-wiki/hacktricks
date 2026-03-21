# 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

名前空間は、コンテナが「自分専用のマシン」のように見えるようにするカーネルの機能です。実際にはホストのプロセスツリーにすぎず、新しいカーネルを作成したりすべてを仮想化したりするわけではありませんが、カーネルが選択されたリソースについて異なるプロセス群に異なるビューを提示できるようにします。これがコンテナの錯覚の中核です：ワークロードはファイルシステム、プロセステーブル、ネットワークスタック、ホスト名、IPCリソース、ユーザ/グループの識別モデルをローカルに見えるようにしますが、基盤となるシステムは共有されています。

このため、名前空間はコンテナの仕組みを学ぶ際に多くの人が最初に遭遇する概念です。同時に、「名前空間がある＝安全に隔離されている」と誤解されやすい最も一般的な概念の一つでもあります。実際には、名前空間は設計された特定のリソースのクラスのみを分離します。プロセスがプライベートな PID 名前空間を持っていても、書き込み可能なホストのバインドマウントがあるために危険なままであることがあります。プライベートな network 名前空間を持っていても、`CAP_SYS_ADMIN` を保持し seccomp を無効にして実行していれば危険であり続けます。名前空間は基盤ですが、最終的な境界の一層にすぎません。

## 名前空間の種類

Linux コンテナは通常、複数の名前空間タイプを同時に利用します。**mount namespace** はプロセスに別個のマウントテーブルを与え、それによって制御されたファイルシステムビューを提供します。**PID namespace** はプロセスの可視性と番号付けを変更し、ワークロードが独自のプロセスツリーを見られるようにします。**network namespace** はインターフェース、ルート、ソケット、ファイアウォール状態を分離します。**IPC namespace** は SysV IPC と POSIX メッセージキューを分離します。**UTS namespace** はホスト名と NIS ドメイン名を分離します。**user namespace** はユーザおよびグループ ID をリマップすることで、コンテナ内の root が必ずしもホストの root を意味しないようにします。**cgroup namespace** は表示される cgroup 階層を仮想化し、**time namespace** は新しいカーネルで選択されたクロックを仮想化します。

これらの名前空間はそれぞれ別の問題を解決します。実務的なコンテナセキュリティ分析は、多くの場合「どの名前空間が分離されているか」と「どの名前空間が意図的にホストと共有されているか」を確認することに帰着します。

## ホスト名前空間の共有

多くのコンテナブレイクアウトはカーネル脆弱性から始まるわけではありません。隔離モデルを意図的に弱めたオペレータから始まります。例として `--pid=host`、`--network=host`、`--userns=host` はここでホスト名前空間共有の具体例として使われる **Docker/Podman-style CLI flags** です。他のランタイムは同じアイデアを異なる方法で表現します。Kubernetes では同等のものが通常 `hostPID: true`、`hostNetwork: true`、`hostIPC: true` といった Pod 設定として現れます。containerd や CRI-O のような低レベルのランタイムスタックでは、ユーザ向けの同名フラグではなく生成された OCI runtime configuration を通じて同じ挙動が達成されることが多いです。いずれの場合も結果は似ています：ワークロードはもはやデフォルトの分離された名前空間ビューを受け取りません。

このため、名前空間のレビューは「プロセスが何らかの名前空間にいる」というところで終わってはいけません。重要な質問は、その名前空間がコンテナに対してプライベートなのか、同じレベルの他コンテナと共有されているのか、あるいはホストに直接結合されているのか、という点です。Kubernetes では同じ考えが `hostPID`、`hostNetwork`、`hostIPC` といったフラグで現れます。プラットフォーム間で名前は変わりますが、リスクのパターンは同じです：ホストと共有された名前空間は、コンテナの残存権限や到達可能なホスト状態の重要性を格段に高めます。

## 検査

最も簡単な概観は次のとおりです：
```bash
ls -l /proc/self/ns
```
各エントリは symbolic link で、inode-like identifier を持ちます。もし2つのプロセスが同じ namespace identifier を指していれば、それらはそのタイプの同じ namespace に属します。  
そのため `/proc` は、現在のプロセスとマシン上の他の興味深いプロセスを比較するのに非常に便利な場所になります。

これらの簡単なコマンドで始めるには十分なことが多い：
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
そこから次のステップは、コンテナのプロセスをホストや隣接するプロセスと比較し、その namespace が実際にプライベートかどうかを判断することです。

### Enumerating Namespace Instances From The Host

既にホストにアクセスできていて、あるタイプの異なる namespace がいくつ存在するかを把握したい場合、`/proc` は手早く一覧を示してくれます:
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
特定の namespace 識別子に属するプロセスを見つけたい場合は、`readlink` ではなく `ls -l` を使用し、ターゲットの namespace 番号で grep してください:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
これらのコマンドは、ホストが単一の隔離されたワークロードを実行しているのか、複数の隔離されたワークロードを実行しているのか、あるいは共有とプライベートのnamespaceインスタンスが混在しているのかを判断するのに有用です。

### ターゲット名前空間に入る

呼び出し元に十分な特権がある場合、`nsenter` は別プロセスの namespace に参加する標準的な方法です:
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
これらの形式をまとめて列挙している目的は、すべての評価がそれらすべてを必要とするということではなく、オペレータが正確なエントリ構文を知っていれば、名前空間固有の post-exploitation は all-namespaces 形式だけを覚えている場合よりもずっと容易になることが多い、という点です。

## Pages

次のページでは各名前空間について詳しく説明します:

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

これらを読むときは2つの考えを念頭に置いてください。第一に、各名前空間は1種類のビューのみを分離します。第二に、プライベートな名前空間が役に立つのは、権限モデルの残りがその分離を依然として意味のあるものにしている場合だけです。

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | 新しい mount、PID、network、IPC、および UTS 名前空間がデフォルトで作成されます；user 名前空間は利用可能ですが、標準の rootful セットアップではデフォルトで有効にはなっていません | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | デフォルトで新しい名前空間を作成します；rootless Podman は自動的に user 名前空間を使用します；cgroup 名前空間のデフォルトは cgroup のバージョンによります | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods はデフォルトでホストの PID、network、または IPC を共有しません；Pod のネットワーキングは Pod 単位でプライベートであり、個々のコンテナごとではありません；user 名前空間は、サポートされるクラスターで `spec.hostUsers: false` によってオプトインされます | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user 名前空間のオプトインを省略、privileged なワークロード設定 |
| containerd / CRI-O under Kubernetes | 通常は Kubernetes の Pod デフォルトに従います | Kubernetes 行と同じ；直接の CRI/OCI スペックでもホスト名前空間参加を要求できます |

主な移植性ルールは簡単です: ホスト名前空間の共有という概念はランタイム間で共通ですが、構文はランタイム固有です。
