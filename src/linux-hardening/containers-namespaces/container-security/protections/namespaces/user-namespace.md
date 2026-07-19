# ユーザー名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ユーザー名前空間は、名前空間内で認識されるユーザー ID とグループ ID を、名前空間外の異なる ID に kernel がマッピングできるようにすることで、その意味を変更します。これは、classic containers における歴史的な最大の問題、つまり **container 内の root が host 上の root と危険なほど近い権限を持っていたこと** に直接対処する、現代の container 保護機能の中でも特に重要なものです。

user namespaces を使用すると、process は container 内で UID 0 として実行されながら、host 上では unprivileged UID range に対応させることができます。つまり、その process は多くの container 内タスクでは root のように動作できる一方、host から見ればはるかに弱い権限しか持ちません。これはすべての container security 問題を解決するわけではありませんが、container compromise の影響を大きく変えます。

## 動作

user namespace には `/proc/self/uid_map` や `/proc/self/gid_map` などの mapping files があり、namespace ID が parent ID にどのように変換されるかを記述しています。namespace 内の root が unprivileged host UID にマッピングされている場合、host の root 権限を必要とする操作は、同じ重みを持たなくなります。これが、user namespaces が **rootless containers** の中心であり、以前の rootful container defaults と、より現代的な least-privilege designs の最大の違いの一つである理由です。

重要な点は微妙ですが、極めて重要です。container 内の root は排除されるのではなく、**変換されます**。process は依然としてローカルでは root に近い環境を利用できますが、host はそれを full root として扱うべきではありません。

## Lab

手動テストは次のとおりです。
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
これにより、現在の user は namespace 内では root として表示されますが、namespace の外側では host root ではない状態が保たれます。user namespace が非常に価値のある理由を理解するための、最も優れたシンプルなデモの一つです。

containers では、次のコマンドで表示される mapping と比較できます：
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
正確な出力は、engine が user namespace remapping を使用しているか、より従来型の rootful configuration を使用しているかによって異なります。

host 側からマッピングを読み取ることもできます：
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman は、user namespace が第一級の security mechanism として扱われている最も明確な例の1つです。Rootless Docker も user namespace に依存しています。Docker の userns-remap サポートは、rootful daemon deployment における安全性も向上させますが、歴史的には compatibility 上の理由から無効のままにされている deployment が多くありました。Kubernetes の user namespace サポートは改善されていますが、採用状況とデフォルト設定は runtime、distro、cluster policy によって異なります。Incus/LXC systems も、UID/GID shifting と idmapping の考え方に大きく依存しています。

全体的な傾向は明らかです。user namespace を本格的に利用する環境は、利用しない環境よりも、「container root は実際には何を意味するのか」という問いに対して、通常はより適切な答えを提供します。

## Advanced Mapping Details

unprivileged process が `uid_map` または `gid_map` に書き込む場合、kernel は privileged parent namespace writer に対する場合よりも厳格なルールを適用します。許可される mapping は限定されており、`gid_map` では通常、writer は最初に `setgroups(2)` を無効化する必要があります。
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
この詳細は重要です。なぜなら、rootless の実験で user namespace のセットアップが失敗することがある理由と、runtime が UID/GID delegation 周辺で慎重な helper logic を必要とする理由を説明しているからです。

もう1つの高度な機能が **ID-mapped mount** です。ディスク上の ownership を変更する代わりに、ID-mapped mount は mount に user namespace の mapping を適用し、その mount view を通して ownership が変換されて見えるようにします。これは rootless および modern runtime setups において特に重要です。再帰的な `chown` 操作を行わずに、共有された host paths を使用できるためです。Security の観点では、この機能によって、基盤となる filesystem metadata を書き換えずに、namespace 内から bind mount がどの程度 writable に見えるかが変わります。

最後に、process が新しい user namespace を作成またはそこへ入ると、**その namespace 内で**完全な capability set を受け取ることを覚えておいてください。これは、host-global な power を突然獲得したという意味ではありません。これらの capabilities は、namespace model とその他の protections によって許可される範囲でのみ使用できます。これが、`unshare -U` によって mount や namespace-local な privileged operations が突然可能になる一方で、host root boundary が直接消失するわけではない理由です。

## 設定ミス

主な weakness は、user namespaces を利用可能な環境で単に使用していないことです。container root が host root に直接 mapping されすぎている場合、writable な host mounts や privileged kernel operations ははるかに危険になります。もう1つの問題は、その trust boundary がどれほど変化するかを認識しないまま、compatibility のために host user namespace sharing を強制したり、remapping を無効化したりすることです。

user namespaces は、model の他の要素と組み合わせて考える必要もあります。user namespaces が有効であっても、広範な runtime API exposure や非常に弱い runtime configuration によって、別の paths から privilege escalation が可能になる場合があります。しかし、user namespaces がなければ、多くの古い breakout classes ははるかに容易に exploit できます。

## Abuse

container が user namespace separation なしの rootful である場合、writable な host bind mount ははるかに危険になります。process が実際に host root として write できる可能性があるためです。危険な capabilities も同様に、より大きな意味を持つようになります。attacker は translation boundary がほとんど存在しないため、その boundary に対してそれほど強く対処する必要がなくなります。

container breakout path を評価する際は、user namespace の有無を早い段階で確認すべきです。これだけですべての疑問に答えられるわけではありませんが、「container 内の root」が host に直接関係するかどうかをすぐに示せます。

最も実用的な abuse pattern は、mapping を確認した直後に、host-mounted content が host-relevant な privileges で writable かどうかをテストすることです。
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
ファイルが実ホストの root として作成される場合、そのパスに対する user namespace の分離は実質的に存在しません。その時点で、従来のホストファイル悪用が現実的になります：
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
実稼働環境での assessment では、critical files を変更する代わりに、無害な marker を書き込むほうが、より安全に confirmation できます：
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
これらのチェックが重要なのは、次の本当の問いに迅速に答えられるからです。このコンテナ内の root は、書き込み可能な host マウントが直ちに host compromise への経路になるほど、host の root に近くマッピングされているか？

### 完全な例: Namespace-Local Capabilities の再取得

seccomp が `unshare` を許可し、環境が新しい user namespace の作成を許可している場合、プロセスはその新しい namespace 内で完全な capability set を再取得できる可能性があります。
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
これは、それ自体が host escape というわけではありません。重要なのは、user namespaces によって namespace 内でのみ有効な特権アクションが再び実行可能になり、それが後に弱い mount、脆弱な kernel、または適切に公開範囲が制限されていない runtime surface と組み合わさる可能性がある点です。

## Checks

これらのコマンドは、このページで最も重要な問いに答えるためのものです。つまり、この container 内部の root は host 上で何にマッピングされているのか、という問いです。
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
ここで重要なのは次の点です。

- プロセスが UID 0 で、maps にホストの root への直接または非常に近いマッピングが示されている場合、そのコンテナははるかに危険です。
- root がホスト上の非特権範囲にマッピングされている場合、これははるかに安全なベースラインであり、通常は実際の user namespace 分離を示します。
- マッピングファイルは `id` だけの場合よりも有用です。`id` は namespace 内でのローカルな identity しか表示しないためです。

workload が UID 0 として実行され、マッピングがそれがホストの root に近いことを示している場合、コンテナの残りの privileges はより厳格に解釈する必要があります。
{{#include ../../../../../banners/hacktricks-training.md}}
