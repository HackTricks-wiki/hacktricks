# ユーザー名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ユーザー名前空間は、名前空間内で見えるユーザーおよびグループのIDをカーネルが外部の別のIDにマッピングすることで、それらの意味を変えます。これは現代のコンテナ保護の中でも最も重要なものの一つで、古典的なコンテナにおける最大の歴史的問題、すなわち **コンテナ内の root はかつてホスト上の root と非常に近かった** に直接対処します。

ユーザー名前空間を使うと、プロセスはコンテナ内で UID 0 として動作していても、ホスト上では権限のない UID 範囲に対応している場合があります。つまり、そのプロセスはコンテナ内の多くのタスクでは root のように振る舞える一方で、ホストから見ればはるかに権限が制限されます。これですべてのコンテナのセキュリティ問題が解決するわけではありませんが、コンテナ侵害の影響を大きく変えます。

## 動作

ユーザー名前空間には `/proc/self/uid_map` や `/proc/self/gid_map` のようなマッピングファイルがあり、名前空間内のIDが親のIDにどう翻訳されるかを記述しています。もし名前空間内の root がホスト上の権限のない UID にマップされていれば、真のホスト root を必要とする操作は同じ重みを持ちません。これが、ユーザー名前空間が **rootless containers** の中心である理由であり、古い rootful なコンテナのデフォルトと、より近代的な最小権限設計との最大の違いの一つである理由です。

要点は微妙だが重要です: コンテナ内の root は消滅するのではなく、**翻訳**されます。プロセスはローカルでは引き続き root のような環境を体験しますが、ホストはそれを完全な root として扱うべきではありません。

## ラボ

手動テストは:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
これにより、現在のユーザーは namespace 内では root として見えますが、外側のホストでは引き続き root ではありません。これは user namespaces がなぜこれほど有用かを理解するための最も単純かつ優れたデモの一つです。

コンテナ内では、表示されるマッピングを次と比較できます:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
正確な出力は、エンジンが user namespace remapping を使用しているか、より従来型の rootful 構成かによって異なります。

ホスト側からマッピングを読み取ることもできます:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## ランタイムでの利用

Rootless Podman は、ユーザー名前空間を第一級のセキュリティ機構として扱う最も明確な例の一つです。Rootless Docker もそれらに依存します。Docker の userns-remap サポートは、rootful なデーモン環境でも安全性を向上させますが、歴史的に多くのデプロイメントでは互換性の理由から無効化されていました。Kubernetes のユーザー名前空間に対するサポートは改善されていますが、採用状況やデフォルト設定はランタイム、ディストロ、クラスターのポリシーによって異なります。Incus/LXC システムも UID/GID のシフトや idmapping の考え方に大きく依存しています。

傾向は明らかです: ユーザー名前空間を真剣に使う環境は、使わない環境よりも「コンテナ内の root は実際に何を意味するのか？」に対してより妥当な答えを提示する傾向があります。

## 高度なマッピングの詳細

非特権プロセスが `uid_map` または `gid_map` に書き込むと、カーネルは特権を持つ親名前空間の書き手に比べて厳しいルールを適用します。許可されるマッピングは限定されており、`gid_map` の場合、書き手は通常まず `setgroups(2)` を無効化する必要があります：
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
この点は、user-namespace の設定が rootless な実験で時々失敗する理由と、なぜ runtimes が UID/GID の委譲に関して慎重なヘルパーロジックを必要とするかを説明するため重要です。

Another advanced feature is the **ID-mapped mount**. ディスク上の所有権を書き換える代わりに、ID-mapped mount はマウントに user-namespace のマッピングを適用し、そのマウントのビュー越しに所有権が翻訳されて見えるようにします。これは、recursive `chown` 操作なしに共有された host パスを使えるようにするため、rootless やモダンな runtime セットアップで特に重要です。セキュリティの観点では、この機能は基盤となる filesystem metadata を書き換えなくても、namespace 内から見た bind mount の書き込み可能性の見え方を変えます。

最後に、プロセスが新しい user namespace を作成または参加すると、そのプロセスは **inside that namespace** で完全な capability セットを受け取ることを忘れないでください。これは、突然ホスト全体の権限を得たという意味ではありません。これらの capability は namespace モデルや他の保護が許す範囲でのみ使えるという意味です。これが `unshare -U` がホスト側の root 境界を直接消すことなく、マウントやnamespace ローカルの特権操作を突然可能にする理由です。

## Misconfigurations

主な弱点は、利用可能な環境で user namespaces を単に使っていないことです。container root が host root にあまりにも直接的にマップされていると、書き込み可能な host mounts や特権付きのカーネル操作ははるかに危険になります。もう一つの問題は、互換性のために host user namespace の共有を強制したり remapping を無効化したりして、信頼境界がどれほど変わるかを認識していないことです。

User namespaces はモデルの他の部分と合わせて考慮する必要もあります。たとえ有効でも、広範な runtime API の露出や非常に弱い runtime 設定は、他の経路を通じた privilege escalation を許すことがあります。しかし user namespaces がないと、多くの古い breakout クラスはずっと exploit しやすくなります。

## Abuse

コンテナが user namespace 分離なしで rootful な場合、書き込み可能な host bind mount ははるかに危険になります。プロセスが実際に host root として書き込んでいる可能性があるためです。危険な capabilities も同様により意味を持ちます。攻撃者は翻訳境界と闘う必要がほとんどなくなります。なぜなら翻訳境界自体がほとんど存在しないからです。

container breakout 経路を評価する際には、User namespace の有無を早期に確認するべきです。これはすべての疑問に答えるわけではありませんが、「root in container」がホストに直接関係するかどうかを即座に示します。

最も実用的な悪用パターンは、まずマッピングを確認し、その後すぐに host-mounted コンテンツが host-relevant な権限で書き込み可能かどうかをテストすることです：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
そのファイルが実際のホスト root として作成されている場合、そのパスに対する user namespace isolation は事実上存在しません。その時点で、古典的な host-file abuses が現実的になります:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
本番での評価時には、重要なファイルを変更する代わりに、無害なマーカーを書き込むことで安全に確認できます：
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
これらのチェックは重要です。なぜなら、本当の問いに素早く答えるからです: このcontainer内のrootはhostのrootに十分近いマッピングになっており、writable host mountが即座にhost compromise pathになるかどうか？

### 完全な例: Regaining Namespace-Local Capabilities

もし seccomp が `unshare` を許可し、環境が新しい user namespace を許可するなら、プロセスはその新しい namespace 内で full capability set を再獲得する可能性があります:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
これはそれ自体では host escape ではありません。重要な点は、ユーザー名前空間 (user namespaces) が特権のあるネームスペース内操作を再有効化でき、それが後に脆弱なマウント、脆弱なカーネル、あるいは露出したランタイムのインターフェースと組み合わさる可能性がある、ということです。

## チェック

これらのコマンドは、このページで最も重要な質問に答えるためのものです: このコンテナ内の root はホスト上で何にマップされていますか？
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
ここで興味深い点：

- プロセスが UID 0 で、マッピングがホスト root への直接的または非常に近い対応を示している場合、コンテナははるかに危険です。
- root が非特権のホスト範囲にマップされている場合、それはより安全なベースラインであり、通常は真のユーザー名前空間の分離を示します。
- マッピングファイルは `id` 単独よりも価値があります。`id` は名前空間ローカルの識別情報しか示さないため。

ワークロードが UID 0 として実行され、マッピングがこれがホストの root に密接に対応していることを示す場合、コンテナの他の権限はより厳格に解釈するべきです。
{{#include ../../../../../banners/hacktricks-training.md}}
