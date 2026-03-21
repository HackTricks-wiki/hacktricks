# ユーザー名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

ユーザー名前空間は、カーネルが名前空間内で見えるユーザーIDとグループIDを外側の異なるIDへマップすることで、これらの意味を変更します。これはモダンなコンテナ保護の中でも最も重要なものの一つであり、古典的なコンテナにおける最大の歴史的問題、すなわち **コンテナ内の root はホスト上の root と非常に近い存在だった** に直接対処します。

ユーザー名前空間を使えば、プロセスはコンテナ内で UID 0 として実行されつつ、ホスト上では権限の低い UID 範囲に対応していることがあります。つまり、そのプロセスはコンテナ内の多くのタスクでは root のように振る舞える一方で、ホスト側から見ればずっと権限が制限されます。すべてのコンテナのセキュリティ問題を解決するわけではありませんが、コンテナが侵害された場合の影響を大きく変えます。

## 動作

ユーザー名前空間には、`/proc/self/uid_map` や `/proc/self/gid_map` のようなマッピングファイルがあり、名前空間内のIDが親のIDへどのように翻訳されるかを記述します。名前空間内の root が権限の低いホストUIDへマップされている場合、ホストの真の root を必要とする操作は同じ重みを持ちません。これがユーザー名前空間が **rootless containers** の中心である理由であり、また古い rootful なコンテナのデフォルトと現代の最小権限設計との最大の違いの一つである理由です。

要点は微妙だが重要です: コンテナ内の root は排除されるわけではなく、**翻訳されている**のです。プロセスはローカルでは依然として root のような環境を体験しますが、ホストはそれを完全な root として扱うべきではありません。

## ラボ

手動でのテストは次の通りです:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
これにより、現在のユーザーは名前空間内では root として見えますが、外側のホストではホストの root ではありません。これは、ユーザー名前空間がなぜこれほど有用なのかを理解するための最も単純なデモのひとつです。

コンテナ内では、見えているマッピングを次と比較できます:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
出力は、engine が user namespace remapping を使用しているか、より伝統的な rootful 構成かによって異なります。

また、host 側からマッピングを次のように読み取ることもできます:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## ランタイムでの利用

Rootless Podman は、ユーザー名前空間を第一級のセキュリティ機構として扱う最も明確な例の一つです。Rootless Docker もそれらに依存します。Docker の userns-remap サポートは rootful なデーモン運用における安全性も向上させますが、互換性の理由で歴史的に多くの導入で無効にされていました。Kubernetes によるユーザー名前空間のサポートは改善されていますが、採用率やデフォルト設定はランタイム、ディストロ、クラスタポリシーによって異なります。Incus/LXC システムも UID/GID shifting と idmapping の考え方に大きく依存しています。

一般的な傾向は明らかです: ユーザー名前空間を真剣に使っている環境は、使っていない環境よりも「コンテナ内の root は実際に何を意味するのか？」という問いに対してより良い答えを提供することが多い。

## 高度なマッピングの詳細

非特権プロセスが `uid_map` や `gid_map` に書き込むと、カーネルは特権を持つ親名前空間の書き手に対する場合より厳しいルールを適用します。許可されるマッピングは制限され、`gid_map` の場合は通常、書き込み前に `setgroups(2)` を無効にする必要があります:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
この点が重要なのは、user-namespace セットアップが rootless の実験で時々失敗する理由と、runtimes が UID/GID の委譲まわりで慎重なヘルパーロジックを必要とする理由を説明するからだ。

もう一つの高度な機能は **ID-mapped mount** だ。オンディスクの所有権を書き換える代わりに、ID-mapped mount は user-namespace mapping をマウントに適用し、そのマウント越しに所有権が翻訳されて見えるようにする。これは、shared host paths を再帰的な `chown` 操作なしに使えるようにするため、rootless や現代の runtime セットアップで特に重要だ。セキュリティ的には、この機能は基盤となる filesystem metadata を書き換えないものの、namespace 内部から見た bind mount の書き込み可能性の見え方を変える。

最後に、プロセスが新しい user namespace を作成するか入ると、**inside that namespace** では完全な capability セットを受け取ることを覚えておいてほしい。これは突然ホスト全体の権力を得るという意味ではない。これらの capability は namespace モデルや他の保護が許す範囲でのみ使えるということだ。これが `unshare -U` がホスト root 境界を直接消すことなく、マウントやnamespace‑ローカルな特権操作を急に可能にする理由である。

## 誤設定

主な弱点は、使用可能な環境で user namespaces を単に使っていないことだ。もし container root が host root に過度に直接マッピングされていると、writable host mounts や privileged kernel operations ははるかに危険になる。もう一つの問題は、互換性のために host user namespace sharing を強制したり remapping を無効にすることで、どれほど信頼境界が変わるかを認識していないことだ。

User namespaces はモデルの他の部分と合わせて考慮する必要がある。たとえ有効でも、広範な runtime API の公開や非常に弱い runtime 設定は、他の経路による privilege escalation を許す可能性がある。しかしそれらがなければ、多くの古い breakout クラスはずっと exploit しやすくなる。

## 悪用

container が user namespace separation なしで rootful な場合、writable host bind mount はプロセスが実際に host root として書き込んでいる可能性があるため、はるかに危険になる。危険な capabilities も同様に意味を持つようになる。攻撃者は翻訳境界とそれほど戦う必要がなくなる、なぜなら翻訳境界はほとんど存在しないからだ。

User namespace の有無は、container breakout path を評価する際に早い段階で確認されるべきだ。すべての問いに答えるわけではないが、「root in container」が直接 host に関係するかどうかを即座に示す。

最も実用的な悪用パターンは、マッピングを確認してから直ちに host-mounted コンテンツが host-relevant privileges で書き込み可能かどうかをテストすることだ：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
ファイルが実際のホストの root として作成されている場合、そのパスに対するユーザー名前空間の隔離は事実上無効になります。その時点で、従来のホストファイルの悪用が現実味を帯びます:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
ライブアセスメントでのより安全な確認方法は、重要なファイルを変更する代わりに無害なマーカーを書き込むことです:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
これらのチェックが重要なのは、次の実際の問いに素早く答えるためです: このcontainer内のrootはhostのrootに十分に近くマップされており、writable host mountが即座にhost compromise pathになるか?

### 完全な例: Regaining Namespace-Local Capabilities

もしseccompが`unshare`を許可し、環境が新しいuser namespaceを許す場合、プロセスはその新しいnamespace内でフルのcapability setを取り戻す可能性があります:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
これはそれ自体では host escape ではありません。重要なのは、ユーザー名前空間がネームスペース内の特権的な操作を再度有効にし、それが弱いマウント、脆弱なカーネル、または適切に保護されていないランタイムの公開部分と組み合わさる可能性がある点です。

## Checks

これらのコマンドは、このページで最も重要な問いに答えることを目的としています: このコンテナ内の root はホスト上で何にマップされているか？
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- プロセスが UID 0 で、マッピングがホストの root に直接またはほぼ一致している場合、コンテナははるかに危険です。
- root が非特権のホスト範囲にマッピングされている場合、それはより安全なベースラインであり、通常は本当の user namespace の分離を示します。
- マッピングファイルは `id` 単体よりも有用です。`id` は名前空間内のローカルな識別情報しか示しません。

ワークロードが UID 0 で動作し、そのマッピングがホストの root とほぼ対応していることを示す場合、コンテナの他の権限はより厳格に評価するべきです。
