# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

The cgroup namespace does not replace cgroups and does not itself enforce resource limits. Instead, it changes **how the cgroup hierarchy appears** to the process. In other words, it virtualizes the visible cgroup path information so that the workload sees a container-scoped view rather than the full host hierarchy.

これは主に可視性と情報削減のための機能です。環境をより自己完結的に見せ、ホストの cgroup レイアウトに関する情報露出を減らします。一見控えめに思えるかもしれませんが、不要なホスト構造の可視性は偵察を助け、環境依存のエクスプロイトチェーンを単純化してしまうため重要です。

## 動作

Without a private cgroup namespace, a process may see host-relative cgroup paths that expose more of the machine's hierarchy than is useful. With a private cgroup namespace, `/proc/self/cgroup` and related observations become more localized to the container's own view. This is particularly helpful in modern runtime stacks that want the workload to see a cleaner, less host-revealing environment.

プライベートな cgroup namespace がないと、プロセスはホスト相対の cgroup パスを見てしまい、マシンの階層構造の不要な部分まで露出することがあります。プライベートな cgroup namespace があると、`/proc/self/cgroup` やそれに類する観察結果は container 自身のビューによりローカライズされます。これは、ワークロードによりクリーンでホストを露呈しない環境を見せたい現代の runtime スタックで特に有用です。

## ラボ

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
そして、実行時の挙動を次と比較してください:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
この変更は主にプロセスが参照できるものに関するものであり、cgroup の強制が存在するかどうかに関するものではありません。

## セキュリティへの影響

cgroup namespace は **視認性強化レイヤー** として理解するのが最も適切です。単体では、container が writable cgroup mounts を持っていたり、広範な capabilities を持っていたり、危険な cgroup v1 環境が存在する場合の breakout を阻止するものではありません。しかし、host cgroup namespace が共有されていると、プロセスはシステムの構成についてより多くを把握し、host-relative の cgroup パスを他の観測と突き合わせやすくなる可能性があります。

したがって、この namespace は通常 container breakout のレポートで主役になることは少ないものの、それでも host information leak を最小化するというより広い目的に寄与します。

## 悪用

即時の悪用価値は主に偵察です。host cgroup namespace が共有されている場合、見えているパスを比較して、host を明らかにする階層の詳細を探します:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
書き込み可能な cgroup パスも公開されている場合は、その可視性を危険なレガシーインターフェースの検索と組み合わせてください:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
The namespace itself rarely gives instant escape, but it often makes the environment easier to map before testing cgroup-based abuse primitives.

### 完全な例: 共有された cgroup namespace + 書き込み可能な cgroup v1

cgroup namespace単体では通常、エスケープには十分ではありません。実際の権限昇格は、host-revealing cgroup paths と書き込み可能な cgroup v1 インターフェースが組み合わさったときに発生します:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
これらのファイルに到達でき、書き込み可能であれば、直ちに [cgroups.md](../cgroups.md) の完全な `release_agent` エクスプロイトフローにピボットしてください。影響はコンテナ内からホスト上でのコード実行です。

書き込み可能な cgroup interfaces がない場合、影響は通常 reconnaissance に限定されます。

## チェック

これらのコマンドの目的は、プロセスがプライベートな cgroup namespace ビューを持っているか、あるいは実際に必要とする以上にホストの階層について情報を取得しているかを確認することです。
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
ここで興味深い点：

- namespace識別子が関心のあるホストプロセスと一致する場合、cgroup namespaceは共有されている可能性がある。
- `/proc/self/cgroup` のホストを明らかにするパスは、直接的に悪用できない場合でも有用な偵察情報になる。
- cgroup mounts が書き込み可能な場合、可視性の問題はさらに重要になる。

cgroup namespaceは主要なエスケープ防止手段というより、可視性を硬化するレイヤーとして扱うべきである。ホストのcgroup構造を不必要に公開すると、攻撃者に対して偵察価値を高めてしまう。
{{#include ../../../../../banners/hacktricks-training.md}}
