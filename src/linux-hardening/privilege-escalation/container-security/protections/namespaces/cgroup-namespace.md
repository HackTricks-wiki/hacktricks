# cgroup 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

cgroup 名前空間は cgroups を置き換えるものではなく、リソース制限を直接課すものでもありません。代わりに、プロセスから見える **cgroup 階層の見え方** を変更します。言い換えれば、表示される cgroup パス情報を仮想化し、ワークロードがホスト全体の階層ではなくコンテナ単位のビューを見るようにします。

これは主に可視性と情報削減のための機能です。環境をより自己完結的に見せ、ホストの cgroup レイアウトに関する情報を減らすのに役立ちます。控えめに聞こえるかもしれませんが、ホスト構造への不要な可視性は偵察を助け、環境依存の exploit chains を単純化してしまう可能性があるため、重要です。

## 動作

プライベートな cgroup 名前空間がないと、プロセスはホスト相対の cgroup パスを見てしまい、マシンの階層構造を不必要に多く晒す可能性があります。プライベートな cgroup 名前空間があると、/proc/self/cgroup やそれに関連する観測はコンテナ内の独自ビューにより局所化されます。これは、ワークロードに対してよりクリーンでホスト情報を明かさない環境を見せたいモダンなランタイムスタックで特に有用です。

## ラボ

cgroup 名前空間は次のコマンドで確認できます：
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
そしてランタイムの挙動を以下と比較する:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
The change is mostly about what the process can see, not about whether cgroup enforcement exists.

## Security Impact

The cgroup namespace is best understood as a **visibility-hardening layer**. By itself it will not stop a breakout if the container has writable cgroup mounts, broad capabilities, or a dangerous cgroup v1 environment. However, if the host cgroup namespace is shared, the process learns more about how the system is organized and may find it easier to line up host-relative cgroup paths with other observations.

So while this namespace is not usually the star of container breakout writeups, it still contributes to the broader goal of minimizing host information leakage.

## Abuse

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
書き込み可能な cgroup パスも露出している場合は、その可視性を危険なレガシーインターフェースの検索と組み合わせる:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
The namespace itself rarely gives instant escape, but it often makes the environment easier to map before testing cgroup-based abuse primitives.

### フル例: 共有 cgroup 名前空間 + 書き込み可能な cgroup v1

cgroup 名前空間だけでは通常、脱出には不十分です。実際の権限昇格は、ホストを明らかにする cgroup パスが書き込み可能な cgroup v1 インターフェースと組み合わさったときに発生します:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
もしそれらのファイルに到達可能かつ書き込み可能であれば、直ちに[cgroups.md](../cgroups.md)の`release_agent`エクスプロイトフロー全体へ切り替えてください。影響はcontainer内部からのホスト上でのコード実行です。

書き込み可能な cgroup インターフェースがない場合、影響は通常 reconnaissance に限定されます。

## チェック

これらのコマンドの目的は、プロセスがプライベートな cgroup namespace ビューを持っているか、あるいは実際に必要以上にホスト階層について学んでいるかを確認することです。
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
ここで注目すべき点:

- 名前空間識別子があなたが関心を持つホストプロセスと一致する場合、cgroup namespace は共有されている可能性がある。
- `/proc/self/cgroup` にあるホストを明らかにするパスは、直接的に悪用できない場合でも有用な情報収集になる。
- cgroup mounts が書き込み可能な場合、可視性の問題はさらに重要になる。

cgroup namespace は主要なエスケープ防止メカニズムではなく、可視性をハードニングする層として扱うべきである。ホストの cgroup 構造を不必要に露出すると、攻撃者にとっての情報収集の価値が増す。
