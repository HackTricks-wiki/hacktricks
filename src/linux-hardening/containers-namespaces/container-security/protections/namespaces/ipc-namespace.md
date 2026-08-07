# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

IPC namespace は **System V IPC objects** と **POSIX message queues** を分離します。これには、ホスト上の無関係なプロセス間で本来なら可視となる shared memory segments、semaphores、message queues が含まれます。実際には、これによりコンテナが他の workload やホストに属する IPC objects に気軽に attach することを防ぎます。

mount、PID、user namespaces と比較すると、IPC namespace は取り上げられる頻度が低いことが多いですが、重要でないという意味ではありません。Shared memory や関連する IPC mechanisms には、非常に有用な state が含まれている可能性があります。ホストの IPC namespace が exposed になると、workload は inter-process coordination objects や、コンテナ境界を越えることが意図されていなかった data を可視化できる可能性があります。

## Operation

runtime が新しい IPC namespace を作成すると、process は独自に分離された IPC identifiers のセットを取得します。つまり、`ipcs` などの commands は、その namespace で利用可能な objects のみを表示します。一方、コンテナが host IPC namespace に join すると、それらの objects は共有された global view の一部になります。

これは、applications や services が shared memory を多用する environments で特に重要です。コンテナが IPC だけで直接 breakout できない場合でも、namespace が information を leak したり、cross-process interference を可能にしたりすることで、その後の attack に大きく役立つ可能性があります。

## Lab

次のコマンドで private IPC namespace を作成できます:
```bash
sudo unshare --ipc --fork bash
ipcs
```
また、以下と実行時の挙動を比較します：
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## ランタイムでの利用

Docker と Podman はデフォルトで IPC を分離します。Kubernetes は通常、Pod に独自の IPC namespace を提供します。これは同じ Pod 内のコンテナ間で共有されますが、デフォルトでは host とは共有されません。Host IPC の共有は可能ですが、軽微な runtime オプションではなく、分離性を大きく低下させるものとして扱うべきです。

## 設定ミス

典型的なミスは `--ipc=host` または `hostIPC: true` です。これは legacy software との互換性や利便性のために行われることがありますが、trust model を大きく変えてしまいます。もう一つのよくある問題は、host PID や host networking ほど深刻に感じられないため、IPC を単純に見落とすことです。実際には、workload が browsers、databases、scientific workloads、その他 shared memory を多用する software を扱う場合、IPC surface は非常に重要になります。

## Abuse

Host IPC が共有されている場合、attacker は shared memory objects を調査または干渉したり、host や近隣の workload の動作に関する新たな情報を得たり、そこで得た情報を process visibility や ptrace-style capabilities と組み合わせたりする可能性があります。IPC sharing は完全な breakout path というより、補助的な weakness であることが多いですが、補助的な weakness が重要なのは、実際の attack chain を短縮し、安定させるためです。

最初に役立つ手順は、そもそもどの IPC objects が可視なのかを列挙することです：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
ホストの IPC namespace が共有されている場合、大きな shared-memory セグメントや興味深いオブジェクトの所有者から、アプリケーションの動作がすぐに明らかになる可能性があります:
```bash
ipcs -m -p
ipcs -q -p
```
一部の環境では、`/dev/shm` の内容自体から、確認する価値のあるファイル名、artifacts、または tokens が leak することがあります。
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing だけで即座に host root を取得できることはほとんどありませんが、後続のプロセス攻撃をはるかに容易にするデータや coordination channel が露出する可能性があります。

### 完全な例: `/dev/shm` Secret Recovery

最も現実的な完全な abuse case は、直接的な escape ではなくデータ窃取です。host IPC または広範な shared-memory layout が露出している場合、機密性の高いアーティファクトを直接 recovery できることがあります。
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
影響:

- shared memory に残された secrets や session material の抽出
- host 上で現在 active な applications に関する情報の取得
- 後続の PID-namespace または ptrace-based attacks に対する targeting の改善

したがって、IPC sharing は standalone の host-escape primitive というより、**attack amplifier** として理解する方が適切です。

## Checks

これらの commands は、workload が private IPC view を持っているか、意味のある shared-memory または message objects が表示されるか、そして `/dev/shm` 自体が有用な artifacts を公開しているかを確認するためのものです。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
ここで注目すべき点：

- `ipcs -a` で予期しないユーザーやサービスが所有するオブジェクトが表示される場合、namespace が想定どおりに分離されていない可能性があります。
- 大規模または通常とは異なる shared memory セグメントは、追加調査の価値があります。
- 広範な `/dev/shm` mount は、それだけでバグとは限りませんが、一部の環境ではファイル名、artifacts、一時的な secrets が leak する可能性があります。

IPC は、より大きな namespace types ほど注目されることはほとんどありませんが、IPC を多用する環境では、host と共有することは明確な security decision です。

{{#include ../../../../../banners/hacktricks-training.md}}
