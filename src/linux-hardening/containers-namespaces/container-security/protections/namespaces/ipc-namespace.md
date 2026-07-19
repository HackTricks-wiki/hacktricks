# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

IPC namespace は **System V IPC objects** と **POSIX message queues** を分離します。これには、ホスト上の無関係なプロセス間で本来共有される可能性のある shared memory segments、semaphores、message queues が含まれます。実際には、これによりコンテナが他のワークロードやホストに属する IPC objects に不用意に接続することを防ぎます。

mount、PID、user namespaces と比べると、IPC namespace は取り上げられる頻度が低い傾向にあります。しかし、それは重要でないという意味ではありません。Shared memory や関連する IPC mechanisms には、非常に有用な state が含まれている場合があります。ホストの IPC namespace が公開されていると、ワークロードから、プロセス間の coordination objects や、コンテナ境界を越えることを意図していなかったデータが見える可能性があります。

## Operation

runtime が新しい IPC namespace を作成すると、プロセスは独自に分離された IPC identifiers のセットを取得します。つまり、`ipcs` などのコマンドには、その namespace で利用可能な objects だけが表示されます。コンテナが代わりに host IPC namespace に参加すると、それらの objects は共有された global view の一部になります。

これは、applications や services が shared memory を多用する環境で特に重要です。コンテナが IPC だけでは直接 break out できない場合でも、namespace によって情報が leak したり、プロセス間の interference が可能になったりすることで、その後の attack に大きく役立つ可能性があります。

## Lab

次のコマンドで private IPC namespace を作成できます:
```bash
sudo unshare --ipc --fork bash
ipcs
```
また、実行時の動作と比較します：
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker と Podman はデフォルトで IPC を分離します。Kubernetes は通常、Pod に専用の IPC namespace を割り当てます。この namespace は同じ Pod 内のコンテナ間で共有されますが、デフォルトでは host とは共有されません。Host IPC の共有は可能ですが、単なる runtime オプションではなく、isolation を大きく低下させるものとして扱うべきです。

## Misconfigurations

明らかなミスは `--ipc=host` または `hostIPC: true` です。これは legacy software との互換性や利便性のために設定されることがありますが、trust model を大きく変化させます。もう1つのよくある問題は、host PID や host networking ほど重大には感じられないため、IPC を単純に見落とすことです。実際には、workload が browsers、databases、scientific workloads、その他 shared memory を多用する software を扱う場合、IPC surface は非常に重要になる可能性があります。

## Abuse

Host IPC が共有されている場合、attacker は shared memory objects を検査または干渉したり、host や隣接する workload の動作について新たな情報を得たり、そこで得た情報を process visibility や ptrace-style capabilities と組み合わせたりできます。IPC sharing は完全な breakout path というより、支援的な weakness であることが多いものの、支援的な weakness は実際の attack chain を短縮し、安定させるため重要です。

最初に行うべき有用な手順は、どの IPC objects がそもそも可視になっているかを enumerate することです：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
ホストの IPC namespace が共有されている場合、大きな shared-memory セグメントや興味深いオブジェクト所有者から、アプリケーションの挙動がすぐに明らかになる可能性があります:
```bash
ipcs -m -p
ipcs -q -p
```
一部の環境では、`/dev/shm` の内容自体から、確認する価値のあるファイル名、アーティファクト、またはトークンが leak することがあります：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC共有だけで即座に host root を取得できることはまれですが、後続の process attacks をはるかに容易にするデータや調整用チャネルが露出する可能性があります。

### 完全な例: `/dev/shm` Secret Recovery

最も現実的な完全な悪用ケースは、直接的な脱出ではなくデータ窃取です。ホストのIPCや広範な shared-memory layout が露出している場合、機密アーティファクトを直接復元できることがあります。
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
影響:

- 共有メモリに残された secrets または session material の抽出
- host 上で現在 active な applications に関する情報の取得
- 後続の PID namespace または ptrace-based attacks における targeting の精度向上

したがって、IPC sharing は standalone の host-escape primitive というより、**attack amplifier** として理解する方が適切です。

## Checks

これらのコマンドは、workload が private IPC view を持っているか、意味のある shared-memory または message objects が見えるか、さらに `/dev/shm` 自体が有用な artifacts を公開しているかを確認するためのものです。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
ここで注目すべき点：

- `ipcs -a` で予期しないユーザーやサービスが所有するオブジェクトが表示される場合、namespace が想定どおりに分離されていない可能性があります。
- 大きな、または通常とは異なる shared memory セグメントは、詳しく調査する価値があります。
- 広範な `/dev/shm` mount は必ずしもバグではありませんが、一部の環境ではファイル名、artifact、一時的な secrets が leak する可能性があります。

IPC は、より大きな namespace タイプほど注目されることはほとんどありません。しかし、IPC を多用する環境では、host と共有することは明確な security decision です。
{{#include ../../../../../banners/hacktricks-training.md}}
