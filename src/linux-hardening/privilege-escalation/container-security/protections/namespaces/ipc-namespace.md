# IPC 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

IPC 名前空間は **System V IPC objects** と **POSIX message queues** を分離します。これには、ホスト上の無関係なプロセス間で共有されるはずの shared memory segments、semaphores、そして message queues が含まれます。実際的には、コンテナが他のワークロードやホストに属するIPCオブジェクトに軽々しくアタッチすることを防ぎます。

mount、PID、user namespaces と比べて、IPC 名前空間はあまり議論されないことが多いですが、それが重要でないというわけではありません。Shared memory や関連する IPC 機構には、非常に有用な状態が含まれていることがあります。ホストの IPC 名前空間が exposed されていると、ワークロードはコンテナ境界を越える意図のなかったプロセス間の調整オブジェクトやデータを可視化できるようになる可能性があります。

## 動作

ランタイムが新しい IPC 名前空間を作成すると、そのプロセスは独自の分離された IPC 識別子セットを持ちます。つまり `ipcs` のようなコマンドは、その名前空間で利用可能なオブジェクトのみを表示します。コンテナがホストの IPC 名前空間に参加した場合、これらのオブジェクトは共有のグローバルなビューの一部になります。

これは、アプリケーションやサービスが shared memory を多用する環境で特に重要です。コンテナが単独の IPC だけで直接脱出できない場合でも、名前空間は情報を leak したり、後の攻撃を実質的に助けるクロスプロセスの干渉を可能にしたりする可能性があります。

## ラボ

プライベートな IPC 名前空間は次のように作成できます:
```bash
sudo unshare --ipc --fork bash
ipcs
```
そして実行時の挙動を次と比較する:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## 実行時の利用

Docker と Podman はデフォルトで IPC を分離します。Kubernetes は通常、Pod に専用の IPC namespace を割り当て、同じ Pod 内のコンテナ間で共有されますが、ホストとはデフォルトで共有されません。ホストとの IPC 共有は可能ですが、それは単なる小さなランタイムオプションではなく、実質的に分離が低下する重要な設定として扱うべきです。

## 誤設定

明らかな誤りは `--ipc=host` や `hostIPC: true` です。これはレガシーソフトウェアとの互換性や利便性のために行われることがありますが、信頼モデルを大きく変えます。もう一つよくある問題は、ホスト PID やホストネットワーキングほど劇的に見えないために IPC を単に見落とすことです。実際には、ワークロードがブラウザ、データベース、科学計算系のワークロード、あるいは共有メモリを多用するその他のソフトウェアを扱う場合、IPC の攻撃対象面は非常に重要になり得ます。

## 悪用

ホスト IPC が共有されていると、攻撃者は共有メモリオブジェクトを検査・改変したり、ホストや隣接するワークロードの挙動について新たな洞察を得たり、そこで得た情報をプロセスの可視性や ptrace スタイルの能力と組み合わせたりする可能性があります。IPC の共有はしばしば完全な脱出経路ではなく補助的な脆弱性ですが、補助的な脆弱性は実際の攻撃チェーンを短く安定させるため重要です。

最初に有用なステップは、どの IPC オブジェクトが見えているかを列挙することです：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
ホストの IPC namespace を共有していると、大きな共有メモリセグメントや注目すべきオブジェクトの所有者からアプリケーションの挙動が即座に明らかになることがある:
```bash
ipcs -m -p
ipcs -q -p
```
一部の環境では、/dev/shm の内容自体がファイル名、アーティファクト、または確認に値するトークンを leak することがある:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC の共有だけで即座に host root を取得できることは稀ですが、データや調整チャネルを露出させ、その後のプロセス攻撃をはるかに容易にする場合があります。

### 完全な例: `/dev/shm` シークレット回収

最も現実的な悪用ケースは直接の脱出ではなくデータ窃取です。host IPC や広範な shared-memory レイアウトが露出している場合、機密アーティファクトを直接回収できることがあります：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact:

- shared memoryに残された秘密情報やセッション素材の抽出
- ホスト上で現在稼働しているアプリケーションの把握
- 後続のPID-namespaceやptraceベースの攻撃に対するより精密なターゲティング

IPC sharingはしたがって単体のhost-escape primitiveというより、**攻撃の増幅手段**として理解する方が適切である。

## Checks

これらのコマンドは、ワークロードがプライベートなIPCビューを持っているか、意味のあるshared-memoryやmessage objectsが見えているか、そして `/dev/shm` 自体が有用なアーティファクトを公開しているかを確認することを目的としている。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
ここで興味深い点:

- If `ipcs -a` reveals objects owned by unexpected users or services, the namespace may not be as isolated as expected.
- 大きい、または異常な共有メモリセグメントは追跡調査する価値があることが多い。
- 広範な `/dev/shm` マウントは自動的にバグとは限らないが、いくつかの環境では it leaks filenames, artifacts, and transient secrets.

IPCはより大きな名前空間の種類ほど注目されることはめったにないが、これを多用する環境では、ホストと共有することは明確にセキュリティ上の判断である。
{{#include ../../../../../banners/hacktricks-training.md}}
