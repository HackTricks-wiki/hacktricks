# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

The IPC namespace isolates **System V IPC objects** and **POSIX message queues**。そこにはホスト上の無関係なプロセス間で見えてしまう可能性のある共有メモリセグメント、セマフォ、メッセージキューが含まれます。実務的には、これにより container が他のワークロードや host に属する IPC オブジェクトに気軽にアタッチすることを防ぎます。

mount、PID、または user namespaces と比べて、IPC namespace は議論される頻度が低いことが多いですが、それを重要でないと混同してはいけません。共有メモリや関連する IPC メカニズムには非常に有用な状態が含まれていることがあります。ホストの IPC namespace が公開されると、ワークロードはコンテナ境界を越えて共有される意図のなかったプロセス間の調整オブジェクトやデータを可視化できる可能性があります。

## 動作

ランタイムが新しい IPC namespace を作成すると、そのプロセスは独自の隔離された IPC 識別子のセットを取得します。つまり、`ipcs` のようなコマンドはその namespace 内で利用可能なオブジェクトのみを表示します。コンテナがホストの IPC namespace に参加する場合、これらのオブジェクトは共有のグローバルビューの一部になります。

これは、アプリケーションやサービスが共有メモリを多用する環境で特に重要です。コンテナが単独で IPC を使って直接脱出できない場合でも、namespace が情報を leak したり、プロセス間干渉を可能にして後の攻撃を実質的に助けることがあります。

## ラボ

プライベートな IPC namespace は以下で作成できます:
```bash
sudo unshare --ipc --fork bash
ipcs
```
そして実行時の挙動を以下と比較してください:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## ランタイムでの使用

Docker と Podman はデフォルトで IPC を分離します。Kubernetes は通常、Pod に専用の IPC 名前空間を割り当て、同じ Pod 内のコンテナ間で共有されますが、デフォルトではホストとは共有されません。ホスト IPC の共有は可能ですが、それは単なるランタイムオプションではなく隔離が大きく低下するものとして扱うべきです。

## 誤設定

明らかなミスは `--ipc=host` や `hostIPC: true` です。これはレガシーソフトウェアとの互換性や利便性のために行われることがありますが、トラストモデルを大きく変えます。別の繰り返し発生する問題は、host PID や host networking よりも劇的に感じられないために単純に IPC を見落とすことです。実際には、ワークロードがブラウザ、データベース、科学計算ワークロード、あるいは共有メモリを多用する他のソフトウェアを扱う場合、IPC の攻撃面は非常に重要になり得ます。

## 悪用

ホスト IPC が共有されていると、攻撃者は共有メモリオブジェクトを検査・干渉したり、ホストや隣接するワークロードの挙動について新たな洞察を得たり、そこで得た情報をプロセス可視性や ptrace-style の能力と組み合わせたりすることが可能になります。IPC の共有はしばしば単独のブレイクアウト経路というよりは補助的な弱点ですが、補助的な弱点は実際の攻撃チェーンを短く安定させるため重要です。

最初の有用なステップは、そもそもどの IPC オブジェクトが見えているかを列挙することです：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
ホスト IPC namespace が共有されている場合、大きな共有メモリセグメントや興味深いオブジェクトの所有者がアプリケーションの挙動を即座に明らかにすることがあります：
```bash
ipcs -m -p
ipcs -q -p
```
一部の環境では、`/dev/shm` の内容自体が確認すべき filenames、artifacts、または tokens を leak することがあります:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPCの共有だけで即座に host root を得られることは稀だが、データや協調チャネルを露出させ、後のプロセス攻撃を格段に容易にすることがある。

### 完全な例: `/dev/shm` の秘密の回収

最も現実的な完全な悪用例は、直接的な escape よりもデータ窃盗である。host IPC や広範な shared-memory レイアウトが露出している場合、機密アーティファクトを直接回収できることがある:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
影響:

- 共有メモリに残された秘密情報やセッション情報の抽出
- ホスト上で現在稼働しているアプリケーションについての洞察
- 後のPID-namespaceやptrace-based attacksに対するターゲティングが容易になる

IPC共有はしたがって、単独のホスト脱出プリミティブとして捉えるよりも、むしろ**攻撃の増幅器**として理解する方が適切です。

## チェック

これらのコマンドは、ワークロードがプライベートなIPCビューを持っているか、有意な共有メモリやメッセージオブジェクトが見えているか、そして /dev/shm 自体が有用なアーティファクトを露出しているかどうかを確認するためのものです。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
ここで注目すべき点：

- `ipcs -a` が予期しないユーザーやサービスが所有するオブジェクトを示す場合、その名前空間は期待どおりに隔離されていない可能性がある。
- 大きいまたは異常な共有メモリセグメントは、追跡調査する価値があることが多い。
- 広範な `/dev/shm` マウントが自動的にバグであるわけではないが、いくつかの環境ではファイル名、アーティファクト、そして一時的なシークレットをleaksする。

IPCは、より大きな名前空間タイプほど注目されることは稀だが、これを多用する環境ではホストと共有するかどうかは重大なセキュリティ上の判断である。
