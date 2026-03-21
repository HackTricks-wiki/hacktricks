# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

UTS namespace はプロセスから見える **hostname** と **NIS domain name** を分離します。一見するとこれは mount、PID、または user namespaces と比べて取るに足らないように見えるかもしれませんが、container が独自のホストのように見える要因の一部です。namespace 内では、ワークロードはその namespace にローカルな hostname を参照し、場合によっては変更することができます（マシン全体に対するグローバルなものではありません）。

単独では、これは通常ブレイクアウトの物語の中心にはなりません。しかし、ホストの UTS namespace が共有されると、十分な権限を持つプロセスがホストの識別に関連する設定に影響を与える可能性があり、それは運用上、また時折セキュリティ上で重要になることがあります。

## ラボ

次のコマンドで UTS namespace を作成できます：
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
ホスト名の変更はその名前空間内にとどまり、ホストのグローバルなホスト名には影響しません。これは分離特性のシンプルで効果的な実例です。

## ランタイムでの使用

通常のコンテナは分離された UTS 名前空間を持ちます。Docker や Podman は `--uts=host` を使ってホストの UTS 名前空間に参加することができ、同様のホスト共有パターンは他のランタイムやオーケストレーションシステムでも見られます。しかしほとんどの場合、プライベートな UTS 分離は通常のコンテナ設定の一部であり、オペレータが特別な対応をする必要はほとんどありません。

## セキュリティへの影響

UTS 名前空間は通常、共有することで最も危険というわけではありませんが、それでもコンテナ境界の整合性に寄与します。ホストの UTS 名前空間が公開され、プロセスが必要な権限を持っている場合、ホストのホスト名関連情報を変更できる可能性があります。それはモニタリング、ログ取得、運用上の前提、あるいはホスト識別データに基づいて信頼判断を行うスクリプトに影響を与える可能性があります。

## 悪用

ホストの UTS 名前空間が共有されている場合、実務的な問題はプロセスがそれらを読み取るだけでなく、ホストの識別設定を変更できるかどうかです：
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
container が必要な privilege を持っている場合、hostname を変更できるか確認してください:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
これは主に整合性および運用への影響の問題であり、完全な escape ではないものの、コンテナがホスト全体のプロパティに直接影響を与え得ることを示しています。

影響:

- ホスト識別の改ざん
- hostname を信頼するログ、監視、または自動化の混乱
- 通常は単独では完全な escape にはならない（他の弱点と組み合わせた場合を除く）

Docker-style 環境では、ホスト側で有用な検出パターンは次のとおりです:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` と表示されているコンテナはホストの UTS 名前空間を共有しており、`sethostname()` や `setdomainname()` を呼び出せる capabilities を持っている場合は、より注意深く確認する必要があります。

## チェック

以下のコマンドで、ワークロードが独自のホスト名ビューを持っているか、ホストの UTS 名前空間を共有しているかを判別できます。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- namespace 識別子がホストプロセスと一致する場合、ホストの UTS 共有を示している可能性がある。
- hostname を変更してコンテナ自身以外にも影響が及ぶ場合、その workload はホストの識別に対して本来より大きな影響力を持っている。
- これは通常、PID、mount、または user namespace に関する問題より優先度の低い所見だが、それでもプロセスがどれだけ隔離されているかを確認するものになる。

ほとんどの環境では、UTS namespace は補助的な隔離レイヤーと考えるのが最適だ。breakout を狙う際に真っ先に追う対象になることは稀だが、それでも container の全体的一貫性と安全性の一部である。
