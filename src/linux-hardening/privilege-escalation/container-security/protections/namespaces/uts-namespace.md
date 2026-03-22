# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

The UTS namespace isolates the **hostname** and **NIS domain name** seen by the process. 一見すると mount、PID、user namespaces と比べて些細に見えるかもしれませんが、コンテナが独自のホストのように見える要因の一部です。namespace 内では、ワークロードはマシン全体にとってグローバルではなく、その namespace にローカルな **hostname** を参照し、場合によっては変更することができます。

単独では、これは通常ブレイクアウトの主役にはなりません。しかし、ホストの UTS namespace が共有されると、十分な権限を持ったプロセスがホストの識別に関わる設定に影響を与える可能性があり、運用上、また時にセキュリティ上の問題になることがあります。

## ラボ

次のコマンドで UTS namespace を作成できます:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
ホスト名の変更はその namespace に限定され、ホストのグローバルなホスト名は変更されません。これは隔離の性質を簡潔かつ効果的に示すデモンストレーションです。

## ランタイムでの使用

通常のコンテナは分離された UTS namespace を使用します。Docker と Podman は `--uts=host` を使ってホストの UTS namespace に参加でき、同様のホスト共有のパターンは他のランタイムやオーケストレーションシステムでも見られます。しかしほとんどの場合、プライベートな UTS の隔離は通常のコンテナ設定の一部であり、オペレータによる特別な注意をほとんど必要としません。

## セキュリティへの影響

UTS namespace は通常共有した場合に最も危険なものではありませんが、それでもコンテナ境界の整合性に寄与します。ホストの UTS namespace が露出し、プロセスが必要な権限を持っている場合、ホストのホスト名関連情報を変更できる可能性があります。これは監視、ログ、運用上の仮定、あるいはホスト識別データに基づいて信頼判断を行うスクリプトに影響を与えるかもしれません。

## 悪用

ホストの UTS namespace が共有されている場合、実務上の問題はプロセスがそれらを読み取るだけでなく、ホストの識別設定を変更できるかどうかです:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
コンテナが必要な権限を持っている場合、ホスト名を変更できるかをテストしてください:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
これは主に整合性および運用上の影響の問題であって、完全な escape ではありませんが、コンテナがホスト全体に関わるプロパティに直接影響を与えうることを示しています。

影響:

- ホストのアイデンティティの改ざん
- hostname を信頼しているログ、監視、または自動化の混乱
- 通常、単独では完全な escape にはならない（他の脆弱性と組み合わされる場合を除く）

Docker スタイルの環境では、ホスト側での有用な検知パターンは次のとおりです:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` と表示されるコンテナはホストの UTS namespace を共有しており、`sethostname()` や `setdomainname()` を呼び出せる capabilities を持っている場合は、より注意深くレビューする必要があります。

## Checks

以下のコマンドで、ワークロードが独自のホスト名ビューを持っているか、それともホストの UTS namespace を共有しているかを確認できます。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- ホストプロセスとnamespace identifiersが一致することは、ホストのUTS共有を示している可能性がある。
- hostnameを変更してcontainer自体以外にも影響が及ぶ場合、そのワークロードは本来よりもホストの識別に対して大きな影響力を持っている。
- これは通常、PID、mount、またはuser namespaceの問題より優先度の低い所見だが、それでもプロセスがどれだけ隔離されているかを確認するものだ。

ほとんどの環境では、UTS namespaceは補助的な隔離レイヤーと考えるのが適切だ。breakoutで最初に追う対象になることは稀だが、それでもcontainerの全体的な整合性と安全性の一部である。
{{#include ../../../../../banners/hacktricks-training.md}}
