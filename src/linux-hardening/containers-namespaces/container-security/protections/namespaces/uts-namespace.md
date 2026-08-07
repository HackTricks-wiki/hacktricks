# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

UTS namespace は、プロセスから見える **hostname** と **NIS domain name** を分離します。一見すると、mount、PID、user namespace と比べて単純に見えるかもしれません。しかし、これはコンテナを独立したホストのように見せる要素の一つです。namespace 内では、ワークロードはマシン全体ではなく、その namespace に固有の hostname を確認でき、場合によっては変更することもできます。

単独では、通常これは breakout の中心的な要素ではありません。ただし、ホストの UTS namespace が共有されている場合、十分な権限を持つプロセスがホストの identity 関連設定に影響を与えられる可能性があり、運用上の問題や、場合によっては security 上の問題につながることがあります。

## Lab

次のコマンドで UTS namespace を作成できます:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
ホスト名の変更はその namespace 内に限定され、host のグローバルなホスト名は変更されません。これは isolation property を簡潔かつ効果的に示す例です。

## Runtime Usage

通常のコンテナには、分離された UTS namespace が割り当てられます。Docker と Podman では `--uts=host` を使用して host の UTS namespace に参加できます。また、同様の host-sharing パターンは、他の runtime や orchestration system にも存在する場合があります。ただし、ほとんどの場合、private UTS isolation は通常のコンテナ設定の一部であり、operator による対応はほとんど必要ありません。

## Security Impact

UTS namespace は通常、共有するうえで最も危険な namespace ではありませんが、それでも container boundary の integrity に寄与します。host UTS namespace が公開され、process に必要な privileges がある場合、host のホスト名関連情報を変更できる可能性があります。これにより、monitoring、logging、運用上の前提、または host identity data に基づいて trust を判断する scripts に影響する可能性があります。

## Abuse

host UTS namespace が共有されている場合、実際に問題となるのは、process が host identity settings を単に読み取るだけでなく、変更できるかどうかです：
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
コンテナにも必要な privilege がある場合、hostname を変更できるかテストします：
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
これは完全な escape というより、主に integrity と operational impact に関する問題ですが、container が host-global property に直接影響を与えられることを示しています。

Impact:

- host identity tampering
- hostname を信頼するログ、monitoring、automation の混乱
- 通常、単独では完全な escape には至らないが、他の弱点と組み合わせると可能

Docker-style environments では、host-side detection pattern として次が有用です:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` を示すコンテナは、ホストの UTS namespace を共有しています。また、`sethostname()` や `setdomainname()` を呼び出せる capabilities も保持している場合は、より慎重に確認する必要があります。

## Checks

これらのコマンドで、workload が独自の hostname view を持っているか、またはホストの UTS namespace を共有しているかを確認できます。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
ここで注目すべき点：

- namespace identifier が host process と一致している場合、host UTS sharing が示唆されます。
- hostname の変更が container 自体を超えて影響する場合、その workload は本来持つべき範囲を超えて host identity に影響を与えています。
- これは通常、PID、mount、または user namespace の問題より優先度の低い finding ですが、process が実際にどの程度 isolate されているかを確認する手がかりにはなります。

ほとんどの環境では、UTS namespace は補助的な isolation layer と考えるのが適切です。breakout で最初に追う対象になることはまれですが、container view 全体の一貫性と安全性を構成する要素ではあります。

{{#include ../../../../../banners/hacktricks-training.md}}
