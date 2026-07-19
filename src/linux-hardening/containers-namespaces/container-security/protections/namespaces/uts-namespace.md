# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

UTS namespace は、プロセスから見える **hostname** と **NIS domain name** を分離します。一見すると mount、PID、user namespace と比べて些細に見えるかもしれませんが、container を独立した host のように見せる要素の一つです。namespace 内では、workload はマシン全体でグローバルなものではなく、その namespace にローカルな hostname を確認でき、場合によっては変更することもできます。

これ単体で breakout の中心的な要素となることは通常ありません。しかし、host UTS namespace が共有されている場合、十分な権限を持つプロセスが host の identity 関連設定に影響を与えられる可能性があり、運用上の問題や、場合によっては security 上の問題につながることがあります。

## Lab

次のコマンドで UTS namespace を作成できます:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
ホスト名の変更はその namespace 内に限定され、ホストのグローバルなホスト名は変更されません。これは、分離特性を示すシンプルながら効果的な例です。

## Runtime Usage

通常のコンテナでは、分離された UTS namespace が使用されます。Docker と Podman では `--uts=host` によってホストの UTS namespace に参加でき、同様のホスト共有パターンは他の runtime や orchestration system にも存在する場合があります。ただしほとんどの場合、private UTS isolation は通常のコンテナ設定の一部であり、operator による対応はほとんど必要ありません。

## Security Impact

UTS namespace は通常、共有しても最も危険な namespace ではありませんが、それでもコンテナ境界の integrity に寄与します。ホストの UTS namespace が公開され、process に必要な privileges がある場合、ホストの hostname 関連情報を変更できる可能性があります。これにより、monitoring、logging、operational assumptions、またはホスト identity data に基づいて trust decisions を行う scripts に影響する可能性があります。

## Abuse

ホストの UTS namespace が共有されている場合、実際の問題は process がホスト identity settings を単に読み取るだけでなく、変更できるかどうかです：
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

- host identity の tampering
- hostname を信頼するログ、monitoring、automation の混乱
- 通常、単独では完全な escape には至らないが、他の弱点と組み合わせると可能性がある

Docker-style environments では、host-side detection pattern として次の方法が有用です：
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` を示すコンテナはホストの UTS namespace を共有しているため、`sethostname()` または `setdomainname()` を呼び出せる capabilities も持っている場合は、より慎重に確認する必要があります。

## Checks

これらのコマンドで、workload が独自の hostname view を持っているか、またはホストの UTS namespace を共有しているかを確認できます。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
ここで注目すべき点：

- namespace identifier が host process と一致している場合、host UTS sharing が発生している可能性があります。
- hostname の変更が container 自体を超えて影響する場合、その workload は本来よりも host identity に対して大きな影響力を持っています。
- これは通常、PID、mount、または user namespace の問題よりも優先度の低い finding ですが、process が実際にどの程度 isolated されているかを確認する材料にはなります。

ほとんどの環境では、UTS namespace は補助的な isolation layer と考えるのが適切です。breakout で最初に調査する対象になることは稀ですが、container view 全体の一貫性と安全性を構成する要素の一つです。
{{#include ../../../../../banners/hacktricks-training.md}}
