# 評価とハードニング

{{#include ../../../banners/hacktricks-training.md}}

## 概要

良い container 評価は並行する2つの質問に答えるべきです。第一に、現在の workload から攻撃者は何ができるか？第二に、どのオペレータの選択がそれを可能にしたか？Enumeration tools は第一の問いを助け、ハードニングの指針は第二の問いを助けます。両方を1ページにまとめておくことで、このセクションは単なるエスケープ手法のカタログ以上に、現場での参照として有用になります。

## 列挙ツール

いくつかのツールは、container 環境を素早く特徴付けるのに有用です:

- `linpeas` は多くの container 指標、マウントされたソケット、capability セット、危険なファイルシステム、およびブレイクアウトのヒントを特定できます。
- `CDK` は特に container 環境に焦点を当て、列挙に加えていくつかの自動化された escape チェックを含みます。
- `amicontained` は軽量で、container の制限、capabilities、namespace の露出、および想定されるブレイクアウト分類の特定に便利です。
- `deepce` はブレイクアウト志向のチェックを備えた、もう一つの container 特化の列挙ツールです。
- `grype` は、評価がランタイムのエスケープ解析だけでなく image-package の脆弱性レビューを含む場合に有用です。

これらツールの価値は確実性ではなく、速度とカバレッジにあります。大まかな姿勢を迅速に明らかにしますが、興味深い発見は実際の runtime、namespace、capability、および mount モデルに照らして手動で解釈する必要があります。

## ハードニングの優先事項

最も重要なハードニング原則は概念的には単純ですが、実装はプラットフォームによって異なります。privileged containers は避けてください。mounted runtime sockets を避けてください。非常に特別な理由がない限り、containers に対して書き込み可能な host paths を与えないでください。可能であれば user namespaces や rootless execution を使用してください。すべての capabilities を削除し、workload が本当に必要とするものだけを戻してください。アプリケーション互換性の問題を解決するために seccomp、AppArmor、SELinux を無効にするのではなく、有効にしておいてください。リソースを制限し、侵害された container がホストに対して簡単にサービス拒否できないようにしてください。

Image と build の衛生は runtime の姿勢と同じくらい重要です。minimal images を使い、頻繁に rebuild し、スキャンし、実用的な場合は provenance を要求し、layers に secrets を置かないでください。small image で narrow syscall と capability surface を持ち non-root として動作する container は、debugging tools がプリインストールされ host-equivalent root で動く大きな convenience image よりもはるかに防御しやすいです。

## リソース枯渇の例

リソース制御は派手ではありませんが、侵害の blast radius を制限するために container セキュリティの一部です。memory、CPU、PID の制限がないと、単純な shell だけでホストや隣接する workloads を劣化させるのに十分です。

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
これらの例は、すべての危険なコンテナの事象が単純な "escape" ではないことを示しており、有用です。弱い cgroup 制限は、code execution を実際の運用上の影響に変えてしまう可能性があります。

## ハードニングツール

Docker に特化した環境では、`docker-bench-security` は、一般的な構成の問題を広く認知されたベンチマークのガイダンスに照らしてチェックするため、依然として有用なホスト側監査のベースラインです:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
このツールは threat modeling の代替にはなりませんが、時間とともに蓄積する不注意な daemon、mount、network、および runtime のデフォルト設定を見つける上で依然として有用です。

## Checks

assessment 中の簡易なファーストパスコマンドとして、以下を使用してください：
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- 広範な capabilities を持ち `Seccomp: 0` の root プロセスは直ちに注意を要する。
- 疑わしい mounts や runtime sockets は、しばしば任意の kernel exploit よりも速く impact を与える経路となる。
- 弱い runtime posture と弱い resource limits の組み合わせは、単一の孤立したミスというより、一般に寛容な container 環境を示すことが多い。
{{#include ../../../banners/hacktricks-training.md}}
