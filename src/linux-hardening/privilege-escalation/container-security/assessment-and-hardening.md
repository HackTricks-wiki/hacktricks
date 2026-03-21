# 評価とハードニング

{{#include ../../../banners/hacktricks-training.md}}

## 概要

良いコンテナ評価は、並行する2つの質問に答えるべきです。第一に、現在のワークロードから攻撃者は何ができるか？第二に、どのオペレーターの選択がそれを可能にしたか？列挙ツールは第一の質問を助け、ハードニングの指針は第二を助けます。両方を1ページにまとめることで、このセクションは単なる escape tricks のカタログよりも現場での参照として有用になります。

## 列挙ツール

いくつかのツールは、コンテナ環境を素早く特徴付けるのに依然として有用です:

- `linpeas` は多くのコンテナ指標、マウントされたソケット、capability sets、危険なファイルシステム、および breakout hints を識別できます。
- `CDK` はコンテナ環境に特化しており、列挙といくつかの自動化された escape checks を含みます。
- `amicontained` は軽量で、コンテナの制限、capabilities、namespace の露出、そして想定される breakout クラスを識別するのに有用です。
- `deepce` は breakout 指向のチェックを備えた別のコンテナ向け列挙ツールです。
- `grype` は、評価がランタイムの escape 分析だけでなくイメージ内パッケージの脆弱性レビューを含む場合に有用です。

これらツールの価値は確実性ではなく、速度とカバレッジにあります。大まかな姿勢を素早く明らかにするのに役立ちますが、興味深い所見は実際の runtime、namespace、capability、マウントモデルに照らして手動で解釈する必要があります。

## ハードニングの優先事項

最も重要なハードニングの原則は概念的に単純ですが、実装はプラットフォームごとに異なります。privileged なコンテナを避けること。ランタイムソケットのマウントを避けること。特別な理由がない限りコンテナに書き込み可能なホストパスを与えないこと。可能であれば user namespaces や rootless execution を使用すること。すべての capabilities を落とし、ワークロードが本当に必要とするものだけを戻すこと。互換性の問題を解決するために seccomp、AppArmor、SELinux を無効にするのではなく、有効なままにすること。侵害されたコンテナがホストに対して簡単にサービス拒否を引き起こせないようにリソースを制限すること。

イメージとビルドの衛生管理はランタイムの姿勢と同じくらい重要です。最小限のイメージを使用し、頻繁に再ビルドし、スキャンし、可能なら出所を要求し、レイヤーにシークレットを残さないようにします。非 root で動作し、小さいイメージで狭い syscall と capability のサーフェスを持つコンテナは、デバッグツールが事前にインストールされホストと同等の root で動作する大きな利便性優先のイメージよりもはるかに防御しやすいです。

## リソース枯渇の例

リソース制御は派手ではありませんが、妥当性の被害範囲（blast radius）を制限するためにコンテナセキュリティの一部です。メモリ、CPU、PID の制限がなければ、単純なシェルだけでホストや隣接するワークロードを劣化させるのに十分です。

ホストに影響を与えるテストの例:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
これらの例は、危険なコンテナの結果が必ずしもクリーンな「escape」ではないことを示しており、有用です。脆弱な cgroup 制限は、code execution を実際の運用上の影響に変えてしまう可能性があります。

## ハードニングツール

Docker 中心の環境では、`docker-bench-security` が広く認知されたベンチマークに基づくガイダンスと照らして一般的な設定問題をチェックするため、有用なホスト側の監査ベースラインであり続けます:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
このツールは threat modeling の代替にはなりませんが、時間の経過とともに蓄積する不注意な daemon、mount、network、および runtime のデフォルト設定を見つけるのに依然として有用です。

## チェック

評価時の簡易な一次確認コマンドとして、以下を使用してください：
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- 広範な権限を持ち、`Seccomp: 0` の root プロセスは即座の注意を要する。
- 疑わしいマウントやランタイムソケットは、多くの場合、いかなる kernel exploit よりも迅速にインパクトに至る経路を提供する。
- 脆弱なランタイム姿勢と緩いリソース制限の組み合わせは、通常、単一の隔離されたミスというよりも、一般的に許容的なコンテナ環境を示している。
