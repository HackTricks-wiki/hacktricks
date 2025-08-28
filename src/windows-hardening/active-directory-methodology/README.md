# Active Directory Методологія

{{#include ../../banners/hacktricks-training.md}}

## Загальний огляд

**Active Directory** слугує базовою технологією, яка дозволяє **network administrators** ефективно створювати та керувати **domains**, **users** та **objects** у межах мережі. Вона спроєктована для масштабування, дозволяючи організовувати велику кількість користувачів у керовані **groups** і **subgroups**, одночасно контролюючи **access rights** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **domains**, **trees** та **forests**. **Domain** охоплює набір об’єктів, таких як **users** або **devices**, що використовують спільну базу даних. **Trees** — це групи таких доменів, пов’язані спільною структурою, а **forest** представляє собою колекцію кількох trees, взаємопов’язаних через **trust relationships**, утворюючи найвищий рівень організаційної структури. На кожному з цих рівнів можна призначати конкретні **access** та **communication rights**.

Ключові поняття в рамках **Active Directory** включають:

1. **Directory** – Містить усю інформацію, що стосується об’єктів Active Directory.
2. **Object** – Позначає сутності в каталозі, включаючи **users**, **groups** або **shared folders**.
3. **Domain** – Служить контейнером для об’єктів каталогу; у **forest** може бути декілька domain, кожен з власною колекцією об’єктів.
4. **Tree** – Групування domain, які мають спільний root domain.
5. **Forest** – Верхівка організаційної структури в Active Directory, що складається з кількох trees з **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює низку сервісів, критичних для централізованого управління та комунікації в мережі. Ці сервіси включають:

1. **Domain Services** – Централізує збереження даних і керує взаємодією між **users** та **domains**, включаючи **authentication** та **search** функціональність.
2. **Certificate Services** – Керує створенням, розповсюдженням та управлінням безпечними **digital certificates**.
3. **Lightweight Directory Services** – Підтримує directory-enabled додатки через протокол **LDAP**.
4. **Directory Federation Services** – Забезпечує **single-sign-on** для аутентифікації користувачів у кількох веб-додатках за одну сесію.
5. **Rights Management** – Допомагає захищати авторські матеріали, регулюючи їхнє несанкціоноване розповсюдження та використання.
6. **DNS Service** – Критично важливий для розв’язання **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Шпаргалка

Ви можете звернутись до [https://wadcoms.github.io/](https://wadcoms.github.io) щоб швидко переглянути які команди можна виконати для перечислення/експлуатації AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Збір інформації про Active Directory (без облікових даних/сесій)

Якщо у вас є доступ до середовища AD, але немає жодних облікових даних/сесій, ви можете:

- **Pentest the network:**
- Скануйте мережу, знаходьте машини та відкриті порти і намагайтеся **exploit vulnerabilities** або **extract credentials** з них (наприклад, [printers could be very interesting targets](ad-information-in-printers.md)).
- Перерахування DNS може дати інформацію про ключові сервери в domain як web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Погляньте на загальну [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) щоб знайти більше інформації про те, як це робити.
- **Check for null and Guest access on smb services** (це не працюватиме на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Детальніший гайд по перечисленню SMB сервера можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Детальніший гайд по перечисленню LDAP можна знайти тут (зверніть **особливу увагу на anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Збирайте облікові дані, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Доступ до хоста через **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирання облікових даних шляхом **exposing fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягуйте usernames/names з internal documents, social media, сервісів (головним чином web) всередині domain середовищ, а також з публічно доступних джерел.
- Якщо ви знайдете повні імена працівників компанії, можна спробувати різні AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші конвенції: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **invalid username**, сервер відповість помилкою Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити, що username є невірним. **Valid usernames** викличуть або **TGT in a AS-REP** відповідь, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, яка вказує, що користувач повинен виконати pre-authentication.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти MS-NRPC (Netlogon) інтерфейсу на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після прив’язки до MS-NRPC інтерфейсу, щоб перевірити, чи існує user або computer без будь-яких облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує такий тип перечислення. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> Ви можете знайти списки імен користувачів у [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  і в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Проте ви повинні мати **name of the people working on the company** з етапу recon, який ви мали виконати раніше. Маючи ім'я та прізвище, ви могли б використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційно валідних імен користувачів.

### Knowing one or several usernames

Ok, тож ви вже знаєте, що маєте валідний username, але немаєте паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете бути в змозі **obtain** деякі challenge **hashes** для crack при **poisoning** деяких протоколів **мережі**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Перерахування Active Directory WITH credentials/session

Для цього етапу вам потрібно **компрометувати credentials або session дійсного доменного акаунта.** Якщо у вас є які-небудь валідні credentials або shell як доменний користувач, **варто пам'ятати, що опції, наведені раніше, все ще можуть бути використані для компрометації інших користувачів.**

Перш ніж починати аутентифіковану enumeration, вам слід знати, що таке **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Перерахування

Компрометація акаунта — це **великий крок для початку компрометації всього домену**, тому що ви зможете почати **Active Directory Enumeration:**

Щодо [**ASREPRoast**](asreproast.md) ви тепер можете знайти кожного можливого вразливого користувача, а щодо [**Password Spraying**](password-spraying.md) ви можете отримати **список всіх usernames** і спробувати пароль від скомпрометованого аккаунта, пусті паролі та нові перспективні паролі.

- Ви можете використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Ви також можете використати [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде більш stealthy
- Ви також можете [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для витягання детальнішої інформації
- Ще один відмінний інструмент для recon в Active Directory — це [**BloodHound**](bloodhound.md). Він **не є дуже stealthy** (залежно від методів збору, які ви використовуєте), але **якщо вам це не важливо**, варто спробувати. Знайдіть, де користувачі можуть RDP, знайдіть шляхи до інших груп тощо.
- **Інші автоматизовані інструменти для AD enumeration:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- Інструмент з GUI для переліку директорії — **AdExplorer.exe** з **SysInternal** Suite.
- Ви також можете шукати в LDAP базі за допомогою **ldapsearch**, щоб знайти credentials у полях _userPassword_ & _unixUserPassword_, або навіть у _Description_. Див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, ви також можете перераховувати домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Ви також можете спробувати автоматизовані інструменти:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Витяг всіх domain users**

Дуже просто отримати всі імена користувачів домену з Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). В Linux ви можете використовувати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration виглядає коротким, це найважливіша частина. Відкрийте посилання (особливо ті про cmd, powershell, powerview і BloodHound), навчіться, як перераховувати домен та практикуйтеся, поки не відчуєте впевненості. Під час оцінки це буде ключовий момент, щоб знайти шлях до DA або вирішити, що нічого зробити не вдається.

### Kerberoast

Kerberoasting включає отримання **TGS tickets**, які використовуються сервісами, прив'язаними до user accounts, та crack їх шифрування — яке базується на user passwords — **offline**.

Детальніше про це в:


{{#ref}}
kerberoast.md
{{#endref}}

### Віддалене підключення (RDP, SSH, FTP, Win-RM, etc)

Коли ви отримали деякі credentials, ви можете перевірити, чи маєте доступ до якоїсь **machine**. Для цього можна використати **CrackMapExec** для спроб підключення до кількох серверів різними протоколами, відповідно до ваших port scans.

### Local Privilege Escalation

Якщо ви скомпрометували credentials або session як звичайний доменний користувач і маєте **access** цим користувачем до **будь-якої машини в домені**, вам слід спробувати знайти шлях до **escalate privileges locally and looting for credentials**. Це тому, що лише з локальними правами адміністратора ви зможете **dump hashes of other users** у пам'яті (LSASS) і локально (SAM).

Є окрема сторінка в цій книзі про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) і [**checklist**](../checklist-windows-privilege-escalation.md). Також не забудьте використати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Поточні Session Tickets

Досить **малоймовірно**, що ви знайдете **tickets** у поточного користувача, які дають вам дозвіл на доступ до несподіваних ресурсів, але ви можете перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося перелічити active directory, у вас буде **більше електронних адрес і краще розуміння мережі**. Ви можете змогти примусово виконати NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **find** якісь **interesting files being shared inside the AD**. Це можна зробити вручну, але це дуже нудне рутинне завдання (особливо якщо знайдете сотні документів, які треба перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які ви можете використати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **access other PCs or shares** ви могли б **place files** (like a SCF file), які, якщо їх якимось чином відкриють, **trigger an NTLM authentication against you**, щоб ви могли **steal** **the NTLM challenge** для його розкриття:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Для наведених технік звичайного доменного користувача недостатньо — потрібні спеціальні привілеї/облікові дані, щоб виконати ці атаки.**

### Hash extraction

Сподіваюсь, вам вдалося **compromise some local admin** акаунт, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Тоді настав час дампити всі хеші з пам'яті та локально.\
[**Прочитайте цю сторінку про різні способи отримання хешів.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Потрібно використати якийсь **tool**, який **perform** **the NTLM authentication using** that **hash**, **or** ви можете створити новий **sessionlogon** і **inject** цей **hash** у **LSASS**, тож коли відбувається будь-яка **NTLM authentication**, цей **hash буде використано.** Останній варіант — те, що робить mimikatz.\
[**Прочитайте цю сторінку для додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **use the user NTLM hash to request Kerberos tickets**, як альтернатива звичайному Pass The Hash через NTLM протокол. Через це це може бути особливо **useful in networks where NTLM protocol is disabled** і лише **Kerberos is allowed** як протокол аутентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** нападники **steal a user's authentication ticket** замість їх пароля або хешів. Цей викрадений ticket потім використовується для **impersonate the user**, отримуючи несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** **of a local administrato**r, ви повинні спробувати **login locally** на інші **PCs** з його допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **шумно**, і **LAPS** могло б **пом'якшити** це.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **доступу до MSSQL instances**, він може використати це, щоб **виконувати команди** на хості MSSQL (якщо сервіс працює як SA), **вкрасти** NetNTLM **hash** або навіть здійснити **relay attack**.\
Також, якщо інстанс MSSQL довірений (database link) іншим інстансом MSSQL, і користувач має привілеї над довіреною базою даних, він зможе **використати відносини довіри для виконання запитів також в іншому інстансі**. Ці довіри можуть бути зчеплені ланцюжком і зрештою користувач може знайти неконфігуровану базу даних, де він зможе виконувати команди.\
**Зв'язки між базами даних працюють навіть через forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні інструменти інвентаризації та розгортання часто відкривають потужні шляхи до credentials та виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і у вас є domain привілеї на цьому комп'ютері, ви зможете дампити TGTs з пам'яті всіх користувачів, які входять на цей комп'ютер.\
Отже, якщо **Domain Admin увійде на цей комп'ютер**, ви зможете дампити його TGT і імітувати його за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть могли б **автоматично скомпрометувати Print Server** (сподіваюсь, це не буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувачу або комп'ютеру дозволено "Constrained Delegation", він зможе **імітувати будь-якого користувача для доступу до певних сервісів на комп'ютері**.\
Отже, якщо ви **компрометуєте hash** цього користувача/комп'ютера, ви зможете **імітувати будь-якого користувача** (навіть domain admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Маючи **WRITE** привілей на Active Directory об'єкті віддаленого комп'ютера, можна досягти виконання коду з **підвищеними привілеями**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач може мати деякі **цікаві привілеї над певними domain об'єктами**, що дозволить вам пізніше **рухатись латерально/ескалювати привілеї**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **списку Spool service, що слухає** в домені можна **зловживати**, щоб **отримати нові credentials** та **ескалювати привілеї**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **інші користувачі** **доступаються** до **скомпрометованої** машини, можливо **збирати credentials з пам'яті** і навіть **інжектувати beacons в їхні процеси**, щоб імітувати їх.\
Зазвичай користувачі підключаються через RDP, тож тут показано, як виконати кілька атак на сесії RDP третіх сторін:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** забезпечує систему для керування **паролем локального Administrator** на комп'ютерах, приєднаних до домену, гарантуючи, що він **рандомізований**, унікальний та часто **змінюється**. Ці паролі зберігаються в Active Directory і доступ контролюється через ACLs лише для авторизованих користувачів. Маючи достатні permissions для доступу до цих паролів, можливе pivot до інших комп'ютерів.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Збирання certificates** зі скомпрометованої машини може бути шляхом для ескалації привілеїв всередині середовища:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовані **вразливі templates**, їх можна зловживати для ескалації привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Отримавши **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **дампити** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, описаних вище, можна використовувати для persistence.\
Наприклад, ви можете:

- Зробити користувачів вразливими до [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити користувачів вразливими до [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати [**DCSync**](#dcsync) привілеї користувачу

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Атака **Silver Ticket** створює **легітимний Ticket Granting Service (TGS) ticket** для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash PC account**). Цей метод використовується для **доступу до привілеїв сервісу**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** полягає в отриманні зловмисником **NTLM hash облікового запису krbtgt** в Active Directory. Цей акаунт особливий, оскільки використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, що необхідні для автентифікації в AD мережі.

Отримавши цей hash, зловмисник може створювати **TGTs** для будь-якого облікового запису, якого він забажає (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схожі на golden tickets, підроблені таким чином, щоб **оминути поширені механізми виявлення golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Маючи certificates облікового запису або можливість їх запитувати** — це дуже хороший спосіб зберегти persistence в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання certificates також дозволяє зберегти високу привілейованість всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує захист **привілейованих груп** (наприклад Domain Admins і Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп, щоб запобігти несанкціонованим змінам. Проте ця функція може бути зловживана; якщо зловмисник змінить ACL AdminSDHolder, щоб надати повний доступ звичайному користувачу, цей користувач отримає широкі права над усіма привілейованими групами. Цей захід безпеки, призначений для захисту, може виявитися протилежним, дозволяючи небажаний доступ, якщо його не моніторити уважно.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

На кожному **Domain Controller (DC)** існує **локальний administrator** акаунт. Отримавши admin права на такій машині, можна витягти локальний Administrator hash за допомогою **mimikatz**. Після цього необхідно змінити реєстр, щоб **дозволити використання цього пароля**, що дасть віддалений доступ до локального Administrator акаунту.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** деяким **спеціальним permissions** **користувачу** на певні domain об'єкти, що дозволить цьому користувачу **ескалювати привілеї в майбутньому**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання permissions**, які має **об'єкт**. Якщо ви зможете зробити навіть **маленьку зміну** в **security descriptor** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом без необхідності бути членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** в пам'яті, щоб встановити **універсальний пароль**, який дає доступ до всіх domain акаунтів.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP**, щоб **захоплювати** в **чистому тексті** **credentials**, які використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Реєструє **новий Domain Controller** в AD і використовує його для **push атрибутів** (SIDHistory, SPNs...) на вказані об'єкти **без** залишення будь-яких **логів** щодо **змін**. Вам потрібні DA привілеї і бути в **root domain**.\
Зауважте, що якщо ви використаєте неправильні дані, з'являться досить помітні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалювати привілеї, якщо у вас є **достатні permissions для читання LAPS passwords**. Однак ці паролі також можна використовувати для **підтримки persistence**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft вважає **Forest** межою безпеки. Це означає, що **компрометація одного домену може потенційно призвести до компрометації всього Forest**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дозволяє користувачу з одного **домену** отримувати доступ до ресурсів в іншому **домені**. Він фактично створює зв'язок між автентифікаційними системами двох доменів, дозволяючи перевіркам автентифікації проходити безперешкодно. Коли домени налаштовують trust, вони обмінюються і зберігають певні **keys** у своїх **Domain Controllers (DCs)**, які важливі для цілісності довіри.

В типовому сценарії, якщо користувач прагне отримати доступ до сервісу в **trusted domain**, спочатку йому потрібно запросити спеціальний квиток, відомий як **inter-realm TGT**, від DC свого домену. Цей TGT шифрується з використанням shared **key**, який обидва домени погодилися використовувати. Користувач потім пред'являє цей TGT **DC trusted domain**, щоб отримати service ticket (**TGS**). Після успішної валідації inter-realm TGT DC trusted domain видає TGS, надаючи користувачу доступ до сервісу.

**Кроки**:

1. **Client computer** в **Domain 1** починає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** від свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт автентифікувався успішно.
3. Клієнт потім запитує **inter-realm TGT** від DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. Inter-realm TGT шифрується з допомогою **trust key**, спільного між DC1 та DC2 як частина двосторонньої domain trust.
5. Клієнт доставляє inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT, використовуючи свій спільний trust key, і, якщо він дійсний, видає **Ticket Granting Service (TGS)** для сервера у Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред'являє цей TGS серверу, який зашифрований з hash акаунту сервера, щоб отримати доступ до сервісу в Domain 2.

### Different trusts

Важливо зауважити, що **trust може бути одно- або двостороннім**. У варіанті двох сторін обидва домени довіряють один одному, але в **односпрямованому** відношенні один із доменів буде **trusted**, а інший — **trusting**. У останньому випадку **ви зможете доступатися лише до ресурсів всередині trusting domain з trusted domain**.

Якщо Domain A trusts Domain B, то A — trusting domain, а B — trusted. Крім того, в **Domain A** це буде **Outbound trust**; а в **Domain B** — **Inbound trust**.

**Різні типи відносин довіри**

- **Parent-Child Trusts**: Поширена конфігурація в межах одного forest, де дочірній домен автоматично має двосторонню транзитивну довіру з його батьківським доменом. Це означає, що запити автентифікації можуть вільно проходити між батьком і дочкою.
- **Cross-link Trusts**: Звані "shortcut trusts", вони встановлюються між дочірніми доменами для прискорення процесів реферування. У складних лісах реферування автентифікації зазвичай мають їхати до forest root, а потім вниз до цільового домену. Створюючи cross-links, шлях скорочується, що особливо корисно в географічно розподілених середовищах.
- **External Trusts**: Налаштовуються між різними, несуміжними доменами і за своєю природою не є транзитивними. За документацією Microsoft, external trusts корисні для доступу до ресурсів у домені поза поточним forest, який не пов'язаний forest trust. Безпеку підсилюють за допомогою SID filtering при external trusts.
- **Tree-root Trusts**: Ці довіри автоматично встановлюються між forest root domain і новоствореним tree root. Хоча зустрічаються рідко, tree-root trusts важливі при додаванні нових domain trees до forest, дозволяючи їм зберігати унікальну доменну назву і забезпечуючи двосторонню транзитивність. Більше інформації в [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Цей тип trust — двосторонній транзитивний trust між двома forest root domains, також забезпечує SID filtering для підвищення заходів безпеки.
- **MIT Trusts**: Ці довіри встановлюються з не-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos доменами. MIT trusts більш спеціалізовані й призначені для інтеграції з Kerberos-системами поза Windows-екосистемою.

#### Інші відмінності в **trusting relationships**

- Відносини довіри можуть бути також **транзитивними** (A trusts B, B trusts C, тоді A trusts C) або **нетранзитивними**.
- Відносини довіри можуть бути налаштовані як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один довіряє іншому).

### Attack Path

1. **Перелічити** trusting relationships
2. Перевірити, чи будь-який **security principal** (user/group/computer) має **доступ** до ресурсів **іншого домену**, можливо через ACE entries або шляхом перебування в групах іншого домену. Шукайте **відносини між доменами** (довіра була створена саме для цього).
1. kerberoast у цьому випадку може бути ще одним варіантом.
3. **Компрометувати** **акаунти**, які можуть **півотитись** через домени.

Атакуючі можуть отримати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, таких як група “Administrators” на сервері, що дає їм значний контроль над цією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у чужому домені. Проте ефективність цього методу залежить від природи довіри та області застосування групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, особливо як сутності в **ACEs** всередині **DACL**, надаючи їм доступ до певних ресурсів. Для тих, хто хоче глибше зрозуміти механіку ACLs, DACLs та ACEs, варто прочитати whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.

### Find external users/groups with permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** щоб знайти foreign security principals у домені. Це будуть user/group з **зовнішнього домену/forest**.

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
> Є **2 довірені ключі**, один для _Child --> Parent_ і інший для _Parent_ --> _Child_.\
> Ви можете побачити, який використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Підніміться до Enterprise admin у child/parent domain, зловживаючи довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), є критично важливим. Configuration NC служить централізованим сховищем конфігураційних даних по всьому forest в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у forest, причому writable DC підтримують записувану копію Configuration NC. Щоб скористатися цим, потрібно мати **SYSTEM privileges on a DC**, бажано на child DC.

**Link GPO to root DC site**

Контейнер Sites у Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, у межах AD forest. Маючи **SYSTEM privileges** на будь-якому DC, нападник може link GPOs до root DC sites. Ця дія потенційно підриває безпеку root domain шляхом маніпулювання політиками, застосованими до цих сайтів.

Для детальної інформації можна переглянути дослідження про [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Один вектор атаки полягає в націлюванні на привілейовані gMSA в домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи **SYSTEM privileges on any DC**, можна отримати доступ до KDS Root key і обчислити паролі будь-якого gMSA по всьому forest.

Детальний аналіз та покрокові інструкції наведені в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Доповнююча делегована атака на MSA (BadSuccessor — зловживання атрибутами міграції):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткові зовнішні дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння — очікування створення нових привілейованих AD об'єктів. Маючи **SYSTEM privileges**, нападник може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD об'єктами.

Додаткове читання доступне за посиланням: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над об'єктами PKI для створення шаблону сертифіката, який дозволяє аутентифікуватися як будь-який користувач у межах forest. Оскільки об'єкти PKI розташовані в Configuration NC, компрометація writable child DC дозволяє виконати ESC5-атаки.

Більше деталей можна прочитати в [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS нападник може налаштувати необхідні компоненти, як обговорюється в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Зовнішній Forest Domain - One-Way (Inbound) or bidirectional
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
У цьому сценарії **ваш domain довірений** зовнішнім, що надає вам **невизначені дозволи** над ним. Вам потрібно з'ясувати, **які principals вашого domain мають який доступ до зовнішнього domain**, а потім спробувати це експлуатувати:


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
У цьому сценарії **your domain** довіряє певні **privileges** сутності з **different domains**.

Проте, коли **domain is trusted** довіреною доменом, trusted domain **creates a user** з **predictable name**, який використовує як пароль **the trusted password**. Це означає, що можливо **access a user from the trusting domain to get inside the trusted one** для його перерахунку та подальшого підвищення привілеїв:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб компрометації trusted domain — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений в **протилежному напрямку** довіри домену (що трапляється не дуже часто).

Ще один спосіб компрометації trusted domain — очікувати на машині, куди **user from the trusted domain can access**, щоб увійти через **RDP**. Тоді нападник може інжектувати код у процес сесії RDP та **access the origin domain of the victim** звідти.\
Більше того, якщо **victim mounted his hard drive**, то з процесу **RDP session** атакуючий може зберегти **backdoors** у **startup folder of the hard drive**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через forest trusts, пом'якшується завдяки SID Filtering, яке активоване за замовчуванням на всіх inter-forest trusts. Це ґрунтується на припущенні, що intra-forest trusts є безпечними, розглядаючи forest, а не domain, як межу безпеки відповідно до позиції Microsoft.
- Однак є нюанс: SID filtering може порушити роботу додатків і доступ користувачів, через що його іноді деактивують.

### **Selective Authentication:**

- Для inter-forest trusts використання Selective Authentication гарантує, що користувачі з обох лесів не автентифікуються автоматично. Натомість потрібні явні дозволи, щоб користувачі могли отримати доступ до доменів і серверів у trusting domain або forest.
- Важливо зазначити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Рекомендується, щоб Domain Admins могли входити лише на Domain Controllers, уникаючи їхнього використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з privileges Domain Admin (DA) для підтримки безпеки.
- **Temporal Privilege Limitation**: Для завдань, що вимагають DA привілеїв, слід обмежувати їхню тривалість. Це можна досягти за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Впровадження deception включає встановлення пасток, як-от приманкові users або computers, з такими ознаками, як паролі, що не спливають, або позначення як Trusted for Delegation. Детальний підхід включає створення користувачів з певними правами або додавання їх до груп з високими привілеями.
- Практичний приклад включає використання інструментів на кшталт: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deception techniques можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Підозрілі індикатори включають нетиповий ObjectSID, рідкісні входи, дати створення та малу кількість неправильних паролів.
- **General Indicators**: Порівняння атрибутів потенційних приманкових об'єктів з реальних може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти в ідентифікації таких deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Уникати перебору сесій на Domain Controllers, щоб запобігти виявленню ATA.
- **Ticket Impersonation**: Використання **aes** keys для створення квитків допомагає уникнути виявлення, не понижуючи до NTLM.
- **DCSync Attacks**: Рекомендується виконувати з не-Domain Controller, щоб уникнути виявлення ATA, оскільки безпосереднє виконання з Domain Controller спричинить сповіщення.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
