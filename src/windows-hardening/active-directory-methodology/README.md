# Active Directory методологія

{{#include ../../banners/hacktricks-training.md}}

## Основний огляд

**Active Directory** служить базовою технологією, що дозволяє **мережевим адміністраторам** ефективно створювати і керувати **домени**, **користувачами** та **обʼєктами** в мережі. Вона спроєктована для масштабування, дозволяючи організовувати велику кількість користувачів у керовані **групи** та **підгрупи**, а також контролювати **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **домени**, **дерева** та **ліси**. **Домен** охоплює набір обʼєктів, таких як **користувачі** чи **пристрої**, що ділять спільну базу даних. **Дерева** — це групи доменів, повʼязані спільною структурою, а **ліс** представляє собою колекцію кількох дерев, зʼєднаних через **trust relationships**, утворюючи найвищий рівень організаційної структури. На кожному з цих рівнів можна задавати конкретні **права доступу** та **права на комунікацію**.

Ключові поняття в **Active Directory** включають:

1. **Directory** – Містить всю інформацію про обʼєкти Active Directory.
2. **Object** – Означає сутності в каталозі, включаючи **користувачів**, **групи** або **спільні папки**.
3. **Domain** – Служить контейнером для обʼєктів каталогу; кілька domain можуть існувати в межах одного **forest**, кожен з яких має власний набір обʼєктів.
4. **Tree** – Групування доменів, які ділять спільний root domain.
5. **Forest** – Верхній рівень організаційної структури в Active Directory, що складається з кількох tree з **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює набір служб, критичних для централізованого управління та комунікації в мережі. До цих служб належать:

1. **Domain Services** – Централізує зберігання даних і керує взаємодією між **користувачами** та **доменами**, включаючи **аутентифікацію** та функції **пошуку**.
2. **Certificate Services** – Керує створенням, розподілом та обслуговуванням безпечних **цифрових сертифікатів**.
3. **Lightweight Directory Services** – Підтримує додатки, орієнтовані на каталог, через протокол **LDAP**.
4. **Directory Federation Services** – Забезпечує можливості **single-sign-on** для аутентифікації користувачів у кількох веб-застосунках в одній сесії.
5. **Rights Management** – Допомагає захищати авторські матеріали, регулюючи їх несанкціонований розподіл і використання.
6. **DNS Service** – Критично важлива для розвʼязання **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Шпаргалка

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Якщо у вас є доступ до середовища AD, але немає облікових даних/сесій, ви можете:

- **Pentest the network:**
- Сканувати мережу, знайти машини та відкриті порти і спробувати **експлуатувати вразливості** або **витягти облікові дані** з них (наприклад, [принтери можуть бути дуже цікавими цілями](ad-information-in-printers.md)).
- Перелічення DNS може дати інформацію про ключові сервери в домені, такі як web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Подивіться загальну [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), щоб знайти більше інформації про те, як це робити.
- **Перевірте null та Guest доступ на smb сервісах** (це не працюватиме на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Більш детальний гайд про те, як перерахувати SMB сервер, можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Перелічення LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Більш детальний гайд про те, як перерахувати LDAP, можна знайти тут (зверніть **особливу увагу на анонімний доступ**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Збирайте облікові дані, **імітуючи сервіси за допомогою Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Доступ до хоста шляхом [**зловживання relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирайте облікові дані, **експонуючи** [**фейкові UPnP сервіси за допомогою evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягайте імена користувачів/імена з внутрішніх документів, соціальних мереж, сервісів (головним чином web) у межах доменної інфраструктури, а також з загальнодоступних джерел.
- Якщо ви знайдете повні імена співробітників компанії, ви можете спробувати різні конвенції імен користувачів AD (**read this**). Найпоширеніші конвенції: _NameSurname_, _Name.Surname_, _NamSur_ (3 літери кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **невірний username**, сервер відповість з кодом помилки **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити, що username невірний. **Дійсні username** викличуть або **TGT в AS-REP** відповіді, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, що вказує на необхідність pre-authentication.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти інтерфейсу MS-NRPC (Netlogon) на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після біндингу MS-NRPC інтерфейсу, щоб перевірити, чи існує користувач або компʼютер без будь-яких облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип перелічення. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> Ви можете знайти списки імен користувачів у [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) і в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Однак ви повинні мати **імена людей, що працюють у компанії**, з етапу recon, який ви мали виконати раніше. Маючи ім'я та прізвище, ви можете використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційно дійсних імен користувачів.

### Knowing one or several usernames

Отже, ви вже знаєте, що маєте дійсне ім'я користувача, але немає паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо користувач **не має** атрибуту _DONT_REQ_PREAUTH_, ви можете **запитати AS_REP message** для цього користувача, яке міститиме дані, зашифровані похідною від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте найбільш **поширені паролі** для кожного виявленого користувача, можливо хтось використовує слабкий пароль (пам'ятайте про політику паролів!).
- Зауважте, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до поштових серверів користувачів.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете зуміти **отримати** деякі challenge **hashes** для crack, шляхом poisoning деяких протоколів **мережі**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося перелічити Active Directory, ви отримаєте **більше email-адрес та краще розуміння мережі**. Ви можете змусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) щоб отримати доступ до середовища AD.

### Steal NTLM Creds

Якщо ви можете **access other PCs or shares** з обліковим записом **null or guest user**, ви можете **розмістити файли** (наприклад SCF файл), які, якщо їх відкриють, **trigger an NTLM authentication against you**, щоб ви могли **steal** the **NTLM challenge** для його розкриття:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Для цього етапу вам потрібно мати **компрометовані облікові дані або сесію дійсного доменного облікового запису.** Якщо у вас є дійсні облікові дані або shell як доменний користувач, **пам'ятайте, що попередньо згадані варіанти все ще можуть використовуватись для компрометації інших користувачів.**

Перед початком аутентифікованого переліку ви повинні знати, що таке **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація облікового запису — це **великий крок для початку компрометації всього домену**, оскільки ви зможете почати **Active Directory Enumeration:**

Стосовно [**ASREPRoast**](asreproast.md) ви тепер можете знайти всіх можливих вразливих користувачів, а стосовно [**Password Spraying**](password-spraying.md) ви можете отримати **список усіх імен користувачів** і спробувати пароль скомпрометованого облікового запису, порожні паролі та інші перспективні паролі.

- Ви можете використати [**CMD для виконання базової розвідки**](../basic-cmd-for-pentesters.md#domain-info)
- Ви також можете використовувати [**powershell для розвідки**](../basic-powershell-for-pentesters/index.html), який буде менш помітним
- Ви також можете [**використати powerview**](../basic-powershell-for-pentesters/powerview.md) для отримання більш детальної інформації
- Ще один чудовий інструмент для розвідки в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже прихований** (залежно від методів збору, які ви використовуєте), але **якщо вам це не важливо**, варто спробувати. Знаходьте, куди користувачі можуть RDP, знаходьте шляхи до інших груп тощо.
- **Інші автоматизовані інструменти для переліку AD:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- **GUI-інструмент**, який можна використати для переліку каталогу — **AdExplorer.exe** з SysInternal Suite.
- Також можна шукати в LDAP базі за допомогою **ldapsearch**, щоб знайти облікові дані у полях _userPassword_ та _unixUserPassword_, або навіть у _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, ви також можете перелічити домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Ви також можете спробувати автоматизовані інструменти:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Отримання всіх доменних користувачів**

Дуже просто отримати всі імена користувачів домену з Windows (`net user /domain`, `Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration виглядає невеликим, це найважливіша частина. Відкрийте посилання (особливо ті на cmd, powershell, powerview і BloodHound), навчіться переліковувати домен і практикуйтесь, доки не відчуєте себе впевнено. Під час оцінювання це буде ключовий момент для знаходження шляху до DA або для вирішення, що нічого зробити не вдасться.

### Kerberoast

Kerberoasting включає отримання **TGS tickets**, які використовуються сервісами, прив'язаними до облікових записів користувачів, і розшифровку їх шифрування — яке базується на паролях користувачів — **офлайн**.

Більше про це в:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Після отримання облікових даних ви можете перевірити, чи маєте доступ до якоїсь **машини**. Для цього можна використати **CrackMapExec** для спроб підключення до кількох серверів різними протоколами згідно з вашими скануваннями портів.

### Local Privilege Escalation

Якщо ви скомпрометували облікові дані або сесію як звичайний доменний користувач і маєте **доступ** цією особою до **будь-якої машини в домені**, спробуйте знайти шлях до **підвищення привілеїв локально та витягання облікових даних**. Лише з локальними правами адміністратора ви зможете **дампити хеші інших користувачів** в пам'яті (LSASS) та локально (SAM).

У цій книзі є повна сторінка про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) та [**checklist**](../checklist-windows-privilege-escalation.md). Також не забудьте використати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** у поточного користувача, які дають вам дозвіл на доступ до несподіваних ресурсів, але ви можете перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося перелічити Active Directory, ви отримаєте **більше електронних адрес і краще розуміння мережі**. Можливо, ви зможете спровокувати NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Шукає Creds у Computer Shares | SMB Shares

Тепер, коли у вас є деякі базові облікові дані, перевірте, чи можете ви **знайти** будь‑які **цікаві файли, що шаряться в AD**. Ви можете робити це вручну, але це дуже нудне повторюване завдання (а ще гірше, якщо знайдете сотні документів, які потрібно перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про інструменти, які можна використовувати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Вкрасти NTLM Creds

Якщо ви можете отримати **доступ до інших ПК або shares**, ви можете **розмістити файли** (наприклад, SCF), які при доступі ініціюватимуть **NTLM authentication проти вас**, щоб ви могли **вкрасти** **NTLM challenge** для його зламу:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь‑якому автентифікованому користувачу **компрометувати domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Ескалація привілеїв в Active Directory З privileged credentials/session

**Для наступних технік звичайного domain user недостатньо — потрібні спеціальні привілеї/credentials для виконання цих атак.**

### Видобування хешів

Сподіваюсь, вам вдалося **скомпрометувати акаунт локального адміністратора** за допомогою [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) включно з relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Тоді настав час дампити всі хеші з пам'яті і локально.\
[**Прочитайте цю сторінку про різні способи отримання хешів.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Як тільки у вас є хеш користувача**, ви можете використовувати його, щоб **видаватися за нього**.\
Потрібно використати якийсь інструмент, який **виконає NTLM authentication з використанням** цього **хешу**, **або** ви можете створити новий **sessionlogon** і **інжектнути** цей **хеш** у **LSASS**, так що коли виконуватиметься будь‑яка **NTLM authentication**, буде використаний саме цей **хеш.** Останній варіант — те, що робить mimikatz.\
[**Прочитайте цю сторінку для додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати NTLM хеш користувача для запиту Kerberos tickets**, як альтернативу звичному Pass The Hash через NTLM протокол. Тому це може бути особливо **корисним у мережах, де протокол NTLM вимкнений** і лише **Kerberos** дозволений як протокол аутентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** атакуючі **крадуть authentication ticket користувача** замість його пароля або значень хешу. Цей вкрадений квиток потім використовується, щоб **видаватися за користувача**, отримуючи несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **хеш** або **пароль** **локального адміністратора**, спробуйте **увійти локально** на інші **PCs** з його допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **шумно**, і **LAPS** **зменшило б** це.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **access MSSQL instances**, він може використати це, щоб **execute commands** на хості MSSQL (якщо процес працює як SA), **steal** NetNTLM **hash** або навіть виконати **relay attack**.\
Крім того, якщо інстанція MSSQL є довіреною (database link) для іншої інстанції MSSQL, і користувач має привілеї над довіреною базою даних, він зможе **use the trust relationship to execute queries also in the other instance**. Ці довіри можуть бути зчеплені, і в якийсь момент користувач може знайти неправильно налаштовану базу даних, де зможе виконувати команди.\
**Зв'язки між базами даних працюють навіть через довіри між лісами.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні рішення для інвентаризації та розгортання часто відкривають потужні шляхи до облікових даних та виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який об'єкт Computer з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і у вас є доменні привілеї на цій машині, ви зможете дампити TGTs з пам'яті всіх користувачів, які входять на цю машину.\
Тож, якщо **Domain Admin logins onto the computer**, ви зможете дампити його TGT і видаватися за нього за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть могли б **автоматично скомпрометувати Print Server** (надіймося, що це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувач або комп'ютер дозволені для "Constrained Delegation", вони зможуть **impersonate any user to access some services in a computer**.\
Якщо ви **compromise the hash** цього користувача/комп'ютера, ви зможете **impersonate any user** (навіть domain admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Наявність привілею **WRITE** на об'єкті Active Directory віддаленого комп'ютера дозволяє досягти виконання коду з **підвищеними привілеями**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач може мати певні **цікаві привілеї над об'єктами домену**, які дозволять вам **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service listening** у домені може бути **abused** для **отримання нових облікових даних** та **ескалації привілеїв**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **інші користувачі** **access** скомпрометовану машину, можливо **gather credentials from memory** та навіть **inject beacons in their processes** для видачі себе за них.\
Зазвичай користувачі підключаються через RDP, тому тут показано, як виконати кілька атак над RDP-сесіями третіх сторін:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає систему для управління **local Administrator password** на комп'ютерах, приєднаних до домену, забезпечуючи його **рандомізацію**, унікальність та часту **зміну**. Ці паролі зберігаються в Active Directory, а доступ контролюється через ACLs тільки для авторизованих користувачів. Маючи достатні дозволи для доступу до цих паролів, можлива pivoting до інших комп'ютерів.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** із скомпрометованої машини може бути способом ескалації привілеїв у середовищі:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовано **vulnerable templates**, їх можна **abuse** для ескалації привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Отримавши **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **dump** базу даних домену: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, обговорених раніше, можна використати для персистенції.\
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

Атака **Silver Ticket** створює легітимний Ticket Granting Service (TGS) ticket для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash of the PC account**). Цей метод використовується для отримання **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** включає отримання доступу до **NTLM hash of the krbtgt account** в середовищі Active Directory. Цей обліковий запис особливий, оскільки він використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які є необхідними для автентифікації в мережі AD.

Отримавши цей hash, атакувач може створювати **TGTs** для будь-якого облікового запису (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це як golden tickets, підроблені таким чином, щоб **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Наявність сертифікатів облікового запису або можливість їх запитувати** — дуже хороший спосіб зберегти персистенцію в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання сертифікатів також дозволяє зберегти персистенцію з високими привілеями всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує безпеку **привілейованих груп** (наприклад, Domain Admins та Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп, щоб запобігти несанкціонованим змінам. Проте цю функцію можна використати зловмисно; якщо атакуючий змінить ACL AdminSDHolder, надавши повний доступ звичайному користувачу, цей користувач отримає широкий контроль над усіма привілейованими групами. Цей механізм безпеки, призначений для захисту, може негативно обернутися, дозволяючи небажаний доступ, якщо його не контролювати.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

У кожному **Domain Controller (DC)** існує локальний обліковий запис адміністратора. Отримавши admin-права на такій машині, можна витягти hash локального Administrator за допомогою **mimikatz**. Після цього необхідна модифікація реєстру, щоб **enable the use of this password**, що дозволяє віддалений доступ до облікового запису локального Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** деяким **користувачам спеціальні дозволи** над конкретними об'єктами домену, що дозволить цим користувачам **escalate privileges** у майбутньому.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **permissions**, які має **об'єкт**. Якщо ви зможете внести навіть **невелику зміну** до **security descriptor** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом без необхідності бути членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** в пам'яті, щоб встановити **універсальний пароль**, що надає доступ до всіх облікових записів домену.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP**, щоб **capture** у **clear text** **credentials**, які використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє **новий Domain Controller** в AD і використовує його для **push attributes** (SIDHistory, SPNs...) на вказані об'єкти **без** залишення логів щодо **змін**. Для цього потрібні привілеї DA та доступ до **root domain**.\
Зверніть увагу, що якщо ви використаєте неправильні дані, з'являться досить неприємні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалювати привілеї, якщо у вас є достатні дозволи для читання паролів LAPS. Проте ці паролі також можна використовувати для **підтримки персистенції**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **компрометація одного домену може потенційно призвести до компрометації всього Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дозволяє користувачу з одного **domain** отримувати доступ до ресурсів в іншому **domain**. Це створює зв'язок між системами автентифікації двох доменів, дозволяючи перевіркам автентичності проходити безшовно. Коли домени встановлюють довіру, вони обмінюються та зберігають певні **keys** у своїх **Domain Controllers (DCs)**, які критично важливі для цілісності довіри.

У типовому сценарії, якщо користувач хоче отримати доступ до сервісу у **trusted domain**, спочатку він має запросити спеціальний квиток, відомий як **inter-realm TGT**, у DC свого домену. Цей TGT зашифрований спільним **key**, який узгоджено між доменами. Користувач потім подає цей TGT до **DC of the trusted domain**, щоб отримати сервісний квиток (**TGS**). Після успішної валідації inter-realm TGT DC довіреного домену видає TGS, надаючи користувачу доступ до сервісу.

**Кроки**:

1. **Client computer** у **Domain 1** починає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт успішно аутентифікований.
3. Клієнт потім запрошує **inter-realm TGT** у DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. inter-realm TGT шифрується спільним **trust key**, який DC1 та DC2 ділять в рамках двосторонньої довіри доменів.
5. Клієнт передає inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT за допомогою свого спільного trust key і, якщо він дійсний, видає **Ticket Granting Service (TGS)** для сервера у Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред'являє цей TGS серверу, який зашифрований з hash облікового запису сервера, щоб отримати доступ до сервісу в Domain 2.

### Different trusts

Важливо зауважити, що **довіра може бути одно- або двосторонньою**. У варіанті з двосторонньою довірою обидва домени довіряють один одному, але в **one-way** відносинах один домен буде **trusted**, а інший — **trusting**. У останньому випадку **ви зможете отримати доступ лише до ресурсів у trusting domain з trusted domain**.

Якщо Domain A trusts Domain B, то A — trusting domain, а B — trusted domain. Більш того, у **Domain A** це буде **Outbound trust**; а у **Domain B** — **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Звичайна конфігурація в межах одного forest, де дочірній домен автоматично має двосторонню транзитивну довіру з батьківським доменом. Це означає, що запити автентифікації можуть проходити між батьком і дитиною без перешкод.
- **Cross-link Trusts**: Називають також "shortcut trusts", встановлюються між дочірніми доменами для пришвидшення процесів реферальності. У складних лісах запити автентифікації зазвичай мають підніматися до кореня forest і потім опускатися до цільового домену. Створюючи cross-links, цей шлях скорочується, що особливо корисно у географічно розподілених середовищах.
- **External Trusts**: Встановлюються між різними, не пов'язаними доменами і за своєю природою є non-transitive. За [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до ресурсів у домені поза поточним forest, який не підключений через forest trust. Безпека посилюється через SID filtering при external trusts.
- **Tree-root Trusts**: Ці довіри автоматично встановлюються між кореневим доменом forest і щойно доданим tree root. Хоча їх не часто зустрінеш, tree-root trusts важливі для додавання нових дерев доменів до forest, дозволяючи їм зберігати унікальне доменне ім'я і забезпечуючи двосторонню транзитивність. Більше інформації у [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Тип довіри, що є двосторонньою транзитивною довірою між двома кореневими доменами forest, також застосовує SID filtering для підвищення заходів безпеки.
- **MIT Trusts**: Встановлюються з невіконними, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos доменами. MIT trusts більш спеціалізовані й призначені для інтеграції з Kerberos-системами поза Windows-екосистемою.

#### Other differences in **trusting relationships**

- Довірчі відносини можуть бути також **transitive** (A trusts B, B trusts C, отже A trusts C) або **non-transitive**.
- Довіра може бути налаштована як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один довіряє іншому).

### Attack Path

1. **Enumerate** довірчі відносини
2. Перевірити, чи має будь-який **security principal** (user/group/computer) **access** до ресурсів **іншого домену**, можливо через ACE entries або шляхом членства в групах іншого домену. Шукайте **relationships across domains** (довіру, ймовірно, створено для цього).
1. kerberoast у цьому випадку може бути ще однією опцією.
3. **Compromise** облікові записи, які можуть **pivot** між доменами.

Атакуючі можуть отримати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, наприклад до групи “Administrators” на сервері, що надає значний контроль над цією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у чужому домені. Проте ефективність цього методу залежить від характеру довіри та області дії групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, особливо як сутності в **ACEs** всередині **DACL**, надаючи їм доступ до конкретних ресурсів. Для тих, хто хоче глибше зануритись в механіку ACLs, DACLs і ACEs, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є неоціненною ресурсом.

### Find external users/groups with permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у домені. Це будуть користувачі/групи з **зовнішнього домену/лісу**.

Ви можете перевірити це в **Bloodhound** або використовуючи **powerview**:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Ескалація привілеїв у лісі: від дочірнього до батьківського
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> Можна визначити, який із них використовує поточний домен, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалація до рівня Enterprise admin у child/parent domain, зловживаючи довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Важливо розуміти, як можна експлуатувати Configuration Naming Context (NC). Configuration NC слугує центральним сховищем конфігураційних даних по всьому лісу в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, при цьому writable DCs зберігають записувану копію Configuration NC. Для експлуатації цього механізму потрібні **SYSTEM привілеї на DC**, бажано на child DC.

**Link GPO to root DC site**

Контейнер Sites у Configuration NC містить інформацію про site'и всіх комп'ютерів, приєднаних до домену в AD-лісі. Маючи SYSTEM привілеї на будь-якому DC, атакуючі можуть прив'язувати GPO до root DC sites. Це потенційно ставить під загрозу root домен шляхом маніпуляції політиками, що застосовуються до цих sites.

Для детальнішої інформації можна ознайомитися з дослідженням [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Вектор атаки включає націлювання на привілейовані gMSA в домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM привілеї на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі для будь-якого gMSA по всьому лісу.

Детальний аналіз і покрокове керівництво доступні в:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Доповнююча делегована MSA-атака (BadSuccessor – зловживання атрибутами міграції):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткові зовнішні дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння — очікування створення нових привілейованих AD об'єктів. Маючи SYSTEM привілеї, атакуючий може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу й контролю над новоствореними AD об'єктами.

Детальніше можна прочитати у [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над об'єктами Public Key Infrastructure (PKI) для створення шаблону сертифіката, який дозволяє автентифікуватися як будь-який користувач у лісі. Оскільки PKI-об'єкти знаходяться в Configuration NC, компрометація writable child DC дозволяє виконати ESC5-атаки.

Більше деталей можна знайти в [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS атакуючий може підготувати необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **ваш domain має довіру з боку зовнішнього** і це дає вам **невизначені права** над ним. Вам потрібно з'ясувати, **які principals вашого domain мають який доступ до зовнішнього domain**, а потім спробувати скористатися цим:


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
У цьому сценарії **your domain** довіряє певні **privileges** principal з **different domains**.

Однак коли **domain is trusted** довіряючим доменом, довірений домен **creates a user** з **predictable name**, який використовує як **password the trusted password**. Це означає, що можливо **access a user from the trusting domain to get inside the trusted one** для його перебору та спроб підвищення привілеїв:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ще один спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **opposite direction** довіри доменів (що трапляється не дуже часто).

Ще один спосіб скомпрометувати довірений домен — перечекати на машині, до якої **user from the trusted domain can access** через **RDP**. Тоді атакуючий може інжектувати код у процес **RDP session** та звідти **access the origin domain of the victim**.\
Крім того, якщо **victim mounted his hard drive**, з процесу **RDP session** атакуючий може зберегти **backdoors** у **startup folder of the hard drive**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ризик атак, що використовують SID history attribute через forest trusts, пом'якшується SID Filtering, яке увімкнено за замовчуванням на всіх inter-forest trusts. Це ґрунтується на припущенні, що intra-forest trusts є безпечними, розглядаючи forest, а не domain, як межу безпеки, згідно з позицією Microsoft.
- Однак є нюанс: SID filtering може порушити роботу додатків і доступ користувачів, через що його іноді деактивують.

### **Selective Authentication:**

- Для inter-forest trusts використання Selective Authentication гарантує, що користувачі з двох лесів не автентифікуються автоматично. Натомість потрібні явні дозволи, щоб користувачі могли отримати доступ до доменів і серверів у trusting domain або forest.
- Важливо зазначити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Деякі загальні заходи захисту

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Рекомендується, щоб Domain Admins могли входити лише на Domain Controllers, уникаючи використання їхніх облікових записів на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з привілеями Domain Admin (DA) для збереження безпеки.
- **Temporal Privilege Limitation**: Для завдань, що вимагають DA привілеїв, слід обмежувати їх тривалість. Це можна зробити, наприклад, так: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Впровадження deception передбачає встановлення пасток, як-от фейкові користувачі або комп'ютери, з такими властивостями, як паролі, що не миняються, або позначені як Trusted for Delegation. Детальний підхід включає створення користувачів зі специфічними правами або додавання їх до груп з високими привілеями.
- Практичний приклад передбачає використання інструментів, наприклад: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deception techniques можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Підозрілі індикатори включають нетиповий ObjectSID, рідкі вхідні сесії, дати створення і низькі лічильники невдалих паролів.
- **General Indicators**: Порівняння атрибутів потенційних приманок з реальними об'єктами може виявити невідповідності. Інструменти, як-от [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster), можуть допомогти в ідентифікації таких deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Уникнення перерахунку сесій на Domain Controllers, щоб не триггерити ATA.
- **Ticket Impersonation**: Використання **aes** ключів для створення ticket-ів допомагає уникнути виявлення, оскільки це не приводить до пониження до NTLM.
- **DCSync Attacks**: Виконання атак не з Domain Controller, щоб уникнути виявлення ATA; виконання безпосередньо з Domain Controller викличе сповіщення.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
