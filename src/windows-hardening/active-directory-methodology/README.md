# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Базовий огляд

**Active Directory** є базовою технологією, яка дозволяє ефективно створювати та керувати **домени**, **користувачами** та **об'єктами** в межах мережі. Вона створена із забезпеченням масштабованості — дозволяє організувати велику кількість користувачів у керовані **групи** та **підгрупи**, а також контролювати **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **domains**, **trees** та **forests**. **Domain** охоплює набір об'єктів, таких як **users** або **devices**, які мають спільну базу даних. **Trees** — це групи доменів, пов'язані спільною структурою, а **forest** представляє собою колекцію кількох trees, з'єднаних через **trust relationships**, формуючи верхній рівень організаційної структури. На кожному з цих рівнів можна задавати конкретні **access** та **communication rights**.

Ключові поняття в **Active Directory** включають:

1. **Directory** – містить всю інформацію, що стосується об'єктів Active Directory.
2. **Object** – позначає сутності в каталозі, включаючи **users**, **groups** або **shared folders**.
3. **Domain** – слугує контейнером для об'єктів каталогу; у **forest** може існувати кілька domains, кожен з власною колекцією об'єктів.
4. **Tree** – групування доменів, що ділять спільний root domain.
5. **Forest** – верхній рівень організаційної структури в Active Directory, що складається з кількох trees з **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює низку сервісів, критично важливих для централізованого керування та комунікації в мережі. Ці сервіси включають:

1. **Domain Services** – централізує зберігання даних і керує взаємодією між **users** та **domains**, включаючи **authentication** та **search** функціональність.
2. **Certificate Services** – відповідає за створення, розповсюдження та керування цифровими **certificates**.
3. **Lightweight Directory Services** – підтримує додатки, що використовують каталог через протокол **LDAP**.
4. **Directory Federation Services** – надає можливості **single-sign-on** для аутентифікації користувачів у кількох веб-додатках в одній сесії.
5. **Rights Management** – допомагає захищати авторські матеріали, регулюючи їх несанкціоноване розповсюдження та використання.
6. **DNS Service** – критично важлива для розв'язання **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися атакувати AD, потрібно добре розуміти процес аутентифікації **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Шпаргалка

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Розвідка Active Directory (No creds/sessions)

Якщо у вас є доступ до середовища AD, але немає облікових даних/сесій, ви можете:

- **Pentest the network:**
- Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them (наприклад, [printers could be very interesting targets](ad-information-in-printers.md)).
- Перелічення DNS може надати інформацію про ключові сервери в домені — web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Ознайомтеся з загальною [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) для детальнішої інформації про те, як це робити.
- **Check for null and Guest access on smb services** (це не працюватиме на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Детальніший посібник з переліку SMB-сервера можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Детальніший посібник з переліку LDAP доступний тут (зверніть **особливу увагу на anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
- Якщо ви знайдете повні імена працівників компанії, можна спробувати різні AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Найпоширеніші convention-и: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Anonymous SMB/LDAP enum:** Перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **invalid username**, сервер відповість використовуючи **Kerberos error** код _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити, що ім'я користувача невірне. **Valid usernames** викличуть або **TGT in a AS-REP** відповідь, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, що вказує на необхідність pre-authentication для користувача.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти MS-NRPC (Netlogon) інтерфейсу на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після биндингу MS-NRPC інтерфейсу, щоб перевірити, чи існує користувач або комп'ютер без будь-яких облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує такий тип переліку. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви знайшли один із таких серверів у мережі, ви також можете виконати **user enumeration against it**. Наприклад, ви можете використовувати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки usernames у [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) та в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Проте ви повинні мати **імена та прізвища людей, які працюють у компанії** з етапу recon, який ви мали виконати раніше. Маючи ім'я та прізвище, ви можете скористатися скриптом [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційних валідних usernames.

### Knowing one or several usernames

Добре, отже ви вже знаєте, що маєте валідний username, але немаєте паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо у користувача **немає** атрибута _DONT_REQ_PREAUTH_ ви можете **запросити AS_REP message** для цього користувача, який міститиме дані, зашифровані похідною від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте найпоширеніші **common passwords** для кожного з виявлених користувачів, можливо якийсь користувач використовує слабкий пароль (не забудьте про password policy!).
- Зверніть увагу, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до поштових серверів користувачів.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете отримати деякі challenge **hashes** для cracking, отруюючи певні протоколи **мережі**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося перерахувати Active Directory, ви отримаєте **більше email-ів та краще розуміння мережі**. Можливо, ви зможете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), щоб отримати доступ до AD env.

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або share-ів** з **null або guest user**, ви можете **розмістити файли** (наприклад SCF file), які, якщо їх якимось чином відвідають, спровокують **NTLM authentication проти вас**, тож ви зможете **забрати** **NTLM challenge** для cracking:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

На цьому етапі вам потрібно мати **скомпрометовані credentials або сесію валідного domain account.** Якщо у вас є деякі валідні credentials або shell як domain user, **пам'ятайте, що опції, наведені раніше, все ще залишаються способами скомпрометувати інших користувачів**.

Перш ніж починати authenticated enumeration, ви повинні знати, що таке **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Скомпрометувати обліковий запис — це **великий крок до компрометації всього домену**, тому що ви зможете розпочати **Active Directory Enumeration:**

Щодо [**ASREPRoast**](asreproast.md) ви тепер можете знайти кожного потенційно вразливого користувача, а щодо [**Password Spraying**](password-spraying.md) ви можете отримати **список усіх usernames** і спробувати пароль скомпрометованого облікового запису, пусті паролі та нові перспективні паролі.

- Ви можете використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна користуватися [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде більш stealthy
- Також можна [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для витягнення детальнішої інформації
- Ще один чудовий інструмент для recon в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежить від методів збору, які ви використовуєте), але **якщо вас це не хвилює**, обов'язково спробуйте. Знайдіть, де користувачі можуть RDP, шляхи до інших груп тощо.
- **Інші автоматизовані інструменти для AD enumeration:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- Інструмент з GUI, який можна використати для перерахування каталогу — **AdExplorer.exe** із **SysInternal** Suite.
- Ви також можете шукати в LDAP базі за допомогою **ldapsearch**, щоб знайти credentials у полях _userPassword_ & _unixUserPassword_, або навіть у _Description_. Див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, ви також можете перерахувати домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Ви також можете спробувати автоматизовані інструменти:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Дуже просто отримати всі usernames домену з Windows (`net user /domain` ,`Get-DomainUser` або `wmic useraccount get name,sid`). У Linux можна використовувати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо цей розділ Enumeration виглядає невеликим, це найважливіша частина. Перейдіть по посиланнях (особливо тим, що стосуються cmd, powershell, powerview і BloodHound), навчіться, як перераховувати домен і практикуйтеся, доки не відчуєте впевненість. Під час оцінювання це буде ключовий момент, щоб знайти шлях до DA або вирішити, що нічого зробити не можна.

### Kerberoast

Kerberoasting передбачає отримання **TGS tickets**, які використовуються службами, прив'язаними до user accounts, і offline cracking їхнього шифрування — яке базується на user passwords.

Детальніше:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Після отримання деяких credentials ви можете перевірити, чи маєте доступ до якоїсь **машини**. Для цього ви можете використати **CrackMapExec**, щоб спробувати з'єднання з кількома серверами через різні протоколи відповідно до вашого port scan.

### Local Privilege Escalation

Якщо ви скомпрометували credentials або сесію як звичайний domain user і маєте **доступ** цим користувачем до **будь-якої машини в домені**, вам слід спробувати знайти спосіб **підвищити привілеї локально та пошукати credentials**. Це тому, що лише з локальними правами адміністратора ви зможете **дампити хеші інших користувачів** з пам'яті (LSASS) та локально (SAM).

У цій книзі є повна сторінка про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) і [**checklist**](../checklist-windows-privilege-escalation.md). Також не забувайте використовувати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** у поточного користувача, які **дають вам дозвіл доступатися** до несподіваних ресурсів, але ви можете перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося просканувати Active Directory, у вас буде **більше емейлів та краще розуміння мережі**. Ви можете змогти примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Пошук Creds у спільних папках на комп'ютерах | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **знайти** будь-які **цікаві файли, що шаряться всередині AD**. Це можна робити вручну, але це дуже нудне повторюване завдання (і ще більше, якщо ви знайдете сотні документів, які потрібно перевірити).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або шарів**, ви можете **розмістити файли** (наприклад SCF file), які у випадку їх відкриття t**запустять NTLM-аутентифікацію проти вас**, щоб ви могли **вкрасти** **NTLM challenge** для його зламу:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому **авторизованому користувачу** **компрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Підвищення привілеїв в Active Directory З привілейованими обліковими даними/сесією

**Для наведених нижче технік звичайного користувача домену недостатньо, вам потрібні спеціальні привілеї/облікові дані для виконання цих атак.**

### Hash extraction

Сподіваюсь, вам вдалося **компрометувати якийсь обліковий запис локального адміністратора** за допомогою [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) включаючи relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Потім час дампити всі хеші з пам'яті та локально.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, ви можете використовувати його для **імітації цього користувача**.\
Потрібно використати якийсь **інструмент**, що **здійснить NTLM-аутентифікацію з використанням** цього **hash**, **або** можна створити новий **sessionlogon** і **інжектнути** цей **hash** в **LSASS**, так що при будь-якій **NTLM-аутентифікації** буде використовуватися саме цей **hash.** Останній варіант реалізує mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати NTLM hash користувача для запиту Kerberos квитків**, як альтернативу поширеному Pass The Hash через NTLM протокол. Тому це може бути особливо **корисним у мережах, де NTLM вимкнений**, і дозволено лише **Kerberos** як протокол автентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки Pass The Ticket (PTT) зловмисники **викрадають автентифікаційний квиток користувача** замість його пароля або хешів. Цей викрадений квиток потім використовується для **імітації користувача**, отримуючи несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** **локального адміністратора**, слід спробувати **login locally** на інших **PCs** з його використанням.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, це доволі **шумно** і **LAPS** **пом’якшить** це.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **доступу до MSSQL instances**, він може використати це, щоб **виконувати команди** на хості MSSQL (якщо процес працює як SA), **вкрасти** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Також, якщо MSSQL instance є trusted (database link) іншим MSSQL instance. Якщо користувач має привілеї над trusted database, він зможе **використати довірчі відносини, щоб виконувати запити також в іншій інстанції**. Ці довірчі зв'язки можна ланцюжити і в якийсь момент користувач може знайти неправильно сконфігуровану базу даних, де він зможе виконувати команди.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні набори для інвентаризації та розгортання часто відкривають потужні шляхи до облікових даних і виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
Отже, якщо **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть можете **автоматично скомпрометувати Print Server** (сподіваюсь, це буде a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Тоді, якщо ви **скомпрометуєте the hash** цього користувача/комп'ютера, ви зможете **імітувати будь-якого користувача** (навіть Domain Admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Маючи привілей **WRITE** над об'єктом Active Directory віддаленого комп'ютера, можна досягти виконання коду з **підвищеними привілеями**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Компрометований користувач може мати деякі **цікаві привілеї над деякими об'єктами домену**, що дозволяють вам **пересуватися латерально / підвищувати привілеї**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **служби Spool, що слухає** у домені може бути **зловживано** для **отримання нових облікових даних** та **ескалації привілеїв**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **інші користувачі** **доступаються** до **компрометованої** машини, можливо **зібрати облікові дані з пам'яті** і навіть **інжектувати beacons у їхні процеси**, щоб імітувати їх.\
Зазвичай користувачі підключаються до системи через RDP, тому тут показано, як виконати декілька атак над сесіями RDP третіх сторін:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** забезпечує систему для керування **локальним Administrator password** на комп'ютерах, приєднаних до домену, гарантуючи, що він **рандомізований**, унікальний і часто **змінюється**. Ці паролі зберігаються в Active Directory, а доступ контролюється через ACLs тільки авторизованим користувачам. Маючи достатні права для доступу до цих паролів, можливе pivoting на інші комп'ютери.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Збір сертифікатів** з компрометованої машини може бути способом ескалації привілеїв у середовищі:


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

Отримавши **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **зняти** **базу даних домену**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з прийомів, описаних вище, можуть бути використані для персистенції.\
Наприклад, ви можете:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати [**DCSync**](#dcsync) привілеї користувачу

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Атака **Silver Ticket** створює **легітимний Ticket Granting Service (TGS) квиток** для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash облікового запису PC**). Цей метод застосовується для отримання **привілеїв доступу до сервісу**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** передбачає, що нападник отримує доступ до **NTLM hash** облікового запису **krbtgt** в Active Directory. Цей обліковий запис особливий, бо він використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які є необхідними для аутентифікації в AD-мережі.

Отримавши цей hash, нападник може створювати **TGTs** для будь-якого облікового запису на свій розсуд (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це подібно до golden tickets, підроблених таким чином, щоб **обійти поширені механізми виявлення golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Наявність сертифікатів облікового запису або можливість їх запитувати** — дуже хороший спосіб зберегти персистенцію в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання сертифікатів також дозволяє підтримувати персистенцію з високими привілеями всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує безпеку **привілейованих груп** (наприклад, Domain Admins та Enterprise Admins) шляхом застосування стандартного **Access Control List (ACL)** до цих груп для запобігання несанкціонованим змінам. Проте, ця функція може бути експлуатована; якщо нападник змінить ACL AdminSDHolder, надавши повний доступ звичайному користувачу, цей користувач отримає розширений контроль над усіма привілейованими групами. Цей захід безпеки, призначений для захисту, може, таким чином, мати зворотний ефект і дозволити небажаний доступ, якщо його не контролювати уважно.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Всередині кожного **Domain Controller (DC)** існує обліковий запис **локального адміністратора**. Отримавши адміністраторські права на такій машині, можна витягти хеш локального Administrator за допомогою **mimikatz**. Після цього потрібно змінити реєстр, щоб **дозволити використання цього пароля**, що дає змогу віддалено заходити під обліковим записом локального Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **надати** певному **користувачу** **спеціальні дозволи** над конкретними об'єктами домену, що дозволить цьому користувачу **ескалувати привілеї в майбутньому**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **дозволів**, які має **об'єкт**. Якщо ви зробите навіть **невелику зміну** в **security descriptor** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом без необхідності бути членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** у пам'яті, щоб встановити **універсальний пароль**, що дає доступ до всіх облікових записів домену.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP**, щоб **перехоплювати в clear text** **облікові дані**, які використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє **новий Domain Controller** в AD і використовує його для **push attributes** (SIDHistory, SPNs...) на вказані об'єкти **без** створення якихось **логів** щодо **змін**. Вам потрібні привілеї **DA** та бути в **root domain**.\
Зверніть увагу, що якщо ви використаєте неправильні дані, з'являться доволі помітні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалювати привілеї, якщо у вас є **достатні права для читання паролів LAPS**. Однак ці паролі також можна використовувати для **підтримки персистенції**.\
Перегляньте:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **компрометація одного домену може потенційно призвести до компрометації всього Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, який дозволяє користувачу з одного **домену** отримувати доступ до ресурсів в іншому **домені**. По суті, це створює зв'язок між системами автентифікації двох доменів, дозволяючи перевіркам автентифікації проходити безшовно. Коли домени встановлюють довіру, вони обмінюються і зберігають певні **ключі** у своїх **Domain Controllers (DCs)**, які є критичними для цілісності цієї довіри.

У типовому сценарії, якщо користувач має намір отримати доступ до сервісу в **trusted domain**, він спочатку повинен запросити спеціальний квиток, відомий як **inter-realm TGT**, у DC свого власного домену. Цей TGT шифрується спільним **ключем**, наданим обома доменами. Користувач потім пред'являє цей inter-realm TGT **DC trusted domain**, щоб отримати сервісний квиток (**TGS**). Після успішної валідації inter-realm TGT DC trusted domain, він видає TGS, надаючи користувачу доступ до сервісу.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

Важливо зауважити, що **довіра може бути двосторонньою або односторонньою**. У варіанті з двосторонньою довірою обидва домени довіряють один одному, але у випадку **односторонньої** довіри один з доменів буде **trusted**, а інший — **trusting**. У останньому випадку **ви зможете отримати доступ до ресурсів всередині trusting domain лише з trusted domain**.

Якщо Domain A довіряє Domain B, A — це trusting domain, а B — trusted. Більше того, у **Domain A** це буде **Outbound trust**; а в **Domain B** це буде **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Звичайна конфігурація в межах одного forest, де дочірній домен автоматично має двосторонню транзитивну довіру з батьківським доменом. Це означає, що запити автентифікації можуть вільно переходити між батьківським і дочірнім доменами.
- **Cross-link Trusts**: Так звані "shortcut trusts", встановлюються між дочірніми доменами для прискорення процесів реферування. У складних лісах реферали автентифікації зазвичай йдуть вгору до кореня forest, а потім вниз до цільового домену. Створюючи cross-links, шлях скорочується, що особливо корисно в географічно розосереджених середовищах.
- **External Trusts**: Встановлюються між різними, не пов'язаними доменами і за своєю природою не є транзитивними. Згідно з документацією Microsoft, external trusts корисні для доступу до ресурсів в домені поза поточним forest, який не з'єднаний forest trust. Безпека посилюється через SID filtering при external trusts.
- **Tree-root Trusts**: Ці довіри автоматично встановлюються між root доменом forest і новим tree root. Хоча вони зустрічаються нечасто, tree-root trusts важливі для додавання нових дерев доменів до forest, дозволяючи їм зберігати унікальне ім'я домену і забезпечуючи двосторонню транзитивність.
- **Forest Trusts**: Цей тип довіри є двосторонньою транзитивною довірою між двома root доменами лісів, також застосовуючи SID filtering для підвищення заходів безпеки.
- **MIT Trusts**: Встановлюються з не-Windows, RFC4120-сумісними Kerberos доменами. MIT trusts більш спеціалізовані і призначені для інтеграції з Kerberos-сумісними системами поза Windows-екосистемою.

#### Other differences in **trusting relationships**

- Довіра також може бути **транзитивною** (A довіряє B, B довіряє C, тоді A довіряє C) або **нетранзитивною**.
- Довіра може бути налаштована як **двобічна** (обидва довіряють один одному) або як **одностороння** (лише один довіряє іншому).

### Attack Path

1. **Перелічити** довірчі відносини
2. Перевірити, чи будь-який **security principal** (user/group/computer) має **доступ** до ресурсів **іншого домену**, можливо через ACE entries або шляхом належності до груп іншого домену. Шукайте **зв'язки між доменами** (довіра була створена для цього, ймовірно).
1. kerberoast в цьому випадку може бути ще однією опцією.
3. **Скомпрометувати** ті **акаунти**, які можуть **пивотити** через домени.

Нападники можуть отримати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, наприклад до групи “Administrators” на сервері, що надає їм значний контроль над тією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у чужому домені. Однак ефективність цього методу залежить від природи довіри та сфери дії групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, зокрема як сутності в **ACE** в **DACL**, надаючи їм доступ до конкретних ресурсів. Для тих, хто хоче заглибитись у механіку ACL, DACL та ACE, білд "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" буде незамінним ресурсом.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

Ви можете перевірити це у **Bloodhound** або використовуючи powerview:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> Ви можете переглянути ту, що використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалюйте до Enterprise admin у дочірньому/батьківському домені, зловживаючи довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), є критично важливим. Configuration NC слугує центральним сховищем конфігураційних даних для всього лісу в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, при цьому записувані DC зберігають записувану копію Configuration NC. Щоб це експлуатувати, потрібно мати **SYSTEM привілеї на DC**, бажано на дочірньому DC.

**Link GPO to root DC site**

Контейнер Sites Configuration NC містить інформацію про всі сайти комп'ютерів, приєднаних до домену, у межах AD forest. Маючи SYSTEM-привілеї на будь-якому DC, зловмисники можуть прив'язати GPO до сайту кореневого DC. Це може поставити під загрозу кореневий домен шляхом маніпуляцій політиками, що застосовуються до цих сайтів.

Для детальної інформації можна ознайомитися з дослідженням [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Одним з векторів атаки є націлювання на привілейовані gMSA в домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM-привілеї на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі для будь-якого gMSA в усьому лісі.

Детальний аналіз та покрокові інструкції можна знайти в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Доповнювальна делегована атака MSA (BadSuccessor – зловживання атрибутами міграції):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткові зовнішні дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння — очікування появи нових привілейованих AD-об'єктів. Маючи SYSTEM-привілеї, зловмисник може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD-об'єктами.

Додаткове читання доступне за посиланням: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над об'єктами Public Key Infrastructure (PKI) з метою створення шаблона сертифіката, який дозволяє автентифікуватися як будь-який користувач у лісі. Оскільки об'єкти PKI розташовані в Configuration NC, компрометація записуваного дочірнього DC дає змогу виконати атаки типу ESC5.

Більше деталей можна прочитати в [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS зловмисник може налаштувати необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **ваш домен довіряється** зовнішнім доменом, що надає вам **невизначені дозволи** щодо нього. Вам потрібно з'ясувати, **які суб'єкти вашого домену мають який доступ до зовнішнього домену**, а потім спробувати ним скористатися:


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
У цьому сценарії ваш домен довіряє деякі привілеї принципалу з іншого домену.

Однак, коли домен довіряється довіряючим доменом, довірений домен створює користувача з передбачуваною назвою, який використовує як пароль пароль довіри. Це означає, що можна отримати доступ до користувача з довіряючого домену, щоб потрапити всередину довіреного, перелічити його і спробувати ескалувати додаткові привілеї:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб компрометації довіреного домену — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **протилежному напрямку** довіри між доменами (що трапляється не дуже часто).

Ще один спосіб компрометації довіреного домену — чекати на машині, до якої **користувач з довіреного домену може підключитися** через **RDP**. Потім атакуючий може інжектувати код у процес RDP сесії та **звідти отримати доступ до початкового домену жертви**. Більше того, якщо **жертва підключила свій жорсткий диск**, з процесу **RDP session** атакуючий може записати **backdoors** у **папку автозавантаження жорсткого диска**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Пом'якшення зловживань довірою домену

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через міжлісові довіри (forest trusts), зменшується завдяки SID Filtering, яка за замовчуванням активована на всіх inter-forest довірах. Це базується на припущенні, що intra-forest довіри безпечні, розглядаючи ліс (forest), а не домен, як межу безпеки відповідно до позиції Microsoft.
- Однак є підводний камінь: SID Filtering може порушити роботу застосунків і доступ користувачів, що іноді призводить до її відключення.

### **Selective Authentication:**

- Для inter-forest довір застосування Selective Authentication гарантує, що користувачі з обох лісів не автентифікуються автоматично. Натомість потрібні явні дозволи для доступу користувачів до доменів і серверів у довіряючому домені або лісі.
- Важливо зазначити, що ці заходи не захищають від експлуатації записуваного Configuration Naming Context (NC) або атак на обліковий запис довіри.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Зловживання AD через LDAP з on-host імплантів

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ре-реалізує bloodyAD-style LDAP примітиви як x64 Beacon Object Files, що виконуються повністю всередині on-host implant'а (наприклад, Adaptix C2). Оператори збирають пакет командою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` з beacon'а. Увесь трафік їде в контексті поточного сеансу входу через LDAP (389) з підписуванням/шифруванням або LDAPS (636) з автоматичним довірям сертифікатів, тож не потрібні socks-проксі або артефакти на диску.

### Перерахування LDAP на боці імпланта

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` перетворюють short names/OU paths на повні DNs і вивантажують відповідні об'єкти.
- `get-object`, `get-attribute`, and `get-domaininfo` витягують довільні атрибути (включаючи security descriptors) та метадані лісу/домену з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` показують roasting candidates, налаштування делегації та наявні [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) дескриптори напряму з LDAP.
- `get-acl` and `get-writable --detailed` розбирають DACL, щоб перерахувати trustees, права (GenericAll/WriteDACL/WriteOwner/attribute writes) та наслідування, даючи негайні цілі для ескалації привілеїв через ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives для escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дозволяють оператору розміщувати нові principals або machine accounts у будь-яких OU, де існують відповідні права. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` безпосередньо перехоплюють цілі, щойно виявлено права write-property.
- Команди, орієнтовані на ACL, такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, та `add-dcsync`, перетворюють WriteDACL/WriteOwner на будь‑якому AD об'єкті на скидання паролів, контроль членства в групах або привілеї реплікації DCSync без залишення артефактів PowerShell/ADSI. Відповідники `remove-*` очищують інжектовані ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача Kerberoastable; `add-asreproastable` (UAC toggle) позначає його для AS-REP roasting без зміни пароля.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, UAC flags або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, дозволяючи шляхи атаки constrained/unconstrained/RBCD і усуваючи потребу в remote PowerShell або RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` інжектить привілейовані SIDs у SID history контрольованого principal (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане наслідування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп'ютерів або користувачів, дозволяючи атакуючому перемістити активи в OUs, де вже існують делеговані права, перш ніж зловживати `set-password`, `add-groupmember`, або `add-spn`.
- Тісно спрямовані команди видалення (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, тощо) дозволяють швидко відкотити зміни після того, як оператор зібрав облікові дані або забезпечив персистенцію, мінімізуючи телеметрію.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Деякі загальні заходи захисту

[**Дізнайтеся більше про те, як захистити облікові дані тут.**](../stealing-credentials/credentials-protections.md)

### **Заходи захисту облікових даних**

- **Domain Admins Restrictions**: Рекомендується дозволяти Domain Admins входити лише на Domain Controllers, уникаючи їхнього використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з привілеями Domain Admin (DA) для підтримки безпеки.
- **Temporal Privilege Limitation**: Для задач, що вимагають привілеїв DA, їх тривалість слід обмежувати. Це можна реалізувати командою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Впровадження deception-технік**

- Впровадження deception включає встановлення пасток, таких як decoy users або computers, з особливими властивостями, наприклад паролями, які не закінчуються, або які позначені як Trusted for Delegation. Детальний підхід включає створення користувачів з певними правами або додавання їх до високопривілейованих груп.
- Практичний приклад включає використання інструментів, наприклад: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deception-технік можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Виявлення deception**

- **Для об'єктів користувачів**: Підозрілі індикатори включають нетиповий ObjectSID, рідкісні входи, дати створення та низьку кількість невдалих спроб пароля.
- **Загальні індикатори**: Порівняння атрибутів потенційних decoy-об'єктів з реальними може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти у виявленні таких deception.

### **Обхід систем виявлення**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Уникайте сесійної енумерації на Domain Controllers, щоб не викликати виявлення ATA.
- **Ticket Impersonation**: Використання **aes** ключів для створення квитків допомагає уникнути виявлення, оскільки не відбувається пониження до NTLM.
- **DCSync Attacks**: Рекомендується виконувати з не‑Domain Controller для уникнення виявлення ATA, оскільки пряме виконання з Domain Controller спричинить оповіщення.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
