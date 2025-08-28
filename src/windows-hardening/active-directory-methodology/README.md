# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundüberblick

**Active Directory** dient als grundlegende Technologie, die **Netzwerkadministratoren** ermöglicht, **Domains**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist so konzipiert, dass es skaliert und die Organisation einer großen Anzahl von Benutzern in überschaubare **Gruppen** und **Untergruppen** ermöglicht, während **Zugriffsrechte** auf verschiedenen Ebenen gesteuert werden.

Die Struktur von **Active Directory** besteht aus drei hauptsächlichen Ebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** stellt die Sammlung mehrerer Trees dar, die durch **trust relationships** verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Bestimmte **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** sind:

1. **Directory** – Beherbergt alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domain** – Dient als Container für Verzeichnisobjekte; es können mehrere Domains innerhalb eines **forests** koexistieren, wobei jede ihre eigene Objektsammlung hat.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Die Spitze der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation in einem Netzwerk entscheidend sind. Diese Dienste beinhalten:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **Benutzern** und **Domains**, einschließlich **Authentifizierung** und **Suche**.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung von sicheren **digitalen Zertifikaten**.
3. **Lightweight Directory Services** – Unterstützt directory-enabled Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **Single-Sign-On**-Funktionalität, um Benutzer über mehrere Webanwendungen in einer Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz von urheberrechtlich geschütztem Material durch Regulierung seiner unautorisierten Verbreitung und Nutzung.
6. **DNS Service** – Wichtig für die Auflösung von **Domain-Namen**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spickzettel

Du kannst dir https://wadcoms.github.io/ ansehen, um schnell einen Überblick zu bekommen, welche Befehle du zum enumerate/exploit eines AD ausführen kannst.

> [!WARNING]
> **Kerberos**-Kommunikation **erfordert einen vollständigen qualifizierten Namen (FQDN)**, um Aktionen durchzuführen. Wenn du versuchst, über die IP-Adresse auf eine Maschine zuzugreifen, **wird NTLM und nicht Kerberos verwendet**.

## Recon Active Directory (keine creds/sessions)

Wenn du nur Zugriff auf eine AD-Umgebung hast, aber keine Credentials/Sessions, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **exploit vulnerabilities** oder **extract credentials** von ihnen (zum Beispiel, [printers could be very interesting targets](ad-information-in-printers.md)).
- Die DNS-Aufzählung kann Informationen über wichtige Server in der Domain liefern, wie Web, Drucker, Shares, VPN, Media, usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu finden, wie man das macht.
- **Check for null and Guest access on smb services** (das funktioniert nicht bei modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- A more detailed guide on how to enumerate a SMB server can be found here:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Credentials, indem du Dienste mit Responder impersonierst ([**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- Greife Hosts an, indem du den [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ausnutzt
- Sammle Credentials, indem du **fake UPnP services** mit evil-S **exponierst** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Usernames/Namen aus internen Dokumenten, Social Media, Services (hauptsächlich Web) innerhalb der Domain-Umgebungen und auch aus öffentlich verfügbaren Quellen.
- Wenn du die vollständigen Namen von Mitarbeitenden findest, kannst du verschiedene AD **username conventions** ausprobieren ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die gängigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzeraufzählung

- **Anonymous SMB/LDAP enum:** Siehe die Seiten zu [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefragt** wird, antwortet der Server mit dem **Kerberos-Fehler**code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, was uns erlaubt zu bestimmen, dass der Benutzername ungültig ist. **Gültige Benutzernamen** führen entweder zu einem **TGT in einer AS-REP**-Antwort oder zum Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was anzeigt, dass der Benutzer Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen die MS-NRPC (Netlogon)-Schnittstelle auf Domain Controllern. Die Methode ruft die Funktion `DsrGetDcNameEx2` nach dem Binden der MS-NRPC-Schnittstelle auf, um zu prüfen, ob der Benutzer oder Computer ohne jegliche Credentials existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung ist hier zu finden: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk finden, können Sie auch **user enumeration against it** durchführen. Zum Beispiel könnten Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Du kannst Listen von Benutzernamen in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) und in diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) finden.
>
> Du solltest jedoch die **Namen der Personen, die in der Firma arbeiten** aus dem Recon-Schritt haben, den du zuvor durchgeführt haben solltest. Mit Vor- und Nachname kannst du das Script [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu erzeugen.

### Wenn du einen oder mehrere Benutzernamen kennst

Ok, du weißt also bereits, dass du einen gültigen Benutzernamen, aber kein Passwort hast... Versuche dann:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du eine AS_REP-Nachricht für diesen Benutzer anfordern, die Daten enthält, welche mit einer Ableitung des Benutzerpassworts verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuche die gängigsten **common passwords** bei jedem entdeckten Benutzer; vielleicht verwendet ein Benutzer ein schwaches Passwort (beachte die Passwort-Richtlinie!).
- Beachte, dass du auch **spray OWA servers** kannst, um Zugriff auf die Mailserver der Benutzer zu versuchen.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du könntest in der Lage sein, einige Challenge-**hashes** zu erhalten, um durch **Poisoning** bestimmter Protokolle im Netzwerk diese zu erhalten und zu cracken:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn es dir gelungen ist, Active Directory zu enumerieren, hast du **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugang zur AD-Umgebung zu erlangen.

### Steal NTLM Creds

Wenn du mit dem **null- oder guest user** auf andere PCs oder Shares zugreifen kannst, könntest du Dateien (z. B. eine SCF-Datei) ablegen, die beim Zugriff eine NTLM-Authentifizierung zu dir auslösen, sodass du die **NTLM challenge** stehlen kannst, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Active Directory mit Credentials/Session enumerieren

Für diese Phase musst du die **Credentials oder eine Session eines gültigen Domain-Kontos** kompromittiert haben. Wenn du gültige Credentials oder eine Shell als Domain-User hast, **solltest du daran denken, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere Benutzer zu kompromittieren**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du wissen, was das **Kerberos Double-Hop-Problem** ist.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ein Konto kompromittiert zu haben ist ein **wichtiger Schritt, um die gesamte Domain zu kompromittieren**, weil du dann mit der **Active Directory Enumeration** beginnen kannst:

Bezüglich [**ASREPRoast**](asreproast.md) kannst du jetzt jeden möglichen verwundbaren Benutzer finden, und bezüglich [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Kontos, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Du könntest [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden.
- Du kannst auch [**powershell for recon**](../basic-powershell-for-pentesters/index.html) nutzen, was unauffälliger ist.
- Du kannst auch [**use powerview**](../basic-powershell-for-pentesters/powerview.md) verwenden, um detailliertere Informationen zu extrahieren.
- Ein weiteres tolles Tool für Recon in Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr unauffällig** (abhängig von den verwendeten Collection-Methoden), aber **wenn es dir egal ist**, solltest du es unbedingt ausprobieren. Finde, wo Benutzer RDP nutzen können, finde Pfade zu anderen Gruppen usw.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer), [**ADRecon**](bloodhound.md#adrecon), [**Group3r**](bloodhound.md#group3r), [**PingCastle**](bloodhound.md#pingcastle).
- [**DNS records of the AD**](ad-dns-records.md), da diese interessante Informationen enthalten können.
- Ein **GUI-Tool**, das du zur Enumeration des Verzeichnisses verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal**-Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ oder sogar in _Description_ zu suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools ausprobieren wie:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)

- **Extracting all domain users**

Es ist sehr einfach, alle Domain-Benutzernamen unter Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein wirkt, ist er der wichtigste Teil von allen. Rufe die Links auf (hauptsächlich die zu cmd, powershell, powerview und BloodHound) auf, lerne, wie man eine Domain enumeriert und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um deinen Weg zu DA zu finden oder zu entscheiden, dass nichts gemacht werden kann.

### Kerberoast

Kerberoasting beinhaltet das Erlangen von **TGS tickets**, die von Diensten verwendet werden, die an Benutzerkonten gebunden sind, und das Offline-Knacken ihrer Verschlüsselung — welche auf Benutzerpasswörtern basiert.

Mehr dazu in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindungen (RDP, SSH, FTP, Win-RM, etc)

Sobald du Credentials erhalten hast, kannst du prüfen, ob du Zugriff auf irgendeine **Maschine** hast. Dafür kannst du **CrackMapExec** verwenden, um Verbindungen zu mehreren Servern mit verschiedenen Protokollen entsprechend deinen Portscans zu versuchen.

### Local Privilege Escalation

Wenn du Credentials oder eine Session als normaler Domain-User kompromittiert hast und mit diesem Benutzer **Zugriff** auf **irgendeine Maschine in der Domain** hast, solltest du versuchen, lokal Privilegien zu eskalieren und nach Credentials zu suchen. Denn nur mit lokalen Administratorrechten kannst du die **Hashes anderer Benutzer** im Speicher (LSASS) und lokal (SAM) dumpen.

Es gibt eine komplette Seite in diesem Buch über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**checklist**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Session-Tickets

Es ist sehr **unwahrscheinlich**, dass du in der aktuellen User-Session **Tickets** findest, die dir die Berechtigung geben, auf unerwartete Ressourcen zuzugreifen, aber du könntest prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn du es geschafft hast, das Active Directory zu enumerieren, verfügst du über **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Da du jetzt einige grundlegende credentials hast, solltest du prüfen, ob du **finden** irgendwelche **interessante Dateien, die im AD geteilt werden**. Du könntest das manuell machen, aber es ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn du Hunderte von Dokumenten findest, die du überprüfen musst).

[**Folge diesem Link, um mehr über Tools zu erfahren, die du verwenden könntest.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du auf andere PCs oder Shares zugreifen kannst, könntest du **Dateien platzieren** (wie eine SCF file), die, falls sie irgendwie geöffnet werden, eine **NTLM-Authentifizierung gegen dich auslösen**, sodass du die **NTLM challenge** stehlen kannst, um sie zu cracken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte es jedem authentifizierten Benutzer, den **domain controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domain-Benutzer nicht aus, du benötigst spezielle Privilegien/Zugangsdaten, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es dir gelungen, ein **lokales admin** Konto zu kompromittieren mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Dann ist es Zeit, alle Hashes im Speicher und lokal auszulesen.  
[**Lies diese Seite über verschiedene Methoden, um die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.  
Du musst ein **tool** verwenden, das die **NTLM authentication using** diesen **hash** durchführt, **oder** du könntest einen neuen **sessionlogon** erstellen und diesen **hash** in den **LSASS** injecten, sodass bei jeder **NTLM authentication** dieser **hash verwendet wird.** Die letzte Option ist das, was mimikatz macht.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den **user NTLM hash zu verwenden, um Kerberos tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM protocol deaktiviert ist** und nur **Kerberos als authentication protocol** erlaubt ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der **Pass The Ticket (PTT)** Angriffsmethode stehlen Angreifer ein **authenticaton ticket eines Benutzers** statt dessen Passwort oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um sich als den Benutzer **auszugeben**, wodurch unbefugter Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks erlangt wird.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **hash** oder das **password** eines **lokalen administrator** hast, solltest du versuchen, dich **lokal** an anderen **PCs** damit anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dies **mildern** würde.

### MSSQL-Missbrauch & vertrauenswürdige Links

Wenn ein Benutzer Berechtigungen hat, auf **MSSQL-Instanzen** zuzugreifen, könnte er diese nutzen, um **Befehle** auf dem MSSQL-Host auszuführen (falls dieser als **SA** läuft), den **NetNTLM hash** zu **stehlen** oder sogar einen **relay** **Angriff** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link). Wenn der Benutzer Berechtigungen für die vertrauenswürdige Datenbank hat, wird er die **Vertrauensbeziehung nutzen können, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden und irgendwann könnte der Benutzer eine falsch konfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Verknüpfungen zwischen Datenbanken funktionieren sogar über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Missbrauch von IT-Asset-/Deployment-Plattformen

Drittanbieter-Inventar- und Deployment-Suiten bieten oft mächtige Wege zu Anmeldeinformationen und Code-Ausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domänenrechte auf dem Rechner hast, kannst du TGTs aus dem Speicher aller Benutzer dumpen, die sich an dem Rechner anmelden.\
Wenn sich also ein **Domain Admin** an dem Rechner anmeldet, kannst du seinen TGT dumpen und ihn mittels [Pass the Ticket](pass-the-ticket.md) impersonifizieren.\
Dank **constrained delegation** könntest du sogar **automatisch einen Print-Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er sich als beliebiger Benutzer ausgeben, um auf bestimmte Dienste auf einem Rechner zuzugreifen.\
Wenn du dann den **Hash** dieses Benutzers/Computers **kompromittierst**, kannst du **jeden Benutzer** (auch Domain Admins) impersonifizieren, um auf bestimmte Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Das Besitzen des **WRITE**-Rechts an einem Active Directory-Objekt eines entfernten Rechners ermöglicht das Erlangen von Code-Ausführung mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte über **interessante Berechtigungen** an bestimmten Domain-Objekten verfügen, die es dir ermöglichen, laterale Bewegungen durchzuführen bzw. **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Printer Spooler-Dienstes

Das Auffinden eines **Spool-Dienstes**, der innerhalb der Domain lauscht, kann **ausgenutzt** werden, um **neue Anmeldeinformationen zu erlangen** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Drittanbieter-Sitzungen

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Anmeldeinformationen aus dem Speicher** zu sammeln und sogar **Beacons in ihre Prozesse zu injizieren**, um sie zu impersonifizieren.\
In der Regel greifen Benutzer per **RDP** auf das System zu, daher hier, wie man ein paar Angriffe über fremde RDP-Sitzungen durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administrator-Passworts** auf domain-joined Computern bereit, stellt sicher, dass es **zufällig**, einzigartig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über **ACLs** nur für autorisierte Benutzer gesteuert. Mit ausreichenden Berechtigungen zum Zugriff auf diese Passwörter wird Pivoting zu anderen Rechnern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, um innerhalb der Umgebung Privilegien zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Zertifikatvorlagen

Wenn **verwundbare Vorlagen** konfiguriert sind, ist es möglich, diese auszunutzen, um Privilegien zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit einem hochprivilegierten Konto

### Auslesen von Domain-Anmeldeinformationen

Sobald du **Domain Admin** oder noch besser **Enterprise Admin**-Rechte hast, kannst du die **Domain-Datenbank** auslesen: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc als Persistenz

Einige der zuvor besprochenen Techniken können zur Persistenz verwendet werden.\
Beispielsweise könntest du:

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

Der **Silver Ticket**-Angriff erzeugt ein **legitimes Ticket Granting Service (TGS)**-Ticket für einen bestimmten Dienst, indem der **NTLM-Hash** verwendet wird (zum Beispiel der **Hash des PC-Accounts**). Diese Methode wird eingesetzt, um auf die **Dienstberechtigungen** zuzugreifen.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket**-Angriff beinhaltet, dass ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Accounts** in einer Active Directory (AD)-Umgebung erlangt. Dieses Konto ist speziell, weil es zur Signierung aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk essentiell sind.

Sobald der Angreifer diesen Hash besitzt, kann er **TGTs** für beliebige Konten erstellen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese ähneln Golden Tickets, sind jedoch so gefertigt, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Das Besitzen von Zertifikaten eines Kontos oder die Möglichkeit, diese zu beantragen**, ist eine sehr gute Methode, um im Benutzerkonto zu persistieren (selbst wenn das Passwort geändert wird):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Die Verwendung von Zertifikaten ermöglicht es auch, mit hohen Rechten innerhalb der Domain persistent zu bleiben:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unbefugte Änderungen zu verhindern. Dieses Feature kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL von AdminSDHolder so verändert, dass einem normalen Benutzer Vollzugriff gewährt wird, erlangt dieser Benutzer weitreichende Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die eigentlich schützt, kann daher nach hinten losgehen und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In jedem **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Durch das Erlangen von Admin-Rechten auf einem solchen Rechner kann der Hash des lokalen Administrators mit **mimikatz** extrahiert werden. Anschließend ist eine Registry-Änderung nötig, um die **Nutzung dieses Passworts zu ermöglichen**, wodurch ein Remote-Zugriff auf das lokale Administrator-Konto möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** **spezielle Rechte** an bestimmten Domain-Objekten vergeben, die es diesem Benutzer erlauben, zukünftig **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sicherheitsdeskriptoren

Die **Sicherheitsdeskriptoren** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** auf einem anderen **Objekt** hat. Wenn du nur eine kleine Änderung im Sicherheitsdeskriptor eines Objekts vornehmen kannst, kannst du sehr interessante Rechte über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um **Anmeldeinformationen im Klartext** zu **erfassen**, die zum Zugriff auf die Maschine verwendet werden.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und nutzt ihn, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten zu **pushen**, **ohne** dass Änderungen in den Logs dieser Modifikationen erscheinen. Du **brauchst DA**-Rechte und musst dich innerhalb der **root domain** befinden.\
Beachte, dass bei Verwendung falscher Daten recht unschöne Logs entstehen können.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorhin haben wir besprochen, wie man Privilegien eskalieren kann, wenn man **ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern** hat. Diese Passwörter können jedoch auch verwendet werden, um **Persistenz** aufrechtzuerhalten.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Privilegieneskalation im Forest - Domain Trusts

Microsoft betrachtet den **Forest** als die Sicherheitsgrenze. Das bedeutet, dass das **Kompromittieren einer einzelnen Domain potenziell zum Kompromittieren des gesamten Forests führen kann**.

### Grundlegende Informationen

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** den Zugriff auf Ressourcen in einer anderen **Domain** ermöglicht. Er stellt im Grunde eine Verbindung zwischen den Authentifizierungssystemen der beiden Domänen her, sodass Authentifizierungsabfragen reibungslos fließen können. Wenn Domänen eine Vertrauensstellung einrichten, tauschen sie spezifische **Keys** zwischen ihren **Domain Controllern (DCs)** aus und speichern diese, die für die Integrität der Vertrauensstellung entscheidend sind.

In einem typischen Szenario muss ein Benutzer, der auf einen Dienst in einer **vertrauenden Domain** zugreifen möchte, zuerst ein spezielles Ticket, bekannt als **inter-realm TGT**, von seinem eigenen Domain Controller anfordern. Dieses TGT ist mit einem gemeinsamen **Key** verschlüsselt, auf den sich beide Domänen geeinigt haben. Der Benutzer präsentiert dieses TGT dann dem **DC der vertrauenden Domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauenden Domain stellt dieser ein TGS aus, das dem Benutzer den Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt bei erfolgreicher Authentifizierung des Clients ein neues TGT aus.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um Ressourcen in **Domain 2** zu erreichen.
4. Das inter-realm TGT wird mit einem **Trust Key** verschlüsselt, der zwischen DC1 und DC2 als Teil der bidirektionalen Domain-Vertrauensstellung geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller von Domain 2 (DC2)**.
6. DC2 verifiziert das inter-realm TGT mit seinem gemeinsamen Trust Key und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem Hash des Server-Accounts verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Verschiedene Vertrauensstellungen

Es ist wichtig zu beachten, dass **eine Vertrauensstellung einseitig oder zweiseitig sein kann**. In der zweiseitigen Option vertrauen beide Domänen einander, aber in der **einseitigen** Vertrauensbeziehung ist eine Domäne die **trusted** und die andere die **trusting** Domäne. In diesem Fall kannst du **nur von der trusted Domäne aus auf Ressourcen innerhalb der trusting Domäne** zugreifen.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted Domain. Zudem wäre dies in **Domain A** eine **Outbound trust**; und in **Domain B** eine **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Dies ist eine gängige Konfiguration innerhalb desselben Forests, wobei eine Child-Domain automatisch eine zweiseitige transitive Vertrauensstellung mit ihrer Parent-Domain hat. Das bedeutet im Wesentlichen, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals typischerweise bis zur Forest-Root aufsteigen und dann zur Ziel-Domain absteigen. Durch das Erstellen von Cross-Links wird dieser Weg verkürzt, was besonders in geografisch verteilten Umgebungen von Vorteil ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht zusammenhängenden Domänen eingerichtet und sind nicht-transitiv. Laut [Microsoft-Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind externe Trusts nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei externen Trusts erhöht.
- **Tree-root Trusts**: Diese Vertrauensstellungen werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root eingerichtet. Obwohl sie nicht häufig vorkommen, sind Tree-Root-Trusts wichtig, um neue Domain-Trees zu einem Forest hinzuzufügen, sodass sie einen einzigartigen Domänennamen beibehalten und Transitivität in beide Richtungen gewährleistet ist. Mehr Informationen finden sich in [Microsofts Leitfaden](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Vertrauensstellung ist eine zweiseitige transitive Vertrauensstellung zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering zur Erhöhung der Sicherheit.
- **MIT Trusts**: Diese Vertrauensstellungen werden mit nicht-Windows, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains aufgebaut. MIT Trusts sind etwas spezialisierter und dienen Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede in Vertrauensbeziehungen

- Eine Vertrauensbeziehung kann auch **transitiv** (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv** sein.
- Eine Vertrauensbeziehung kann als **bidirektional** (beide vertrauen einander) oder als **einseitig** (nur eine vertraut der anderen) eingerichtet werden.

### Angriffspfad

1. **Enumeriere** die Vertrauensstellungen
2. Prüfe, ob irgendein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, eventuell durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domäne. Suche nach **Beziehungen über Domänen hinweg** (die Vertrauensstellung wurde vermutlich dafür erstellt).
1. **kerberoast** könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Konten**, die sich **durch Domänen pivoten** können.

Angreifer können auf Ressourcen in einer anderen Domäne über drei primäre Mechanismen zugreifen:

- **Local Group Membership**: Principals können lokalen Gruppen auf Maschinen hinzugefügt werden, wie z. B. der “Administrators”-Gruppe auf einem Server, was ihnen umfangreiche Kontrolle über diese Maschine gewährt.
- **Foreign Domain Group Membership**: Principals können auch Mitglieder von Gruppen in der fremden Domäne sein. Die Effektivität dieser Methode hängt jedoch von der Natur des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals können in einer **ACL** spezifiziert sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, die ihnen Zugriff auf bestimmte Ressourcen gewähren. Für ein tieferes Verständnis der Mechanik von ACLs, DACLs und ACEs ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Externe Benutzer/Gruppen mit Berechtigungen finden

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um fremde Security Principals in der Domain zu finden. Dies werden Benutzer/Gruppen aus **einer externen Domäne/einem externen Forest** sein.

Du kannst dies in **Bloodhound** oder mit **powerview** prüfen:
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
> Du kannst denjenigen, der von der aktuellen Domain verwendet wird, mit folgendem herausfinden:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise-Admin in die Child-/Parent-Domain eskalieren, indem man den Trust mit SID-History injection ausnutzt:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Das Verständnis, wie der Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Der Configuration NC dient in Active Directory (AD)-Umgebungen als zentrales Repository für Konfigurationsdaten über einen Forest hinweg. Diese Daten werden an jeden Domain Controller (DC) innerhalb des Forest repliziert; writable DCs halten eine beschreibbare Kopie des Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM privileges on a DC**, vorzugsweise einen child DC.

**Link GPO to root DC site**

Der Sites-Container des Configuration NC enthält Informationen über die Sites aller domain-joined Computer im AD-Forest. Mit SYSTEM-Privilegien auf einem beliebigen DC können Angreifer GPOs an die root DC sites linken. Diese Aktion kann die root domain kompromittieren, indem die auf diese Sites angewendeten Richtlinien manipuliert werden.

Für ausführlichere Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) heranziehen.

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt auf privilegierte gMSAs innerhalb der Domain. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs essenziell ist, wird im Configuration NC gespeichert. Mit SYSTEM-Privilegien auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für beliebige gMSAs im Forest zu berechnen.

Detaillierte Analysen und Schritt-für-Schritt-Anleitungen findet man in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementärer delegierter MSA-Angriff (BadSuccessor – Missbrauch von Migration-Attributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Weitere externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Abwarten der Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Privilegien kann ein Angreifer das AD Schema so verändern, dass jedem Benutzer vollständige Kontrolle über alle Klassen gewährt wird. Dies kann zu unbefugtem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Informationen sind verfügbar unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt darauf ab, Kontrolle über Public Key Infrastructure (PKI)-Objekte zu erlangen, um ein Zertifikattemplate zu erstellen, das die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte im Configuration NC liegen, erlaubt die Kompromittierung eines writable child DC die Durchführung von ESC5-Angriffen.

Weitere Details dazu finden sich in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS kann der Angreifer die notwendigen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario ist **deine Domäne von einer externen Domäne vertraut** und erhält dadurch **unbestimmte Berechtigungen** über diese. Du musst herausfinden, **welche principals deiner Domäne welche Zugriffsrechte auf die externe Domäne haben**, und dann versuchen, diese auszunutzen:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domäne - Einweg (Outbound)
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
In diesem Szenario vertraut **your domain** bestimmten **privileges** gegenüber einem Principal aus **different domains**.

Allerdings, wenn eine **domain is trusted** von der vertrauenden Domain, erstellt die vertrauenswürdige Domain **creates a user** mit einem **predictable name**, der als **password the trusted password** verwendet. Das bedeutet, dass es möglich ist, **access a user from the trusting domain to get inside the trusted one** um diese zu enumerieren und weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domain zu kompromittieren, ist das Finden eines [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links), das in die **opposite direction** der Domain-Trusts erstellt wurde (was nicht sehr häufig ist).

Eine andere Methode, die vertrauenswürdige Domain zu kompromittieren, ist es, auf einer Maschine zu warten, auf die sich ein **user from the trusted domain can access** via **RDP** einloggen kann. Dann könnte der Angreifer Code in den RDP-Session-Prozess injizieren und von dort **access the origin domain of the victim**.\
Zudem, wenn der **victim mounted his hard drive**, könnte der Angreifer aus dem **RDP session**-Prozess **backdoors** im **startup folder of the hard drive** ablegen. Diese Technik nennt sich **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen gegen Missbrauch von Domain-Trusts

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID history-Attribut über forest trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig auf allen inter-forest trusts aktiviert ist. Dies beruht auf der Annahme, dass intra-forest trusts sicher sind, wobei der forest anstelle der domain als Sicherheitsgrenze betrachtet wird, entsprechend der Stellungnahme von Microsoft.
- Allerdings gibt es einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Für inter-forest trusts sorgt Selective Authentication dafür, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domains und Server innerhalb der trusting domain oder des Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des writable Configuration Naming Context (NC) oder vor Angriffen auf das trust account schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Verteidigungsmaßnahmen

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins sich nur an Domain Controllers anmelden dürfen und nicht auf anderen Hosts verwendet werden.
- **Service Account Privileges**: Dienste sollten nicht mit Domain Admin (DA)-Rechten ausgeführt werden, um die Sicherheit zu gewährleisten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Privilegien erfordern, sollte die Dauer dieser Privilegien begrenzt werden. Dies kann erreicht werden mit: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementierung von Deception beinhaltet das Aufstellen von Fallen, wie beispielsweise decoy users oder computers, mit Eigenschaften wie Passwörtern, die nicht ablaufen, oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hochprivilegierten Gruppen.
- Ein praktisches Beispiel verwendet Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zur Bereitstellung von Deception-Techniken findet sich unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdächtige Indikatoren umfassen untypische ObjectSID, seltene Logons, Erstellungsdaten und geringe Counts bei falschen Passworteingaben.
- **General Indicators**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit echten Objekten kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifizierung solcher Deceptions unterstützen.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeiden der Session-Enumeration auf Domain Controllers, um ATA-Erkennung zu verhindern.
- **Ticket Impersonation**: Die Nutzung von **aes**-Schlüsseln zur Ticket-Erstellung hilft, die Erkennung zu umgehen, indem ein Downgrade zu NTLM vermieden wird.
- **DCSync Attacks**: Es wird empfohlen, DCSync nicht von einem Domain Controller auszuführen, um ATA-Erkennung zu vermeiden, da eine direkte Ausführung auf einem Domain Controller Alarmmeldungen auslösen würde.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
