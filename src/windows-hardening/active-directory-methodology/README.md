# Active Directory Methodik

{{#include ../../banners/hacktricks-training.md}}

## Grundlegender Überblick

**Active Directory** dient als grundlegende Technologie, die **Netzwerkadministratoren** ermöglicht, **domains**, **users** und **objects** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist skalierbar konzipiert und erleichtert die Organisation einer großen Anzahl von Benutzern in handhabbare **groups** und **subgroups**, während **access rights** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie **users** oder **devices**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** stellt die Sammlung mehrerer Trees dar, die über **trust relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können spezifische **access**- und **communication rights** festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** sind:

1. **Directory** – Enthält alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Directory, einschließlich **users**, **groups** oder **shared folders**.
3. **Domain** – Dient als Container für Directory-Objekte; mehrere Domains können innerhalb eines **forest** koexistieren, wobei jede ihre eigene Objektkollektion verwaltet.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Die Spitze der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks wichtig sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **users** und **domains**, einschließlich **authentication** und **search**-Funktionalitäten.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digital certificates**.
3. **Lightweight Directory Services** – Unterstützt directory-enabled Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen, um Benutzer für mehrere Webanwendungen in einer einzigen Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz urheberrechtlich geschützter Inhalte, indem die unautorisierte Verbreitung und Nutzung eingeschränkt wird.
6. **DNS Service** – Entscheidend für die Auflösung von **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD** angreift, musst du den **Kerberos authentication process** wirklich gut verstehen.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst vieles auf [https://wadcoms.github.io/](https://wadcoms.github.io) finden, um schnell zu sehen, welche Befehle du ausführen kannst, um ein AD zu enumerieren/exploiten.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** für Aktionen. Wenn du versuchst, auf eine Maschine über die IP-Adresse zuzugreifen, **wird NTLM und nicht kerberos verwendet**.

## Recon Active Directory (No creds/sessions)

Wenn du nur Zugriff auf eine AD-Umgebung hast, aber keine Credentials/Sessions, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **Vulnerabilities zu exploit-en** oder **Credentials** daraus zu extrahieren (zum Beispiel können [Printers sehr interessante Ziele sein](ad-information-in-printers.md)).
- Die Enumeration von DNS kann Informationen über wichtige Server in der Domain liefern, wie Web, Drucker, Shares, VPN, Media usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu finden, wie man das macht.
- **Check for null and Guest access on smb services** (dies funktioniert nicht auf modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine detailliertere Anleitung, wie man einen SMB-Server enumeriert, findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine detailliertere Anleitung, wie man LDAP enumeriert, findest du hier (achte besonders auf den anonymen Zugriff):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Credentials, indem du Dienste imitierst mit Responder (impersonating services with Responder) (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife Hosts an durch Missbrauch des [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sammle Credentials, indem du **fake UPnP services** mit evil-S **exposest** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, Social Media, Services (hauptsächlich Web) innerhalb der Domain-Umgebungen und auch aus öffentlich zugänglichen Quellen.
- Wenn du die vollständigen Namen von Firmenmitarbeitenden findest, könntest du verschiedene AD-**username conventions** ausprobieren ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die gebräuchlichsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Letters von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters und 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Siehe die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **invalid username angefragt** wird, antwortet der Server mit dem **Kerberos error** Code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wodurch wir feststellen können, dass der Benutzername ungültig war. **Valid usernames** führen entweder zu einem **TGT in einer AS-REP**-Antwort oder dem Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was anzeigt, dass der User Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (No authentication) gegen die MS-NRPC (Netlogon) Schnittstelle auf Domain-Controllern. Die Methode ruft die Funktion `DsrGetDcNameEx2` auf, nachdem die MS-NRPC-Schnittstelle gebunden wurde, um zu prüfen, ob der Benutzer oder Computer ohne jegliche Credentials existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung dazu ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch **user enumeration against it** durchführen. Zum Beispiel könnten Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, du weißt also bereits einen gültigen Benutzernamen, aber keine Passwörter... Dann versuche:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Versuche die häufigsten **common passwords** bei jedem entdeckten Benutzer — vielleicht verwendet jemand ein schwaches Passwort (beachte die password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Du könntest in der Lage sein, einige Challenge-Hashes zu erhalten, die du cracken kannst, indem du bestimmte Protokolle im Netzwerk poisonst:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn es dir gelungen ist, das Active Directory zu enumerieren, wirst du **mehr E-Mails und ein besseres Verständnis des Netzwerks** haben. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD-Umgebung zu bekommen.

### Steal NTLM Creds

Wenn du mit dem **null- oder guest-Benutzer** Zugriff auf andere PCs oder Shares hast, könntest du **Dateien platzieren** (z. B. eine SCF-Datei), die beim Zugriff eine NTLM-Authentifizierung gegen dich auslösen, sodass du die **NTLM challenge** abgreifen und cracken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Für diese Phase musst du die **Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert** haben. Wenn du gültige Credentials oder eine Shell als Domain-User besitzt, **solltest du bedenken, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, weitere Nutzer zu kompromittieren**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos double hop problem** kennen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Das Kompromittieren eines Accounts ist ein **großer Schritt, um die gesamte Domain zu kompromittieren**, denn du kannst jetzt mit der **Active Directory Enumeration** beginnen:

Bezüglich [**ASREPRoast**](asreproast.md) kannst du nun alle potentiell verwundbaren Benutzer finden, und bezüglich [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Usernames** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter oder neue vielversprechende Passwörter ausprobieren.

- Du könntest das [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Du kannst auch [**powershell for recon**](../basic-powershell-for-pentesters/index.html) nutzen, was unauffälliger ist
- Du kannst außerdem [**use powerview**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **not very stealthy** (abhängig von den verwendeten Collection-Methoden), aber **if you don't care** darum, solltest du es auf jeden Fall ausprobieren. Finde, wo sich Nutzer per RDP verbinden können, finde Pfade zu anderen Gruppen usw.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md), da diese interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des Verzeichnisses nutzen kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch die LDAP-Datenbank mit **ldapsearch** nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ durchsuchen, oder sogar nach _Description_. Vgl. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für weitere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools ausprobieren wie:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Es ist sehr einfach, alle Domain-Usernames von Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux kannst du verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt kurz erscheint, ist er der wichtigste Teil von allem. Öffne die Links (vor allem die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments ist dies der entscheidende Moment, um den Weg zu DA zu finden oder zu entscheiden, dass nichts unternommen werden kann.

### Kerberoast

Kerberoasting beinhaltet das Beschaffen von **TGS tickets**, die von Services verwendet werden, die an Benutzerkonten gebunden sind, und das Offline-Cracken ihrer Verschlüsselung — welche auf Benutzerpasswörtern basiert.

Mehr dazu in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sobald du einige Credentials erhalten hast, solltest du prüfen, ob du Zugriff auf irgendeine **machine** hast. Dafür kannst du **CrackMapExec** verwenden, um zu versuchen, dich mit verschiedenen Protokollen auf mehreren Servern entsprechend deiner Port-Scans zu verbinden.

### Local Privilege Escalation

Wenn du Credentials oder eine Session als normaler Domain-User kompromittiert hast und mit diesem Benutzer auf **irgendeinen Rechner in der Domain** zugreifen kannst, solltest du versuchen, lokal Privilegien zu eskalieren und nach Credentials zu suchen. Nur mit lokalen Administrator-Rechten kannst du nämlich **Hashes anderer Nutzer** im Speicher (LSASS) und lokal (SAM) dumpen.

Es gibt eine komplette Seite in diesem Buch über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**checklist**](../checklist-windows-privilege-escalation.md). Vergiss auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Current Session Tickets

Es ist sehr **unlikely**, dass du **tickets** im aktuellen Benutzer findest, die dir unerwartete Zugriffsrechte geben, aber du könntest folgendes prüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn es Ihnen gelungen ist, das active directory zu enumerieren, haben Sie **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise können Sie NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Jetzt, da Sie einige grundlegende credentials haben, sollten Sie prüfen, ob Sie **finden** können **interessante Dateien, die innerhalb des AD freigegeben werden**. Sie könnten das manuell machen, aber das ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn Sie Hunderte von Docs finden, die Sie prüfen müssen).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn Sie auf andere PCs oder Shares **access** haben, könnten Sie **Dateien platzieren** (wie eine SCF-Datei), die, falls sie irgendwie geöffnet werden, eine **NTLM authentication gegen Sie auslösen**, sodass Sie **die NTLM challenge** **stehlen** können, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte es jedem authentifizierten Benutzer, **den Domänencontroller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler domain user nicht aus, Sie benötigen spezielle Privilegien/credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es Ihnen gelungen, **ein lokales Admin-Konto zu kompromittieren** mithilfe von [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald Sie den Hash eines Users haben**, können Sie ihn verwenden, um sich als dieser auszugeben.\
Sie müssen ein **Tool** verwenden, das die **NTLM authentication mit** diesem **hash** durchführt, **oder** Sie könnten eine neue **sessionlogon** erstellen und diesen **hash** in **LSASS** **injecten**, sodass bei jeder **NTLM authentication**, die durchgeführt wird, dieser **hash verwendet wird.** Letzteres ist das, was mimikatz macht.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash eines Users zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll erlaubt** ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der **Pass The Ticket (PTT)**-Angriffsmethode stehlen Angreifer **das Authentifizierungsticket eines Users** anstatt dessen Passwort oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um **den User zu impersonate**, wodurch unautorisierter Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks erlangt wird.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn Sie den **hash** oder das **password** eines **lokalen Administrators** haben, sollten Sie versuchen, sich lokal bei anderen **PCs** damit anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **laut** ist und **LAPS** dies **mildern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer die Rechte hat, **MSSQL-Instanzen zuzugreifen**, könnte er diese nutzen, um **Befehle** auf dem MSSQL-Host auszuführen (wenn dieser als SA läuft), den NetNTLM **hash** zu **stehlen** oder sogar einen **relay attack** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link). Wenn der Benutzer Berechtigungen für die vertrauenswürdige Datenbank hat, wird er in der Lage sein, **die Vertrauensbeziehung zu nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden und irgendwann könnte der Benutzer eine falsch konfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über forest trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Drittanbieter-Inventar- und Deployment-Suiten bieten oft mächtige Pfade zu Credentials und Code-Ausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domänenrechte auf dem Computer hast, kannst du TGTs aus dem Speicher jedes Benutzers dumpen, der sich auf dem Computer anmeldet.\
Wenn sich also ein **Domain Admin** auf dem Computer anmeldet, kannst du seinen TGT dumpen und ihn mittels [Pass the Ticket](pass-the-ticket.md) impersonifizieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er **jeden Benutzer impersonifizieren, um auf bestimmte Services auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, wirst du in der Lage sein, **jeden Benutzer** (auch Domain Admins) zu impersonifizieren, um auf diese Services zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

WRITE-Rechte auf ein Active Directory-Objekt eines entfernten Computers zu haben, ermöglicht die Erlangung von Code-Ausführung mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Rechte über bestimmte Domain-Objekte** haben, die dir erlauben könnten, später lateral zu **bewegen**/**privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **Spool-Dienstes, der im Domain-Kontext lauscht**, kann **missbraucht** werden, um **neue Credentials zu erlangen** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** **auf die kompromittierte Maschine zugreifen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in ihre Prozesse zu injizieren**, um sie zu impersonifizieren.\
Normalerweise greifen Benutzer über RDP auf das System zu, hier siehst du, wie man ein paar Angriffe auf Third-Party-RDP-Sessions durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-joined Computern bereit, das sicherstellt, dass es **randomisiert**, einzigartig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über ACLs nur für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen, um auf diese Passwörter zuzugreifen, wird das Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, um innerhalb der Umgebung Privilegien zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **verletzliche Templates** konfiguriert sind, ist es möglich, diese zum Eskalieren von Privilegien zu missbrauchen:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin** Rechte erlangt hast, kannst du die **Domain-Datenbank** dumpen: _ntds.dit_.

[**Mehr Informationen über den DCSync-Angriff findest du hier**](dcsync.md).

[**Mehr Informationen darüber, wie man die NTDS.dit stiehlt, findest du hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können zur Persistenz genutzt werden.\
Zum Beispiel könntest du:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Einer Person [**DCSync**](#dcsync)-Rechte gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket-Angriff** erzeugt ein legitimes Ticket Granting Service (TGS) Ticket für einen spezifischen Service, indem der **NTLM hash** (z. B. der **Hash des PC-Kontos**) verwendet wird. Diese Methode wird genutzt, um **auf die Service-Rechte** zuzugreifen.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket-Angriff** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt-Kontos** in einer Active Directory-Umgebung erlangt. Dieses Konto ist speziell, weil es verwendet wird, um alle **Ticket Granting Tickets (TGTs)** zu signieren, die für die Authentifizierung innerhalb des AD-Netzwerks essenziell sind.

Sobald der Angreifer diesen Hash hat, kann er **TGTs** für beliebige Konten erstellen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind ähnlich wie Golden Tickets, aber so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Kontos zu besitzen oder in der Lage zu sein, sie anzufordern**, ist ein sehr guter Weg, um in einem Benutzerkonto persistieren zu können (selbst wenn das Passwort geändert wird):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mit Zertifikaten ist es auch möglich, mit hohen Rechten innerhalb der Domain zu persistieren:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL von AdminSDHolder so ändert, dass einem normalen Benutzer Vollzugriff gewährt wird, erhält dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die schützen soll, kann somit ins Gegenteil umschlagen, wenn sie nicht genau überwacht wird.

[**Mehr Informationen zur AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In jedem **Domain Controller (DC)** existiert ein **lokales Administrator**-Konto. Durch das Erlangen von Admin-Rechten auf einem solchen Rechner kann der lokale Administrator-Hash mit **mimikatz** extrahiert werden. Danach ist eine Registry-Änderung notwendig, um die **Nutzung dieses Passworts zu ermöglichen**, wodurch ein Remote-Zugriff auf das lokale Administrator-Konto möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** spezielle **Berechtigungen** über bestimmte Domain-Objekte **geben**, die es dem Benutzer erlauben, in der Zukunft **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **Objekt** hat. Wenn du nur eine **kleine Änderung** im **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Rechte über dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle Domain-Konten gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Erfahre, was ein SSP (Security Support Provider) ist, hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um **Credentials im Klartext** zu **capturen**, die zum Zugriff auf die Maschine verwendet werden.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und verwendet ihn, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten zu **pushen**, **ohne** dabei Logs über die **Änderungen** zu hinterlassen. Du **brauchst DA**-Rechte und musst dich in der **Root-Domain** befinden.\
Beachte, dass bei Verwendung falscher Daten ziemlich hässliche Logs entstehen können.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorher haben wir besprochen, wie man Privilegien eskalieren kann, wenn man **genügend Berechtigung hat, LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch genutzt werden, um **Persistenz** aufrechtzuerhalten.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das impliziert, dass **das Kompromittieren einer einzelnen Domain potentiell zum Kompromiss des gesamten Forests führen kann**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** den Zugriff auf Ressourcen in einer anderen **Domain** ermöglicht. Er stellt im Wesentlichen eine Verknüpfung zwischen den Authentifizierungssystemen der beiden Domains her, sodass Authentifizierungsüberprüfungen nahtlos fließen können. Wenn Domains eine Trust-Beziehung einrichten, tauschen sie bestimmte **Keys** aus und speichern diese in ihren **Domain Controllers (DCs)**, die für die Integrität des Trusts entscheidend sind.

In einem typischen Szenario, wenn ein Benutzer Zugriff auf einen Service in einer **vertrauenden Domain** anstrebt, muss er zuerst ein spezielles Ticket namens **inter-realm TGT** von seinem eigenen Domain-DC anfordern. Dieses TGT ist mit einem geteilten **Key** verschlüsselt, auf den sich beide Domains geeinigt haben. Der Benutzer präsentiert dieses TGT dann dem **DC der vertrauenden Domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauenden Domain stellt dieser ein TGS aus, das dem Benutzer den Zugriff auf den Service gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert ist.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT ist mit einem **Trust Key** verschlüsselt, der zwischen DC1 und DC2 im Rahmen des zweiseitigen Domain-Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller von Domain 2 (DC2)**.
6. DC2 überprüft das inter-realm TGT mit seinem geteilten Trust Key und stellt, wenn es gültig ist, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem Hash des Serverkontos verschlüsselt ist, um Zugriff auf den Service in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **ein Trust einseitig oder zweiseitig** sein kann. Bei der zweiseitigen Option vertrauen sich beide Domains gegenseitig, aber bei einer **einseitigen** Trust-Beziehung ist eine Domain die **trusted** und die andere die **trusting** Domain. In diesem letzten Fall **kannst du nur von der trusted zur trusting Domain auf Ressourcen zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Verschiedene Vertrauensbeziehungen**

- **Parent-Child Trusts**: Dies ist eine übliche Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch eine zweiseitige transitive Trust-Beziehung zu ihrer Parent-Domain hat. Das bedeutet im Wesentlichen, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssten Authentifizierungs-Referrals normalerweise bis zur Forest-Root und dann wieder hinunter zur Ziel-Domain reisen. Durch das Erstellen von Cross-Links wird die Reise verkürzt, was besonders in geografisch verteilten Umgebungen vorteilhaft ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verwandten Domains eingerichtet und sind nicht transitiv. Laut [Microsoft-Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forests zuzugreifen, die nicht durch einen Forest-Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei External Trusts gestärkt.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einem neu hinzugefügten Tree-Root hergestellt. Sie sind zwar nicht häufig anzutreffen, spielen aber eine Rolle beim Hinzufügen neuer Domain-Trees zu einem Forest, indem sie ihnen einen einzigartigen Domain-Namen ermöglichen und zweiseitige Transitivität sicherstellen. Weitere Informationen finden sich in [Microsofts Leitfaden](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Diese Art von Trust ist ein zweiseitiger transitiver Trust zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering zur Erhöhung der Sicherheitsmaßnahmen.
- **MIT Trusts**: Diese Trusts werden mit non-Windows, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezialisierter und dienen Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Other differences in **trusting relationships**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv**.
- Eine Trust-Beziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **einseitiger Trust** (nur einer vertraut dem anderen) eingerichtet werden.

### Attack Path

1. **Enumeriere** die Vertrauensbeziehungen
2. Prüfe, ob irgendein **Security Principal** (User/Group/Computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, vielleicht durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domain. Suche nach **Beziehungen über Domains hinweg** (wahrscheinlich wurde der Trust dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Accounts**, die sich **zwischen Domains pivoten** können.

Angreifer können über drei primäre Mechanismen auf Ressourcen in einer anderen Domain zugreifen:

- **Lokale Gruppenmitgliedschaft**: Principals könnten lokalen Gruppen auf Maschinen hinzugefügt worden sein, wie z. B. der „Administrators“-Gruppe auf einem Server, was ihnen erhebliche Kontrolle über diese Maschine gewährt.
- **Fremde Domain-Gruppenmitgliedschaft**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Effektivität dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals könnten in einer **ACL** spezifiziert sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, die ihnen Zugang zu spezifischen Ressourcen gewährt. Für diejenigen, die tiefer in die Mechanik von ACLs, DACLs und ACEs eintauchen möchten, ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um fremde Security Principals in der Domain zu finden. Diese werden Benutzer/Gruppen aus **einer externen Domain/Forest** sein.

Du kannst das in **Bloodhound** oder mit powerview prüfen:
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
Weitere Möglichkeiten, Domain Trusts zu enumerieren:
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
> Es gibt **2 trusted keys**, einer für _Child --> Parent_ und ein anderer für _Parent_ --> _Child_.\
> Man kann denjenigen, der von der aktuellen Domäne verwendet wird, mit folgendem Befehl ermitteln:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise-Administrator in die Child-/Parent-Domain eskalieren, indem man den Trust mit SID-History Injection missbraucht:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Das Verständnis, wie die Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten im ganzen Forest in Active Directory (AD)-Umgebungen. Diese Daten werden an jeden Domain Controller (DC) im Forest repliziert; writable DCs halten eine schreibbare Kopie der Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM privileges on a DC**, idealerweise eines Child-DC.

**Link GPO to root DC site**

Der Sites-Container der Configuration NC enthält Informationen zu den Sites aller domain-joined Computer im AD-Forest. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den root DC sites verknüpfen. Diese Aktion kann die Root-Domain gefährden, indem Richtlinien manipuliert werden, die auf diese Sites angewendet werden.

Für detailliertere Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) konsultieren.

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt auf privilegierte gMSAs innerhalb der Domain ab. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für beliebige gMSAs im gesamten Forest zu berechnen.

Detaillierte Analysen und Schritt-für-Schritt-Anleitungen finden sich in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementärer delegated MSA-Angriff (BadSuccessor – Missbrauch von Migration-Attributen):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Rechten kann ein Angreifer das AD-Schema ändern, um jedem Benutzer vollständige Kontrolle über alle Klassen zu gewähren. Dies könnte zu unbefugtem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Lektüre zu diesem Thema: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt auf die Kontrolle über PKI-Objekte ab, um ein Certificate Template zu erstellen, das die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte in der Configuration NC liegen, erlaubt die Kompromittierung eines writable Child-DC die Durchführung von ESC5-Angriffen.

Mehr Details dazu sind unter [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) zu finden. In Szenarien ohne ADCS kann der Angreifer die erforderlichen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

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
In diesem Szenario wird **Ihre Domain von einer externen Domain vertraut**, wodurch Ihnen **unklare Berechtigungen** gegenüber dieser gewährt werden. Sie müssen herausfinden, **welche Principals Ihrer Domain welchen Zugriff auf die externe Domain haben**, und dann versuchen, diesen auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domain - Einseitig (Ausgehend)
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
In diesem Szenario vertraut **Ihre Domäne** einigen **Berechtigungen** an einen Prinzipal aus **anderen Domänen**.

Wenn jedoch eine **Domäne von der vertrauenden Domäne** vertraut wird, erstellt die vertrauenswürdige Domäne einen **Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das vertrauenswürdige Passwort** verwendet. Das bedeutet, dass es möglich ist, auf einen **Benutzer der vertrauenden Domäne zuzugreifen, um in die vertrauenswürdige Domäne zu gelangen**, diese zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** der Domänenvertrauensstellung erstellt wurde (was nicht sehr üblich ist).

Eine andere Methode, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, sich auf einem Host aufzuhalten, auf dem sich ein **Benutzer aus der vertrauenswürdigen Domäne auf RDP anmelden kann**. Dann könnte der Angreifer Code in den Prozess der RDP-Sitzung injizieren und **von dort auf die Ursprungsdomäne des Opfers zugreifen**.\
Außerdem, wenn das **Opfer seine Festplatte eingebunden hat**, könnte der Angreifer vom **RDP session**-Prozess aus **backdoors** im **Autostart-Ordner der Festplatte** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Maßnahmen gegen Missbrauch von Domänenvertrauen

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest-Vertrauensstellungen ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen inter-Forest-Vertrauensstellungen aktiviert ist. Dies beruht auf der Annahme, dass intra-Forest-Vertrauensstellungen sicher sind und der Forest statt der Domäne als Sicherheitsgrenze angesehen wird, gemäß Microsoft.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, was dazu führt, dass es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei inter-Forest-Vertrauensstellungen stellt die Verwendung von Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht gegen die Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder Angriffe auf das Vertrauenskonto schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-style LDAP-Primitiven als x64 Beacon Object Files, die vollständig innerhalb eines On-Host Implants (z. B. Adaptix C2) laufen. Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon auf. Der gesamte Traffic nutzt den aktuellen Logon-Sicherheitskontext über LDAP (389) mit signing/sealing oder LDAPS (636) mit automatischem Zertifikatvertrauen, sodass keine socks proxies oder Festplattenartefakte erforderlich sind.

### Implant-seitige LDAP-Enumerierung

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` lösen Kurznamen/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute`, and `get-domaininfo` ziehen beliebige Attribute (einschließlich security descriptors) sowie die Forest-/Domain-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` zeigen roasting-Kandidaten, Delegationseinstellungen und vorhandene [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP an.
- `get-acl` and `get-writable --detailed` parsen die DACL, listen Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/attribute writes) und Vererbung auf und liefern damit unmittelbare Ziele für ACL-Privilegieneskalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitiven für escalation & persistence

- Objekt-Erstellungs-BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) erlauben dem Operator, neue principals oder Maschinenkonten dort zu platzieren, wo OU-Rechte bestehen. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` übernehmen Ziele direkt, sobald write-property rights gefunden werden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` übersetzen WriteDACL/WriteOwner auf jedem AD-Objekt in Passwort-Resets, Gruppenmitgliedschaftskontrolle oder DCSync-Replikationsprivilegien, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*` Gegenstücke räumen injizierte ACEs wieder auf.

### Delegation, roasting und Kerberos abuse

- `add-spn`/`set-spn` machen einen kompromittierten Benutzer sofort Kerberoastable; `add-asreproastable` (UAC-Schalter) markiert ihn für AS-REP roasting, ohne das Passwort zu berühren.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` vom Beacon aus um, ermöglichen constrained/unconstrained/RBCD-Angriffswege und eliminieren die Notwendigkeit für remote PowerShell oder RSAT.

### sidHistory-Injektion, OU-Verschiebung und Attack Surface Shaping

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und stellt so stealthy Access Inheritance ausschließlich über LDAP/LDAPS bereit.
- `move-object` ändert DN/OU von Computern oder Benutzern, wodurch ein Angreifer Assets in OUs ziehen kann, in denen bereits delegierte Rechte bestehen, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng begrenzte Entferungsbefehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` usw.) erlauben ein schnelles Zurückrollen, nachdem der Operator Anmeldeinformationen oder Persistence geerntet hat, und minimieren Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Es wird empfohlen, dass Domain Admins nur die Anmeldung an Domain Controllers erlaubt sein sollte und nicht die Nutzung auf anderen Hosts.
- **Service Account Privileges**: Dienste sollten nicht mit Domain Admin (DA)-Rechten ausgeführt werden, um die Sicherheit zu erhalten.
- **Temporal Privilege Limitation**: Für Aufgaben, die DA-Privilegien benötigen, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementierung von Deception beinhaltet das Aufstellen von Fallen, wie Decoy-Benutzer oder -Computer, mit Merkmalen wie Passwörtern, die nie ablaufen, oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hoch privilegierten Gruppen.
- Ein praktisches Beispiel verwendet Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zur Bereitstellung von Deception-Techniken findet sich unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdächtige Indikatoren umfassen atypische ObjectSID, seltene Logons, Erstellungsdaten und geringe Counts für fehlerhafte Passworteingaben.
- **General Indicators**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit echten Objekten kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifikation solcher Deceptions helfen.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeiden von Session-Enumeration auf Domain Controllers, um ATA-Detection zu verhindern.
- **Ticket Impersonation**: Verwendung von **aes**-Keys zur Ticket-Erstellung hilft, Detection zu umgehen, indem kein Downgrade auf NTLM erfolgt.
- **DCSync Attacks**: Ausführung von einem Nicht-Domain Controller wird empfohlen, um ATA-Detection zu vermeiden, da direkte Ausführung von einem Domain Controller Alerts auslösen wird.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
